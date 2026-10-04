#!/usr/bin/env bash
#
# deploy.sh — the only supported way to move PHP source onto a live node.
#
#   ./deploy.sh                  # deploy HEAD to both nodes
#   ./deploy.sh HEAD retichat    # ...to one node
#   ./deploy.sh 71b5229          # ...a specific ref (rollback)
#
# WHAT THIS EXISTS TO PREVENT
# ===========================
# On 2026-08-17 the working tree here held a copy of five lib files that was
# HEAD with the newest commit's fixes surgically removed — content that was in
# no commit and on no server. `scp`ing that tree would have silently reverted
# the last_seen_at staleness fix, the orphaned-local-destination cleanup and
# the path-request throttle on a live node.
#
# Three of the repo's own tests fail instantly against those files. The defence
# was already written; nothing ran it. So this script's whole job is to make the
# checks unskippable and to deploy from git rather than from the filesystem:
#
#   1. refuse a dirty working tree      — you cannot ship what isn't committed
#   2. run the test suite               — and refuse on any failure
#   3. deploy from `git archive <ref>`  — never from the working directory
#   4. lint on every node, then swap    — never a half-uploaded release live
#   5. hash-verify every node afterward — proof, not hope
#   6. only then stamp each node with the commit it runs
#
# NO NODE RUNS A MIX OF TWO RELEASES
# ==================================
# Until 2026-10-04 the code was scp'd straight into the live directory, the
# top-level files first and lib/ a few seconds later. For those seconds a node
# ran the new index.php with the old lib/ (for e3c05ea: every exchange a 500,
# every ingest "Class ReticulumPhp\WakeConfig not found"); it was linted only
# once live; and a file the ref had deleted stayed on the node for good. Now
# code reaches the nodes in two phases:
#
#   stage — every node receives the ref's *.php and lib/*.php in a fresh
#           ~/reticulum-incoming, outside the web root, and lints them with
#           its own php -l. If any file fails on any node the deploy stops
#           there, with nothing changed live on any node, stamps included.
#   swap  — then, node by node, the rollback copy is refreshed, and ONE ssh
#           command checks it, clears the stamp, mv's every incoming file over
#           its live name (lib/ first, so a request that meets a new entry
#           point meets the whole new lib/; each rename is atomic and the set
#           takes milliseconds) and removes the RETIRED files. The live files
#           are then linted again.
#
# It also leaves a build stamp: build.json (write-build-stamp.sh) names the
# commit, and GET /health publishes it, so verify-live-stamp.sh can say which
# commit each node runs without credentials. /health must never name a commit
# the node was not proven to run, so before any code goes live the node's
# stamp is replaced with an unknown one ({"commit":null}), in the same command
# as the swap, and the new stamp is uploaded only after verify-deploy.sh has
# proved every node's bytes. A deploy that stops before the swap leaves the
# node's code and stamp as they were; one that stops after it leaves
# "unknown", never the old commit's name on new code or the new commit's name
# on unverified code. The rollback copy (~/reticulum-rollback, outside the web
# root) carries the previous stamp (or an explicit unknown one), so restoring
# it does not leave the new commit's name on old code either.
#
# Credentials come from the environment. Keep them in a gitignored deploy.env:
#
#   export RETICHAT_SSH_PASS=...   RETICHAT_SSH_HOST=retichat@retichat.com
#   export SELECTIV_SSH_PASS=...   SELECTIV_SSH_HOST=selectiv@selectivesubconscious.com
#
# Bypass for a genuine emergency: DEPLOY_ALLOW_DIRTY=1 (tree check) and
# DEPLOY_SKIP_TESTS=1 (suite). Both print a loud warning and are recorded in
# the deploy log. If you find yourself using them routinely, fix the cause.

set -uo pipefail

REF="${1:-HEAD}"
ONLY_NODE="${2:-}"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_PREFIX="php/src"
REMOTE_DIR="public_html/reticulum"
# Both beside public_html, never inside it: nothing in them may be served.
# Deploys before 2026-10-04 kept the rollback copy at
# ~/public_html/reticulum-rollback, in the web root, while the rollback
# command they printed read ~/reticulum-rollback. This script never removes
# that old copy; deleting it is for a person.
INCOMING_DIR="reticulum-incoming"
ROLLBACK_DIR="reticulum-rollback"
LOG_FILE="${REPO_DIR}/.deploy.log"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; DIM=$'\033[2m'; NC=$'\033[0m'
SSH_OPTS=(-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o LogLevel=ERROR)

# Files the node owns that a deploy must never overwrite: per-node secrets and
# runtime state. Deploying config.toml would push retichat's MySQL password to
# selectiv and break it.
EXCLUDE=(config.toml config.local.toml config.php _test.php)

# Files a commit deleted from php/src. Uploading only adds and replaces, so
# without this a deleted file stays on every node for good: reachable by URL,
# loadable by anything that still names it. The swap removes each one, after
# the new code is in and only once it has checked that the rollback copy holds
# it (so the rollback command restores it), unless the ref being deployed
# ships it itself: `./deploy.sh <older-ref>` keeps what that ref needs.
#
# Add a file here in the commit that deletes it. Drop an entry once every node
# has deployed past that commit. Only top-level and lib/ .php files, which is
# all the rollback copy holds. Nothing that is not listed here is ever
# removed: not config, not var/, not a file the node keeps for itself.
RETIRED=(
  post_interface.php                     # e3c05ea
  lib/request_post_interface_trait.php   # e3c05ea
  lib/request_wake_dispatch_trait.php    # e3c05ea
)

die() { echo "${RED}✗ $*${NC}" >&2; exit 1; }
step() { echo; echo "${CYAN}▸ $*${NC}"; }

trap 'echo "${RED}deploy aborted${NC}"' ERR

# ── 1. The tree must be clean ────────────────────────────────────────────
step "Checking working tree"

if ! git -C "$REPO_DIR" rev-parse --verify "$REF" >/dev/null 2>&1; then
  die "not a valid git ref: ${REF}"
fi

DIRTY="$(git -C "$REPO_DIR" status --porcelain -- "$SRC_PREFIX")"
if [[ -n "$DIRTY" ]]; then
  if [[ "${DEPLOY_ALLOW_DIRTY:-0}" == "1" ]]; then
    echo "${YELLOW}⚠ working tree is dirty and DEPLOY_ALLOW_DIRTY=1 — deploying ${REF} anyway${NC}"
    echo "${YELLOW}  (the files below are NOT what will be deployed)${NC}"
    sed 's/^/    /' <<< "$DIRTY"
  else
    echo "${RED}Uncommitted changes under ${SRC_PREFIX}:${NC}"
    sed 's/^/    /' <<< "$DIRTY"
    echo
    echo "${DIM}Deploys come from git, not from your filesystem. Commit the work"
    echo "(or stash it) so that what runs in production is a thing you can name,"
    echo "diff and roll back to.${NC}"
    die "refusing to deploy with a dirty working tree"
  fi
else
  echo "  ${GREEN}✓${NC} clean"
fi

REF_SHA="$(git -C "$REPO_DIR" rev-parse --short "$REF")"
REF_SUBJECT="$(git -C "$REPO_DIR" log -1 --format=%s "$REF")"
echo "  ${GREEN}✓${NC} deploying ${REF_SHA} — ${REF_SUBJECT}"

# ── 2. The suite must be green ───────────────────────────────────────────
step "Running test suite"

if [[ "${DEPLOY_SKIP_TESTS:-0}" == "1" ]]; then
  echo "  ${YELLOW}⚠ skipped (DEPLOY_SKIP_TESTS=1)${NC}"
else
  TEST_FAIL=0
  for test_file in "$REPO_DIR/php/tests"/*.php; do
    [[ -f "$test_file" ]] || continue
    name="$(basename "$test_file")"
    # stubs/ holds fixtures, not runnable tests
    [[ "$name" == "static_check_methods.php" ]] && continue
    printf "  %-34s " "$name"
    if output="$("$(command -v php)" "$test_file" 2>&1)"; then
      echo "${GREEN}✓${NC}"
    else
      echo "${RED}✗${NC}"
      sed 's/^/      /' <<< "$output" | tail -12
      TEST_FAIL=$((TEST_FAIL + 1))
    fi
  done

  printf "  %-34s " "static_check_methods.php"
  if "$(command -v php)" "$REPO_DIR/php/tests/static_check_methods.php" 2>&1 | grep -q "Undefined: 0"; then
    echo "${GREEN}✓${NC}"
  else
    echo "${RED}✗ undefined methods${NC}"
    TEST_FAIL=$((TEST_FAIL + 1))
  fi

  if [[ $TEST_FAIL -gt 0 ]]; then
    echo
    echo "${DIM}A red suite is the reason regressions ship. Fix the failure, or if it"
    echo "is a known divergence, document it with assertKnownDivergence() so the"
    echo "next real failure is visible.${NC}"
    die "${TEST_FAIL} test file(s) failed — not deploying"
  fi
  echo "  ${GREEN}✓${NC} suite green"
fi

# ── 3. Materialise the ref (never the working directory) ─────────────────
step "Staging ${REF_SHA} from git"

STAGE="$(mktemp -d)"
cleanup() { rm -rf "$STAGE"; }
trap 'cleanup; echo "${RED}deploy aborted${NC}"' ERR
trap cleanup EXIT

git -C "$REPO_DIR" archive "$REF" "$SRC_PREFIX" | tar -x -C "$STAGE" \
  || die "git archive failed"

STAGE_SRC="$STAGE/$SRC_PREFIX"
for excluded in "${EXCLUDE[@]}"; do
  rm -f "$STAGE_SRC/$excluded"
done

FILE_COUNT="$(find "$STAGE_SRC" -name '*.php' -type f | wc -l | tr -d ' ')"
echo "  ${GREEN}✓${NC} ${FILE_COUNT} php files staged from git (working tree untouched)"

"$REPO_DIR/write-build-stamp.sh" "$REF" "$STAGE_SRC" || die "could not write the build stamp"
echo "  ${GREEN}✓${NC} build stamp: $(cat "$STAGE_SRC/build.json")"

# The ref's code as paths under php/src, lib/ first: the swap renames in this
# order. The names go into remote shell commands, so only plain ones pass.
NAME_RE='^(lib/)?[A-Za-z0-9._-]+\.php$'
CODE_FILES=""
for path in "$STAGE_SRC"/lib/*.php "$STAGE_SRC"/*.php; do
  [[ -f "$path" ]] || continue
  rel="${path#"$STAGE_SRC"/}"
  [[ "$rel" =~ $NAME_RE ]] || die "${REF_SHA} has a file name this script will not put in a shell command: ${rel}"
  CODE_FILES="${CODE_FILES:+${CODE_FILES} }${rel}"
done
[[ -n "$CODE_FILES" ]] || die "${REF_SHA} has no php files under ${SRC_PREFIX}"

# The RETIRED files this ref does not ship: the swap removes exactly these.
REMOVE_FILES=""
for retired in ${RETIRED[@]+"${RETIRED[@]}"}; do
  [[ "$retired" =~ $NAME_RE ]] \
    || die "RETIRED may list only top-level and lib/ .php files, all the rollback copy holds: ${retired}"
  case " ${CODE_FILES} " in
    *" ${retired} "*) echo "  ${DIM}${retired} is RETIRED but ${REF_SHA} ships it — kept${NC}" ;;
    *) REMOVE_FILES="${REMOVE_FILES:+${REMOVE_FILES} }${retired}" ;;
  esac
done
[[ -z "$REMOVE_FILES" ]] || echo "  ${GREEN}✓${NC} retiring, where present: ${REMOVE_FILES}"

# Sentinels the remote commands print last, so a lint or swap that did not
# run to the end (a dropped connection, a missing directory) is never read as
# one that found nothing wrong.
LINT_OK="lint-ok"
SWAP_OK="swap-ok"

# ── 4. Upload to every node, outside its web root, and lint there ────────
# Sets host, scp_cmd and ssh_cmd for one node; returns 1 when its host is not
# configured. stage_node, swap_node and stamp_node declare them local before
# calling.
node_commands() {
  local host_var="$1" pass_var="$2"
  local pass="${!pass_var:-}"
  host="${!host_var:-}"
  [[ -n "$host" ]] || return 1

  if [[ -n "$pass" ]]; then
    command -v sshpass >/dev/null 2>&1 || die "sshpass required when ${pass_var} is set"
    scp_cmd=(env "SSHPASS=$pass" sshpass -e scp "${SSH_OPTS[@]}")
    ssh_cmd=(env "SSHPASS=$pass" sshpass -e ssh "${SSH_OPTS[@]}")
  else
    scp_cmd=(scp "${SSH_OPTS[@]}" -o BatchMode=yes)
    ssh_cmd=(ssh "${SSH_OPTS[@]}" -o BatchMode=yes)
  fi
}

# The command that puts a node's rollback copy back. It names the password
# variable, never its value, so a deploy's output carries no secret.
rollback_hint() {
  local host="$1" pass_var="$2" via
  if [[ -n "${!pass_var:-}" ]]; then
    via="SSHPASS=\"\$${pass_var}\" sshpass -e ssh ${SSH_OPTS[*]}"
  else
    via="ssh ${SSH_OPTS[*]} -o BatchMode=yes"
  fi
  echo "${YELLOW}  roll back with: ${via} ${host} 'cp -r ~/${ROLLBACK_DIR}/* ~/${REMOTE_DIR}/'${NC}"
}

# Nodes holding this ref, linted, in ~/reticulum-incoming, one
# "label|host_var|pass_var" per line; step 5 swaps exactly these.
STAGED=""

stage_node() {
  local label="$1" host_var="$2" pass_var="$3"
  local host
  local -a scp_cmd ssh_cmd

  if ! node_commands "$host_var" "$pass_var"; then
    echo "  ${DIM}skipped — ${host_var} not set${NC}"
    return 0
  fi

  # A fresh incoming directory every deploy, so nothing a previous one left
  # there can be linted or swapped in. The live directory is only created,
  # on a node never deployed to; on any other it is not touched.
  "${ssh_cmd[@]}" "$host" "rm -rf ~/${INCOMING_DIR} && mkdir -p ~/${INCOMING_DIR}/lib ~/${REMOTE_DIR}/lib" \
    || die "${label}: could not create ~/${INCOMING_DIR} (nothing live changed)"

  "${scp_cmd[@]}" "$STAGE_SRC"/*.php "$host:~/${INCOMING_DIR}/" >/dev/null \
    || die "${label}: upload of top-level files to ~/${INCOMING_DIR} failed (nothing live changed)"
  if compgen -G "$STAGE_SRC/lib/*.php" >/dev/null; then
    "${scp_cmd[@]}" "$STAGE_SRC"/lib/*.php "$host:~/${INCOMING_DIR}/lib/" >/dev/null \
      || die "${label}: upload of lib to ~/${INCOMING_DIR} failed (nothing live changed)"
  fi

  # The node's own php -l on every file of the ref, by name, so one that did
  # not arrive fails as well. The swap renames, so incoming and live must be
  # on one filesystem: across two, mv copies and is not atomic.
  local lint
  lint="$("${ssh_cmd[@]}" "$host" "cd ~/${INCOMING_DIR} || exit 1; dev() { stat -c %d \"\$1\" 2>/dev/null || stat -f %d \"\$1\"; }; [ \"\$(dev .)\" = \"\$(dev ~/${REMOTE_DIR})\" ] || echo '~/${INCOMING_DIR} and ~/${REMOTE_DIR} are on different filesystems'; for f in ${CODE_FILES}; do out=\$(php -l \$f 2>&1) || echo \"\$f: php -l exited \$?\"; printf '%s\n' \"\$out\" | grep -v '^No syntax errors'; done; echo ${LINT_OK}")"
  if [[ "$lint" != "$LINT_OK" ]]; then
    echo "${RED}  ${REF_SHA} fails the lint on ${label}:${NC}"
    sed -e "/^${LINT_OK}\$/d" -e 's/^/    /' <<< "${lint:-(no answer from the node)}"
    die "${label}: ${REF_SHA} does not parse there — nothing went live on any node"
  fi

  STAGED="${STAGED}${label}|${host_var}|${pass_var}"$'\n'
  echo "  ${GREEN}✓${NC} ${label} — in ~/${INCOMING_DIR} and parsing (not live yet)"
}

swap_node() {
  local label="$1" host_var="$2" pass_var="$3"
  local host
  local -a scp_cmd ssh_cmd
  node_commands "$host_var" "$pass_var" || die "${label}: ${host_var} vanished between upload and swap"

  echo "  ${DIM}backing up current state${NC}"
  # The rollback copy keeps the node's current stamp; a node deployed before
  # stamps gets an explicit unknown one, so restoring the copy never leaves
  # this deploy's commit named on the old code.
  "${ssh_cmd[@]}" "$host" \
    "cd ~/${REMOTE_DIR} && rm -rf ~/${ROLLBACK_DIR} && mkdir -p ~/${ROLLBACK_DIR}/lib && cp *.php ~/${ROLLBACK_DIR}/ 2>/dev/null; cp lib/*.php ~/${ROLLBACK_DIR}/lib/ 2>/dev/null; if [ -f build.json ]; then cp build.json ~/${ROLLBACK_DIR}/; else echo '{\"commit\":null}' > ~/${ROLLBACK_DIR}/build.json; fi; true" \
    || die "${label}: backup failed"

  # The swap, in ONE command. It refuses, with nothing changed, unless every
  # incoming file is there and the rollback copy holds every live file it
  # replaces or removes. Then the stamp says "unknown" (from here until the
  # stamp step the node's code is unproven), every file is renamed over its
  # live name, and the RETIRED files the ref does not ship are removed.
  local swap="cd ~/${REMOTE_DIR} || exit 1"
  swap+="; for f in ${CODE_FILES}; do [ -f ~/${INCOMING_DIR}/\$f ] || { echo \"~/${INCOMING_DIR}/\$f is missing; nothing changed\"; exit 1; }; done"
  swap+="; for f in *.php lib/*.php; do [ -f \"\$f\" ] || continue; sum=\$(cksum < \"\$f\") && [ \"\$sum\" = \"\$(cksum 2>/dev/null < ~/${ROLLBACK_DIR}/\"\$f\")\" ] || { echo \"~/${ROLLBACK_DIR} does not hold \$f; nothing changed\"; exit 1; }; done"
  swap+="; echo '{\"commit\":null}' > build.json || exit 1"
  swap+="; for f in ${CODE_FILES}; do mv -f ~/${INCOMING_DIR}/\$f \$f || exit 1; done"
  if [[ -n "$REMOVE_FILES" ]]; then
    swap+="; for f in ${REMOVE_FILES}; do rm -f \$f || exit 1; done"
  fi
  swap+="; echo ${SWAP_OK}"

  local swapped
  swapped="$("${ssh_cmd[@]}" "$host" "$swap")"
  if [[ "$swapped" != "$SWAP_OK" ]]; then
    echo "${RED}  the swap on ${label} did not complete:${NC}"
    sed -e "/^${SWAP_OK}\$/d" -e 's/^/    /' <<< "${swapped:-(no answer from the node)}"
    rollback_hint "$host" "$pass_var"
    die "${label}: swap failed — unless it says nothing changed, roll back"
  fi

  # Syntax-check what is now live, in place, as it serves requests.
  local lint
  lint="$("${ssh_cmd[@]}" "$host" "cd ~/${REMOTE_DIR} && for f in *.php lib/*.php; do php -l \$f 2>&1 | grep -v '^No syntax errors'; done" 2>/dev/null)"
  if [[ -n "$lint" ]]; then
    echo "${RED}  syntax errors on ${label}:${NC}"
    sed 's/^/    /' <<< "$lint"
    rollback_hint "$host" "$pass_var"
    die "${label}: deployed code does not parse"
  fi

  DEPLOYED="${DEPLOYED}${label}|${host_var}|${pass_var}"$'\n'
  echo "  ${GREEN}✓${NC} ${label} — swapped in and parsing (rollback in ~/${ROLLBACK_DIR})"
}

# Nodes whose code went live in this run, one "label|host_var|pass_var" per
# line; step 7 stamps exactly these.
DEPLOYED=""

# Step 7: the node's bytes are proven, so it may now say which commit it runs.
stamp_node() {
  local label="$1" host_var="$2" pass_var="$3"
  local host
  local -a scp_cmd ssh_cmd
  node_commands "$host_var" "$pass_var" || die "${label}: ${host_var} vanished between deploy and stamp"
  "${scp_cmd[@]}" "$STAGE_SRC/build.json" "$host:~/${REMOTE_DIR}/build.json" >/dev/null \
    || die "${label}: upload of the build stamp failed (code is deployed and verified; /health reports no commit until a deploy completes)"
  echo "  ${GREEN}✓${NC} ${label} — /health now names ${REF_SHA}"
}

if [[ -z "$ONLY_NODE" || "$ONLY_NODE" == "retichat" ]]; then
  step "Uploading to retichat.com (not live yet)"
  stage_node "retichat.com" RETICHAT_SSH_HOST RETICHAT_SSH_PASS
fi
if [[ -z "$ONLY_NODE" || "$ONLY_NODE" == "selectiv" ]]; then
  step "Uploading to selectivesubconscious.com (not live yet)"
  stage_node "selectivesubconscious.com" SELECTIV_SSH_HOST SELECTIV_SSH_PASS
fi

# ── 5. Swap ──────────────────────────────────────────────────────────────
# Only now, with the ref parsing on every node, does anything go live. ssh
# reads stdin, so it gets /dev/null here, not the rest of the node list.
while IFS='|' read -r label host_var pass_var; do
  [[ -n "$label" ]] || continue
  step "Going live on ${label}"
  swap_node "$label" "$host_var" "$pass_var" </dev/null
done <<< "$STAGED"

# ── 6. Prove it ──────────────────────────────────────────────────────────
step "Verifying deployed bytes against ${REF_SHA}"
if "$REPO_DIR/verify-deploy.sh" "$REF" "$ONLY_NODE"; then
  VERIFY_OK=1
else
  VERIFY_OK=0
fi

printf '%s  ref=%s  nodes=%s  dirty_override=%s  tests_skipped=%s  verified=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$REF_SHA" "${ONLY_NODE:-all}" \
  "${DEPLOY_ALLOW_DIRTY:-0}" "${DEPLOY_SKIP_TESTS:-0}" "$VERIFY_OK" >> "$LOG_FILE"

[[ $VERIFY_OK -eq 1 ]] || die "post-deploy verification failed — nodes do not match ${REF_SHA}; their /health reports no commit"

# ── 7. Stamp ─────────────────────────────────────────────────────────────
step "Stamping verified nodes"
while IFS='|' read -r label host_var pass_var; do
  [[ -n "$label" ]] || continue
  stamp_node "$label" "$host_var" "$pass_var"
done <<< "$DEPLOYED"

echo
echo "${GREEN}✓ ${REF_SHA} deployed and verified${NC}"
