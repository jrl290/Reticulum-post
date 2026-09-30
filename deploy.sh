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
#   4. hash-verify every node afterward — proof, not hope
#   5. only then stamp each node with the commit it runs
#
# It also leaves a build stamp: build.json (write-build-stamp.sh) names the
# commit, and GET /health publishes it, so verify-live-stamp.sh can say which
# commit each node runs without credentials. /health must never name a commit
# the node was not proven to run, so before any code goes up the node's stamp
# is replaced with an unknown one ({"commit":null}), and the new stamp is
# uploaded only after verify-deploy.sh has proved every node's bytes. A
# deploy that stops anywhere in between leaves "unknown", never the old
# commit's name on new code or the new commit's name on unverified code. The
# rollback copy carries the previous stamp (or an explicit unknown one), so
# restoring it does not leave the new commit's name on old code either.
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
LOG_FILE="${REPO_DIR}/.deploy.log"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; DIM=$'\033[2m'; NC=$'\033[0m'
SSH_OPTS=(-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o LogLevel=ERROR)

# Files the node owns that a deploy must never overwrite: per-node secrets and
# runtime state. Deploying config.toml would push retichat's MySQL password to
# selectiv and break it.
EXCLUDE=(config.toml config.local.toml config.php _test.php)

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

# ── 4. Push ──────────────────────────────────────────────────────────────
# Sets host, scp_cmd and ssh_cmd for one node; returns 1 when its host is not
# configured. deploy_node and stamp_node declare them local before calling.
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

# Nodes whose code went up in this run, one "label|host_var|pass_var" per
# line; step 6 stamps exactly these.
DEPLOYED=""

deploy_node() {
  local label="$1" host_var="$2" pass_var="$3"
  local host
  local -a scp_cmd ssh_cmd

  if ! node_commands "$host_var" "$pass_var"; then
    echo "  ${DIM}skipped — ${host_var} not set${NC}"
    return 0
  fi

  echo "  ${DIM}backing up current state${NC}"
  # The rollback copy keeps the node's current stamp; a node deployed before
  # stamps gets an explicit unknown one, so restoring the copy never leaves
  # this deploy's commit named on the old code.
  "${ssh_cmd[@]}" "$host" \
    "cd ~/${REMOTE_DIR} && rm -rf ../reticulum-rollback && mkdir -p ../reticulum-rollback/lib && cp *.php ../reticulum-rollback/ 2>/dev/null; cp lib/*.php ../reticulum-rollback/lib/ 2>/dev/null; if [ -f build.json ]; then cp build.json ../reticulum-rollback/; else echo '{\"commit\":null}' > ../reticulum-rollback/build.json; fi; true" \
    || die "${label}: backup failed"

  # From here until the stamp step the node's code is in flux or unproven: it
  # says "unknown", not the commit it ran before.
  "${ssh_cmd[@]}" "$host" "mkdir -p ~/${REMOTE_DIR}/lib && echo '{\"commit\":null}' > ~/${REMOTE_DIR}/build.json" \
    || die "${label}: mkdir or clearing the build stamp failed"

  "${scp_cmd[@]}" "$STAGE_SRC"/*.php "$host:~/${REMOTE_DIR}/" >/dev/null \
    || die "${label}: upload of top-level files failed"
  if compgen -G "$STAGE_SRC/lib/*.php" >/dev/null; then
    "${scp_cmd[@]}" "$STAGE_SRC"/lib/*.php "$host:~/${REMOTE_DIR}/lib/" >/dev/null \
      || die "${label}: upload of lib failed"
  fi

  # Syntax-check what actually landed, before it serves a request.
  local lint
  lint="$("${ssh_cmd[@]}" "$host" "cd ~/${REMOTE_DIR} && for f in *.php lib/*.php; do php -l \$f 2>&1 | grep -v '^No syntax errors'; done" 2>/dev/null)"
  if [[ -n "$lint" ]]; then
    echo "${RED}  syntax errors on ${label}:${NC}"
    sed 's/^/    /' <<< "$lint"
    echo "${YELLOW}  roll back with: ${ssh_cmd[*]} ${host} 'cp -r ~/reticulum-rollback/* ~/${REMOTE_DIR}/'${NC}"
    die "${label}: deployed code does not parse"
  fi

  DEPLOYED="${DEPLOYED}${label}|${host_var}|${pass_var}"$'\n'
  echo "  ${GREEN}✓${NC} ${label} — uploaded and parsing (rollback in ~/reticulum-rollback)"
}

# Step 6: the node's bytes are proven, so it may now say which commit it runs.
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
  step "Deploying to retichat.com"
  deploy_node "retichat.com" RETICHAT_SSH_HOST RETICHAT_SSH_PASS
fi
if [[ -z "$ONLY_NODE" || "$ONLY_NODE" == "selectiv" ]]; then
  step "Deploying to selectivesubconscious.com"
  deploy_node "selectivesubconscious.com" SELECTIV_SSH_HOST SELECTIV_SSH_PASS
fi

# ── 5. Prove it ──────────────────────────────────────────────────────────
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

# ── 6. Stamp ─────────────────────────────────────────────────────────────
step "Stamping verified nodes"
while IFS='|' read -r label host_var pass_var; do
  [[ -n "$label" ]] || continue
  stamp_node "$label" "$host_var" "$pass_var"
done <<< "$DEPLOYED"

echo
echo "${GREEN}✓ ${REF_SHA} deployed and verified${NC}"
