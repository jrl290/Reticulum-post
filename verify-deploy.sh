#!/usr/bin/env bash
#
# verify-deploy.sh — does each live node match a given git ref?
#
# Answers, in about five seconds, the question that today took an hour of
# hand-diffing: "is production actually running what I think it is?"
#
#   ./verify-deploy.sh              # compare both nodes against HEAD
#   ./verify-deploy.sh 71b5229      # ...against a specific ref
#   ./verify-deploy.sh HEAD retichat
#
# Exit status is 0 only when every deployed file matches the ref byte for byte.
# That makes it usable as a gate, not just a report.
#
# Credentials come from the environment, never from this file:
#
#   export RETICHAT_SSH_PASS=...     RETICHAT_SSH_HOST=retichat@retichat.com
#   export SELECTIV_SSH_PASS=...     SELECTIV_SSH_HOST=selectiv@selectivesubconscious.com
#
# Put those in a gitignored deploy.env and `source` it. The passwords currently
# hardcoded in post-deploy-check.sh should be rotated and moved here.

set -uo pipefail

REF="${1:-HEAD}"
ONLY_NODE="${2:-}"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_PREFIX="php/src"
REMOTE_DIR="public_html/reticulum"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; DIM=$'\033[2m'; NC=$'\033[0m'

SSH_OPTS=(-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o LogLevel=ERROR)

drift_total=0
checked_total=0

# Files that live on the node but are deliberately not tracked in git.
# config.toml holds per-node secrets; var/ is runtime state.
is_ignored() {
  case "$1" in
    config.toml|config.local.toml|config.php|_test.php|error_log) return 0 ;;
    var/*) return 0 ;;
    *) return 1 ;;
  esac
}

# macOS ships `md5`, Linux ships `md5sum`. Normalise to a bare hex digest so the
# local and remote sides are directly comparable.
if command -v md5sum >/dev/null 2>&1; then
  md5_stdin() { md5sum | cut -d' ' -f1; }
else
  md5_stdin() { md5 -q; }
fi

remote_sh() {
  local host_var="$1"; shift
  local pass_var="$1"; shift
  local host="${!host_var:-}"
  local pass="${!pass_var:-}"

  if [[ -z "$host" ]]; then
    return 97
  fi

  if [[ -n "$pass" ]]; then
    if ! command -v sshpass >/dev/null 2>&1; then
      return 98
    fi
    SSHPASS="$pass" sshpass -e ssh "${SSH_OPTS[@]}" "$host" "$@" 2>/dev/null
  else
    ssh "${SSH_OPTS[@]}" -o BatchMode=yes "$host" "$@" 2>/dev/null
  fi
}

verify_node() {
  local label="$1" host_var="$2" pass_var="$3"

  echo "${CYAN}── ${label} ─────────────────────────────────${NC}"

  # One round trip: md5 every php file the node serves.
  local remote_hashes
  remote_hashes="$(remote_sh "$host_var" "$pass_var" \
    "cd ~/${REMOTE_DIR} 2>/dev/null && find . -name '*.php' -type f -print0 | xargs -0 md5sum 2>/dev/null | sed 's|\./||'")"
  local rc=$?

  if [[ $rc -eq 97 ]]; then
    echo "  ${DIM}skipped — ${host_var} not set${NC}"; echo; return 0
  elif [[ $rc -eq 98 ]]; then
    echo "  ${RED}sshpass not installed but ${pass_var} is set${NC}"; echo; return 1
  elif [[ -z "$remote_hashes" ]]; then
    echo "  ${RED}unreachable, or ~/${REMOTE_DIR} is missing${NC}"; echo; return 1
  fi

  local drift=0 checked=0 missing=0 untracked=0

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local rhash rpath
    rhash="${line%% *}"
    rpath="${line##* }"

    is_ignored "$rpath" && continue

    if ! git -C "$REPO_DIR" cat-file -e "${REF}:${SRC_PREFIX}/${rpath}" 2>/dev/null; then
      untracked=$((untracked + 1))
      echo "  ${YELLOW}?${NC} ${rpath} ${DIM}— on node, not in ${REF}${NC}"
      continue
    fi

    # Stream the blob straight into md5. Never round-trip file bytes through a
    # shell variable: $(...) strips every trailing newline, so a file that ends
    # in one hashes differently from the identical bytes on the node and every
    # file reports as drifted — which is exactly as useless as no check at all.
    local lhash
    lhash="$(git -C "$REPO_DIR" show "${REF}:${SRC_PREFIX}/${rpath}" 2>/dev/null | md5_stdin)"

    checked=$((checked + 1))
    if [[ "$lhash" != "$rhash" ]]; then
      drift=$((drift + 1))
      echo "  ${RED}✗${NC} ${rpath} ${DIM}— differs from ${REF}${NC}"
    fi
  done <<< "$remote_hashes"

  # The reverse direction: tracked files the node is missing entirely.
  while IFS= read -r tracked; do
    local rel="${tracked#${SRC_PREFIX}/}"
    is_ignored "$rel" && continue
    if ! grep -qF " ${rel}" <<< "$remote_hashes" && ! grep -qF "  ${rel}" <<< "$remote_hashes"; then
      missing=$((missing + 1))
      echo "  ${RED}✗${NC} ${rel} ${DIM}— in ${REF}, absent from node${NC}"
    fi
  done < <(git -C "$REPO_DIR" ls-tree -r --name-only "$REF" -- "${SRC_PREFIX}" | grep '\.php$')

  local bad=$((drift + missing))
  if [[ $bad -eq 0 ]]; then
    echo "  ${GREEN}✓${NC} ${checked} files match ${REF}${untracked:+ (${untracked} untracked on node)}"
  else
    echo "  ${RED}${bad} file(s) drifted from ${REF}${NC}"
  fi
  echo

  drift_total=$((drift_total + bad))
  checked_total=$((checked_total + checked))
  return 0
}

echo
echo "${CYAN}Deploy drift vs $(git -C "$REPO_DIR" rev-parse --short "$REF") ($(git -C "$REPO_DIR" log -1 --format=%s "$REF" | cut -c1-60))${NC}"
echo

if [[ -z "$ONLY_NODE" || "$ONLY_NODE" == "retichat" ]]; then
  verify_node "retichat.com" RETICHAT_SSH_HOST RETICHAT_SSH_PASS
fi
if [[ -z "$ONLY_NODE" || "$ONLY_NODE" == "selectiv" ]]; then
  verify_node "selectivesubconscious.com" SELECTIV_SSH_HOST SELECTIV_SSH_PASS
fi

if [[ $drift_total -eq 0 ]]; then
  echo "${GREEN}✓ every node matches ${REF} (${checked_total} files checked)${NC}"
  exit 0
fi

echo "${RED}✗ ${drift_total} file(s) drifted — the nodes are NOT running ${REF}${NC}"
exit 1
