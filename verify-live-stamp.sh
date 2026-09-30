#!/usr/bin/env bash
#
# verify-live-stamp.sh — which commit does each node say it runs? No credentials.
#
#   ./verify-live-stamp.sh                     # both nodes vs HEAD
#   ./verify-live-stamp.sh 84e72ba             # ...vs a specific ref
#   ./verify-live-stamp.sh HEAD selectiv       # one node
#   HEALTH_URL=http://127.0.0.1:8080/health ./verify-live-stamp.sh HEAD
#                                              # any node, by its /health URL
#
# Reads build.commit from the node's public GET /health (written by deploy.sh,
# through write-build-stamp.sh, from the ref it deployed) and compares it with
# the commit <ref> resolves to here.
#
# What it proves: the last deploy.sh run whose bytes verify-deploy.sh proved on
# the node. deploy.sh clears the stamp to "unknown" before any code goes up and
# writes the new one only after that proof, so a deploy that stopped part way
# reads as "unknown" (exit 2), never as a commit. What it does not prove: the
# bytes now. A file edited by hand after the deploy is invisible here; the
# byte-level proof is still verify-deploy.sh, which needs SSH. Run this one for
# drift checks from anywhere; run that one when the answer matters.
#
# Exit status: 0 every node matches; 1 a node runs a different commit;
# 2 a node could not be read or carries no stamp (deployed before 2026-09-30,
# not by deploy.sh, or by a deploy.sh run that did not reach verification).

set -uo pipefail

REF="${1:-HEAD}"
ONLY_NODE="${2:-}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'; DIM=$'\033[2m'; NC=$'\033[0m'

WANT="$(git -C "$REPO_DIR" rev-parse --verify --quiet "${REF}^{commit}")" \
  || { echo "${RED}✗ not a commit here: ${REF}${NC}" >&2; exit 2; }

# build.commit and build.stamped_at from a /health body on stdin; empty when
# absent. php is on every machine that can run deploy.sh.
extract_build() {
  php -r '
    $d = json_decode(stream_get_contents(STDIN), true);
    $b = is_array($d) && is_array($d["build"] ?? null) ? $d["build"] : [];
    $c = is_string($b["commit"] ?? null) ? $b["commit"] : "";
    $t = is_string($b["stamped_at"] ?? null) ? $b["stamped_at"] : "";
    echo preg_match("/^[0-9a-f]{40}$/", $c) === 1 ? $c : "", "|", $t, "\n";
  '
}

mismatch=0
unknown=0

check_node() {
  local label="$1" url="$2"
  local body live stamped
  if ! body="$(curl -fsS --max-time 10 "$url" 2>/dev/null)"; then
    echo "  ${RED}?${NC} ${label} ${DIM}— ${url} did not answer${NC}"
    unknown=$((unknown + 1)); return
  fi
  IFS='|' read -r live stamped <<< "$(extract_build <<< "$body")"
  if [[ -z "$live" ]]; then
    echo "  ${YELLOW}?${NC} ${label} ${DIM}— no build stamp in /health (deployed before stamps, not by deploy.sh, or a deploy that did not verify)${NC}"
    unknown=$((unknown + 1)); return
  fi
  if [[ "$live" == "$WANT" ]]; then
    echo "  ${GREEN}✓${NC} ${label} runs ${live:0:7} ${DIM}(stamped ${stamped:-?})${NC}"
    return
  fi
  local relation="not in this repository — fetch, or it was deployed from elsewhere"
  if git -C "$REPO_DIR" cat-file -e "${live}^{commit}" 2>/dev/null; then
    if git -C "$REPO_DIR" merge-base --is-ancestor "$live" "$WANT" 2>/dev/null; then
      relation="$(git -C "$REPO_DIR" rev-list --count "${live}..${WANT}") commit(s) behind ${REF}"
    elif git -C "$REPO_DIR" merge-base --is-ancestor "$WANT" "$live" 2>/dev/null; then
      relation="$(git -C "$REPO_DIR" rev-list --count "${WANT}..${live}") commit(s) ahead of ${REF}"
    else
      relation="diverged from ${REF}"
    fi
    relation="${relation}: $(git -C "$REPO_DIR" log -1 --format=%s "$live" | cut -c1-60)"
  fi
  echo "  ${RED}✗${NC} ${label} runs ${live:0:7} ${DIM}(stamped ${stamped:-?}), ${relation}${NC}"
  mismatch=$((mismatch + 1))
}

echo
echo "${CYAN}Live build stamp vs ${WANT:0:7} ($(git -C "$REPO_DIR" log -1 --format=%s "$WANT" | cut -c1-60))${NC}"

if [[ -n "${HEALTH_URL:-}" ]]; then
  check_node "${HEALTH_URL}" "${HEALTH_URL}"
else
  if [[ -z "$ONLY_NODE" || "$ONLY_NODE" == "retichat" ]]; then
    check_node "retichat.com" "https://retichat.com/reticulum/health"
  fi
  if [[ -z "$ONLY_NODE" || "$ONLY_NODE" == "selectiv" ]]; then
    check_node "selectivesubconscious.com" "https://selectivesubconscious.com/reticulum/health"
  fi
fi
echo

if [[ $mismatch -gt 0 ]]; then
  echo "${RED}✗ ${mismatch} node(s) run a different commit than ${REF}${NC}"; exit 1
fi
if [[ $unknown -gt 0 ]]; then
  echo "${YELLOW}? ${unknown} node(s) could not say what they run${NC}"; exit 2
fi
echo "${GREEN}✓ every node checked reports ${REF} (${WANT:0:7})${NC}"
exit 0
