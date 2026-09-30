#!/usr/bin/env bash
#
# write-build-stamp.sh <ref> <dir> — write <dir>/build.json naming the commit
# that <ref> resolves to, for GET /health to publish as build.commit.
#
# deploy.sh calls this on the git-archive stage it is about to upload. The
# nodes hold no .git (deploys come from `git archive`), so without a stamp the
# only way to learn what a node runs is to md5 its files over SSH
# (verify-deploy.sh). With it, verify-live-stamp.sh answers "is <ref> live?"
# from the public /health, with no credentials.
#
# The stamp names the full 40-hex commit, never a branch or a short sha, and
# the UTC time it was written. BuildStamp::read() in index.php publishes only
# those two fields, and only when they have exactly that shape.

set -euo pipefail

REF="${1:?usage: write-build-stamp.sh <ref> <dir>}"
DIR="${2:?usage: write-build-stamp.sh <ref> <dir>}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SHA="$(git -C "$REPO_DIR" rev-parse --verify --quiet "${REF}^{commit}")" \
  || { echo "write-build-stamp.sh: not a commit: ${REF}" >&2; exit 1; }
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] \
  || { echo "write-build-stamp.sh: unexpected sha '${SHA}' for ${REF}" >&2; exit 1; }
[[ -d "$DIR" ]] || { echo "write-build-stamp.sh: no such directory: ${DIR}" >&2; exit 1; }

printf '{"commit":"%s","stamped_at":"%s"}\n' "$SHA" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${DIR}/build.json"
