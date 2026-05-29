#!/usr/bin/env bash
# Run AutoSec inside the clean-room container.
#
# Auth strategy:
#   - GitHub: pass host's gh token via GH_TOKEN env (read-only, scoped to user)
#   - Claude: bind-mount ~/.claude and ~/.claude.json read-write (login state)
#   - git identity: pass through HOST git user.name / user.email so commits attribute correctly
#
# Usage:
#   ./run-docker.sh <repoUrl> [--dry-run] [--max-iters N] [--branch-base main]

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <repoUrl> [autosec args...]" >&2
  exit 2
fi

GH_TOKEN_VAL="$(gh auth token 2>/dev/null || true)"
GIT_NAME="$(git config --global user.name 2>/dev/null || echo 'AutoSec Bot')"
GIT_EMAIL="$(git config --global user.email 2>/dev/null || echo 'autosec@example.invalid')"

mkdir -p "$HOME/.autosec-runs"

TTY_FLAG=""
if [ -t 0 ] && [ -t 1 ]; then TTY_FLAG="-it"; fi

exec docker run --rm $TTY_FLAG \
  -e GH_TOKEN="$GH_TOKEN_VAL" \
  -e GITHUB_TOKEN="$GH_TOKEN_VAL" \
  -e GIT_AUTHOR_NAME="$GIT_NAME" \
  -e GIT_AUTHOR_EMAIL="$GIT_EMAIL" \
  -e GIT_COMMITTER_NAME="$GIT_NAME" \
  -e GIT_COMMITTER_EMAIL="$GIT_EMAIL" \
  -v "$HOME/.claude:/root/.claude" \
  -v "$HOME/.claude.json:/root/.claude.json" \
  -v "$HOME/.autosec-runs:/tmp/autosec-runs" \
  autosec:dev \
  run "$@"
