#!/usr/bin/env bash
# Point this clone at the in-tree hooks dir so the pre-commit secret scanner runs.
set -euo pipefail
git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true
echo "[autosec] git hooks installed: core.hooksPath=.githooks"
