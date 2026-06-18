#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${CODEX_HOME:-$HOME/.codex}/skills/cnb-devops-skill"

mkdir -p "$(dirname "$TARGET_DIR")"

if [[ -e "$TARGET_DIR" && ! -L "$TARGET_DIR" ]]; then
  echo "Target already exists: $TARGET_DIR" >&2
  echo "Remove it first or install manually." >&2
  exit 1
fi

ln -sfn "$ROOT_DIR" "$TARGET_DIR"
echo "Installed cnb-devops-skill -> $TARGET_DIR"
echo "Restart Codex or start a new session to load the skill."
