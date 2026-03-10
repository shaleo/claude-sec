#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Install/sync dependencies
UV_CACHE_DIR="${TMPDIR:-/tmp}/uv-cache" uv sync --quiet 2>/dev/null

# Run the scan against your actual Claude Code config
UV_CACHE_DIR="${TMPDIR:-/tmp}/uv-cache" uv run claude-sec \
  --project-dir "$(pwd)" \
  --output claude-sec-report.html \
  "$@"

# Open the report in the default browser
open claude-sec-report.html 2>/dev/null || xdg-open claude-sec-report.html 2>/dev/null || echo "Open claude-sec-report.html in your browser"
