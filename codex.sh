#!/usr/bin/env bash
# Install development tooling for the f2b project.
# This script installs all tools required for development and CI/CD.
set -euo pipefail

# Determine Go environment
if ! command -v go >/dev/null; then
  echo "Go is required to install tools" >&2
  exit 1
fi

echo "Installing all development dependencies using Makefile..."

# Use make dev-deps for all tool installation - this handles:
# - golangci-lint, markdownlint-cli2, yamlfmt, actionlint
# - goimports, editorconfig-checker, gosec, staticcheck, revive, checkmake
make dev-deps

echo "All development tools installed successfully!"
echo "Run 'make check-deps' to verify all dependencies are available."
