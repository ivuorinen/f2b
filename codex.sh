#!/usr/bin/env bash
# Install development tooling for the f2b project.
# This script installs all tools required for development and CI/CD.
set -euo pipefail

# Determine Go environment
if ! command -v go >/dev/null; then
  echo "Go is required to install tools" >&2
  exit 1
fi

echo "Setting up development environment using Makefile..."

# make dev-setup installs prek and configures its git hooks; other tools
# (golangci-lint, yamlfmt, actionlint, ...) run on demand via `go run`
# with versions pinned in the Makefile.
make dev-setup

echo "Development environment ready!"
