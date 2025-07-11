#!/usr/bin/env bash
# Install development tooling for the f2b project.
# This script installs Go-based tools used for linting and formatting.
set -euo pipefail

# Determine Go environment
if ! command -v go >/dev/null; then
  echo "Go is required to install tools" >&2
  exit 1
fi

# Install goimports for formatting
echo "Installing goimports..."
go install golang.org/x/tools/cmd/goimports@latest

# Install golangci-lint for linting
echo "Installing golangci-lint..."
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

echo "Tool installation complete."
