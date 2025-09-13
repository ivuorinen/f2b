# f2b Development Commands

## Quick Reference (Most Used)

```bash
# Test & Build (Primary workflow)
make test                 # Run all tests
make build               # Build f2b binary
make ci                  # Complete CI pipeline (format, lint, test)

# Dependency Management (NEW 2025-09-13)
make update-deps         # Update all Go dependencies to latest versions

# Linting (Essential for code quality)
make lint                # Run all linters via pre-commit (PREFERRED)
pre-commit run --all-files  # Alternative direct pre-commit usage

# Setup (One-time)
make dev-setup           # Complete development environment setup
make pre-commit-setup    # Install pre-commit hooks only
```

## Dependency Management (NEW)

```bash
# Update dependencies (Added 2025-09-13)
make update-deps                    # Update all dependencies + show changes
go get -u ./...                     # Direct dependency update
go mod tidy                         # Clean up go.mod and go.sum
go list -u -m all                   # Check for available updates
```

## Build & Installation

```bash
# Development build
go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=dev" -o f2b .

# Production build with version
go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=1.2.3" -o f2b .

# Install latest
go install github.com/ivuorinen/f2b@latest

# Clean artifacts
make clean
```

## Testing (Comprehensive)

```bash
# Basic testing
go test ./...                     # All tests
go test -v ./...                  # Verbose output
make test-verbose                 # Via Makefile

# Coverage analysis
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
make test-coverage               # Combined coverage workflow

# Security testing
F2B_TEST_SUDO=true go test ./fail2ban -run TestSudo
go test ./fail2ban -run TestPath  # Path traversal tests
```

## Code Quality & Linting

### Primary Method (Unified)

```bash
make lint                        # Run ALL linters via pre-commit
pre-commit run --all-files       # Direct pre-commit execution
```

### Individual Linters (Debugging)

```bash
make lint-go                     # Go-specific linting
make lint-md                     # Markdown linting
make lint-yaml                   # YAML linting
make lint-actions                # GitHub Actions linting
make lint-make                   # Makefile linting

# Direct tool usage
golangci-lint run --timeout=5m
markdownlint-cli "**/*.md"
yamlfmt -lint .
actionlint .github/workflows/*.yml
```

## Development Environment

```bash
# Complete setup (recommended for new contributors)
make dev-setup                   # Install all tools + pre-commit hooks

# Individual components
make dev-deps                    # Install development dependencies
make check-deps                  # Verify all tools installed
make pre-commit-setup           # Install pre-commit hooks only
```

## Release Management

```bash
# Release preparation
make release-check              # Validate GoReleaser config
make release-dry-run           # Test release without artifacts

# Release execution
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3
make release                   # Full release (requires tag)
make release-snapshot         # Snapshot (no tag required)
```

## Security & Analysis

```bash
make security                  # Run gosec security analysis
gosec ./...                   # Direct security scanning
staticcheck ./...             # Advanced static analysis
revive ./...                  # Code style analysis
```

## System Utilities (macOS/Darwin)

```bash
# File operations
find . -name "*.go" -type f    # Find Go files
grep -r "pattern" .            # Search in files
ls -la                         # List files with details
pwd                           # Current directory

# Development tools
which go                      # Go binary location (should show 1.25.0)
which golangci-lint          # Linter location
which pre-commit             # Pre-commit location
```

## Environment Variables

```bash
# Core configuration
export F2B_LOG_LEVEL=debug           # Enable debug logging
export F2B_VERBOSE_TESTS=true        # Force verbose in CI
export F2B_TEST_SUDO=false          # Disable sudo in tests

# Development paths
export ALLOW_DEV_PATHS=true         # Allow /tmp paths (dev only)
```

## CI/CD Integration

```bash
# GitHub Actions equivalent commands
make ci                              # Complete CI pipeline
make ci-coverage                     # CI with coverage
GITHUB_ACTIONS=true go test ./...    # CI-aware testing
```

## Docker (Multi-Architecture)

```bash
# Development container
docker build -t f2b-dev .
docker run --rm f2b-dev version

# Production images (auto-built on release)
docker pull ghcr.io/ivuorinen/f2b:latest
docker pull ghcr.io/ivuorinen/f2b:latest-arm64
```

## Version Information (Updated 2025-09-13)

```bash
go version                          # Should show: go version go1.25.0
./f2b version                       # Show f2b version information
go list -m -versions github.com/ivuorinen/f2b  # Available versions
```
