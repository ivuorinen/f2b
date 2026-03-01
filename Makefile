# f2b Makefile

.PHONY: help all build test lint fmt clean install
.PHONY: ci ci-coverage test-verbose test-coverage update-deps fmt-md
.PHONY: lint-go lint-md lint-yaml lint-actions lint-make
.PHONY: security dev-setup pre-commit-setup
.PHONY: release-dry-run release release-snapshot release-check _check-tag

# Tool versions (managed by Renovate)
# renovate: datasource=go depName=github.com/goreleaser/goreleaser/v2
GORELEASER_VERSION := v2.14.1
# renovate: datasource=go depName=github.com/golangci/golangci-lint/v2/cmd/golangci-lint
GOLANGCI_LINT_VERSION := v2.10.1
# renovate: datasource=go depName=github.com/google/yamlfmt/cmd/yamlfmt
YAMLFMT_VERSION := v0.21.0
# renovate: datasource=go depName=github.com/rhysd/actionlint/cmd/actionlint
ACTIONLINT_VERSION := v1.7.11
# renovate: datasource=go depName=golang.org/x/tools/cmd/goimports
GOIMPORTS_VERSION := v0.42.0
# renovate: datasource=go depName=github.com/editorconfig-checker/editorconfig-checker/v3/cmd/editorconfig-checker
EDITORCONFIG_CHECKER_VERSION := v3.6.1
# renovate: datasource=go depName=github.com/securego/gosec/v2/cmd/gosec
GOSEC_VERSION := v2.24.0
# renovate: datasource=go depName=honnef.co/go/tools/cmd/staticcheck
STATICCHECK_VERSION := v0.7.0
# renovate: datasource=go depName=github.com/mgechev/revive
REVIVE_VERSION := v1.14.0
# renovate: datasource=go depName=github.com/checkmake/checkmake/cmd/checkmake
CHECKMAKE_VERSION := v0.3.2
# renovate: datasource=go depName=github.com/segmentio/golines
GOLINES_VERSION := v0.13.0

# Default target
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: ci ## Run all CI checks (same as ci target)
	@echo "All checks completed"

# Build targets
build: ## Build the f2b binary
	go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=dev" -o f2b .

install: ## Install f2b globally
	go install github.com/ivuorinen/f2b@latest

# Testing targets
test: ## Run all tests
	go test ./...

test-verbose: ## Run tests with verbose output
	go test -v ./...

test-coverage: ## Run tests with coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

update-deps: ## Update Go dependencies to latest patch versions
	go get -u=patch ./...
	go mod tidy
	go mod verify
	@go list -u -m all | grep '\[' || true

# Code quality targets
fmt: ## Format Go code
	gofmt -w .

fmt-md: ## Format Markdown files
	@pre-commit run mdformat --all-files

lint: ## Run all linters using pre-commit (preferred method)
	@pre-commit run --all-files

lint-go: ## Run only Go linters
	go vet ./...
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m

lint-md: ## Run only Markdown linter
	npx --yes markdownlint-cli2@0.21.0 "*.md" "**/*.md"

lint-yaml: ## Run only YAML linter
	go run github.com/google/yamlfmt/cmd/yamlfmt@$(YAMLFMT_VERSION) -lint .

lint-actions: ## Run only GitHub Actions linter
	go run github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION) .github/workflows/*.yml

lint-make: ## Run only Makefile linter
	go run github.com/checkmake/checkmake/cmd/checkmake@$(CHECKMAKE_VERSION) Makefile

# CI targets
ci: fmt lint test ## Run all CI checks (format, lint, test)

ci-coverage: fmt lint test-coverage ## Run CI checks with coverage

# Security targets
security: ## Run security checks
	go run github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) ./...

# Cleanup targets
clean: ## Clean build artifacts
	rm -f f2b coverage.out coverage.html
	go clean

# Development targets
dev-setup: pre-commit-setup ## Set up development environment

pre-commit-setup: ## Install and configure pre-commit hooks
	@command -v pre-commit >/dev/null 2>&1 || pip install pre-commit
	@pre-commit install

# Release targets
release-dry-run: ## Test release process without creating artifacts
	@VERSION=$$(git describe --tags --exact-match 2>/dev/null || echo "v0.0.0-dev"); \
	echo "Building version: $$VERSION"; \
	go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=$$VERSION" -o f2b-test . && rm -f f2b-test

release: _check-tag ## Create a new release using GoReleaser
	go run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) release --clean

_check-tag: ## Internal: Check if a git tag exists
	@if [ -z "$$(git describe --exact-match 2>/dev/null)" ]; then \
		echo "Error: No tag found. Please create a tag first (e.g., git tag v1.0.0)"; \
		exit 1; \
	fi

release-snapshot: ## Create a snapshot release (no tag required)
	go run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) release --snapshot --clean

release-check: ## Check if GoReleaser configuration is valid
	go run github.com/goreleaser/goreleaser/v2@$(GORELEASER_VERSION) check
