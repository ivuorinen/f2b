# f2b Makefile

.PHONY: help all build test lint fmt clean install dev-deps ci \
	check-deps test-verbose test-coverage update-deps \
	lint-go lint-md lint-yaml lint-actions lint-make \
	ci ci-coverage security dev-setup pre-commit-setup \
	release-dry-run release release-snapshot release-check _check-tag

# Default target
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: ci ## Run all CI checks (same as ci target)
	@echo "All checks completed ✓"

# Build targets
build: ## Build the f2b binary
	go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=dev" -o f2b .

install: ## Install f2b globally
	go install github.com/ivuorinen/f2b@latest

# Development dependencies
dev-deps: ## Install development dependencies
	@echo "Installing development dependencies..."
	@echo ""
	@echo "Installing goreleaser..."
	@go install github.com/goreleaser/goreleaser/v2@v2.12.0;
	# renovate: datasource=go depName=github.com/goreleaser/goreleaser/v2
	@echo "Installing golangci-lint...";
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0;
	# renovate: datasource=go depName=github.com/golangci/golangci-lint/v2/cmd/golangci-lint
	@command -v markdownlint-cli2 >/dev/null 2>&1 || { \
		echo "Installing markdownlint-cli2..."; \
		npm install -g markdownlint-cli2; \
	}
	@command -v markdown-link-check >/dev/null 2>&1 || { \
		echo "Installing markdown-link-check..."; \
		npm install -g markdown-link-check; \
	}
	@command -v yamlfmt >/dev/null 2>&1 || { \
		echo "Installing yamlfmt..."; \
		go install github.com/google/yamlfmt/cmd/yamlfmt@v0.17.2; \
	}
	# renovate: datasource=go depName=github.com/google/yamlfmt/cmd/yamlfmt
	@command -v actionlint >/dev/null 2>&1 || { \
		echo "Installing actionlint..."; \
		go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.7; \
	}
	# renovate: datasource=go depName=github.com/rhysd/actionlint/cmd/actionlint
	@command -v goimports >/dev/null 2>&1 || { \
		echo "Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	}
	@command -v editorconfig-checker >/dev/null 2>&1 || { \
		echo "Installing editorconfig-checker..."; \
		go install github.com/editorconfig-checker/editorconfig-checker/v3/cmd/editorconfig-checker@v3.4.0; \
	}
	# renovate: datasource=go depName=github.com/editorconfig-checker/editorconfig-checker/v3
	@command -v gosec >/dev/null 2>&1 || { \
		echo "Installing gosec..."; \
		go install github.com/securego/gosec/v2/cmd/gosec@v2.22.8; \
	}
	# renovate: datasource=go depName=github.com/securego/gosec/v2/cmd/gosec
	@command -v staticcheck >/dev/null 2>&1 || { \
		echo "Installing staticcheck..."; \
		go install honnef.co/go/tools/cmd/staticcheck@2024.1.1; \
	}
	# renovate: datasource=go depName=honnef.co/go/tools/cmd/staticcheck
	@command -v revive >/dev/null 2>&1 || { \
		echo "Installing revive..."; \
		go install github.com/mgechev/revive@v1.12.0; \
	}
	# renovate: datasource=go depName=github.com/mgechev/revive
	@command -v checkmake >/dev/null 2>&1 || { \
		echo "Installing checkmake..."; \
		go install github.com/checkmake/checkmake/cmd/checkmake@0.2.2; \
	}
	# renovate: datasource=go depName=github.com/checkmake/checkmake/cmd/checkmake
	@command -v golines >/dev/null 2>&1 || { \
		echo "Installing golines..."; \
		go install github.com/segmentio/golines@v0.13.0; \
	}
	# renovate: datasource=go depName=github.com/segmentio/golines

check-deps: ## Check if all development dependencies are installed
	@echo "Checking development dependencies..."
	@command -v go >/dev/null 2>&1 || { \
		echo "go is not installed"; exit 1; }
	@command -v goreleaser >/dev/null 2>&1 || {
		echo "goreleaser is not installed (run: make dev-deps)"; exit 1; }
	@command -v golangci-lint >/dev/null 2>&1 || {
		echo "golangci-lint is not installed (run: make dev-deps)"; exit 1; }
	@command -v markdownlint-cli2 >/dev/null 2>&1 || {
		echo "markdownlint-cli2 is not installed (run: make dev-deps)"; exit 1; }
	@command -v markdown-link-check >/dev/null 2>&1 || {
		echo "markdown-link-check is not installed (run: make dev-deps)"; exit 1; }
	@command -v goimports >/dev/null 2>&1 || {
		echo "goimports is not installed (run: make dev-deps)"; exit 1; }
	@command -v editorconfig-checker >/dev/null 2>&1 || {
		echo "editorconfig-checker is not installed (run: make dev-deps)"; exit 1; }
	@command -v gosec >/dev/null 2>&1 || {
		echo "gosec is not installed (run: make dev-deps)"; exit 1; }
	@command -v staticcheck >/dev/null 2>&1 || {
		echo "staticcheck is not installed (run: make dev-deps)"; exit 1; }
	@command -v revive >/dev/null 2>&1 || {
		echo "revive is not installed (run: make dev-deps)"; exit 1; }
	@command -v checkmake >/dev/null 2>&1 || {
		echo "checkmake is not installed (run: make dev-deps)"; exit 1; }
	@command -v yamlfmt >/dev/null 2>&1 || {
		echo "yamlfmt is not installed (run: make dev-deps)"; exit 1; }
	@command -v actionlint >/dev/null 2>&1 || {
		echo "actionlint is not installed (run: make dev-deps)"; exit 1; }
	@command -v golines >/dev/null 2>&1 || {
		echo "golines is not installed (run: make dev-deps)"; exit 1; }
	@echo "All dependencies are installed ✓"

# Testing targets
test: ## Run all tests
	go test ./...

test-verbose: ## Run tests with verbose output
	go test -v ./...

test-coverage: ## Run tests with coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report saved to coverage.html"

update-deps: ## Update all Go dependencies to latest versions
	@echo "Updating Go dependencies..."
	go get -u=patch ./...
	go mod tidy
	go mod verify
	@echo "Dependencies updated ✓"
	@echo "Updated dependencies:"
	@go list -u -m all | grep '\[' || true

# Code quality targets
fmt: ## Format Go code
	gofmt -w .
	@echo "Go code formatted ✓"

lint: ## Run all linters using pre-commit (preferred method)
	@echo "Running pre-commit linters..."
	@pre-commit run --all-files
	@echo "All linting completed ✓"

lint-go: ## Run only Go linters
	go vet ./...
	golangci-lint run --timeout=5m

lint-md: ## Run only Markdown linter
	markdownlint-cli2 *.md **/*.md

lint-yaml: ## Run only YAML linter
	yamlfmt -lint .

lint-actions: ## Run only GitHub Actions linter
	actionlint .github/workflows/*.yml

lint-make: ## Run only Makefile linter
	checkmake Makefile

# CI targets
ci: fmt lint test ## Run all CI checks (format, lint, test)

ci-coverage: fmt lint test-coverage ## Run CI checks with coverage

# Security targets
security: ## Run security checks
	gosec ./...

# Cleanup targets
clean: ## Clean build artifacts
	rm -f f2b
	rm -f coverage.out
	rm -f coverage.html
	go clean

# Development targets
dev-setup: dev-deps ## Set up development environment
	@echo "Setting up development environment..."
	@echo "Installing pre-commit hooks..."
	@command -v pre-commit >/dev/null 2>&1 || { \
		echo "Installing pre-commit..."; \
		pip install pre-commit; \
	}
	@pre-commit install
	@echo "Development environment setup complete ✓"

pre-commit-setup: ## Install and configure pre-commit hooks
	@echo "Installing pre-commit..."
	@command -v pre-commit >/dev/null 2>&1 || { \
		echo "Installing pre-commit..."; \
		pip install pre-commit; \
	}
	@pre-commit install
	@echo "Pre-commit hooks installed ✓"

# Release targets
release-dry-run: ## Test release process without creating artifacts
	@echo "Testing release process..."
	@VERSION=$$(git describe --tags --exact-match 2>/dev/null || echo "v0.0.0-dev"); \
	echo "Building version: $$VERSION"; \
	go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=$$VERSION" -o f2b-test .
	@rm -f f2b-test
	@echo "Release dry-run complete ✓"

release: ## Create a new release using GoReleaser
	@echo "Creating release with GoReleaser..."
	@$(MAKE) _check-tag
	@goreleaser release --clean

_check-tag: ## Internal: Check if a git tag exists
	@if [ -z "$$(git describe --exact-match 2>/dev/null)" ]; then \
		echo "Error: No tag found. Please create a tag first (e.g., git tag v1.0.0)"; \
		exit 1; \
	fi

release-snapshot: ## Create a snapshot release (no tag required)
	@echo "Creating snapshot release with GoReleaser..."
	goreleaser release --snapshot --clean

release-check: ## Check if GoReleaser configuration is valid
	@echo "Checking GoReleaser configuration..."
	goreleaser check
	@echo "GoReleaser configuration is valid ✓"
