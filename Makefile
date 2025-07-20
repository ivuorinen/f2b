# f2b Makefile

.PHONY: help all build test lint fmt clean install dev-deps check-deps test-verbose test-coverage lint-legacy lint-strict lint-fix lint-go lint-md lint-yaml lint-actions lint-make ci ci-coverage security dev-setup pre-commit-setup release-dry-run release release-snapshot release-check _check-tag

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
	@command -v goreleaser >/dev/null 2>&1 || { \
		echo "Installing goreleaser..."; \
		go install github.com/goreleaser/goreleaser/v2@latest; \
	}
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "Installing golangci-lint..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v1.55.2; \
	}
	@command -v markdownlint-cli2 >/dev/null 2>&1 || { \
		echo "Installing markdownlint-cli2..."; \
		npm install -g markdownlint-cli2; \
	}
	@command -v yamlfmt >/dev/null 2>&1 || { \
		echo "Installing yamlfmt..."; \
		go install github.com/google/yamlfmt/cmd/yamlfmt@latest; \
	}
	@command -v actionlint >/dev/null 2>&1 || { \
		echo "Installing actionlint..."; \
		go install github.com/rhysd/actionlint/cmd/actionlint@latest; \
	}
	@command -v goimports >/dev/null 2>&1 || { \
		echo "Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	}
	@command -v editorconfig-checker >/dev/null 2>&1 || { \
		echo "Installing editorconfig-checker..."; \
		go install github.com/editorconfig-checker/editorconfig-checker/cmd/editorconfig-checker@latest; \
	}
	@command -v gosec >/dev/null 2>&1 || { \
		echo "Installing gosec..."; \
		go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
	}
	@command -v staticcheck >/dev/null 2>&1 || { \
		echo "Installing staticcheck..."; \
		go install honnef.co/go/tools/cmd/staticcheck@latest; \
	}
	@command -v revive >/dev/null 2>&1 || { \
		echo "Installing revive..."; \
		go install github.com/mgechev/revive@latest; \
	}
	@command -v checkmake >/dev/null 2>&1 || { \
		echo "Installing checkmake..."; \
		go install github.com/mrtazz/checkmake/cmd/checkmake@latest; \
	}

check-deps: ## Check if all development dependencies are installed
	@echo "Checking development dependencies..."
	@command -v go >/dev/null 2>&1 || { echo "go is not installed"; exit 1; }
	@command -v goreleaser >/dev/null 2>&1 || { echo "goreleaser is not installed (run: make dev-deps)"; exit 1; }
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint is not installed (run: make dev-deps)"; exit 1; }
	@command -v markdownlint-cli2 >/dev/null 2>&1 || { echo "markdownlint-cli2 is not installed (run: make dev-deps)"; exit 1; }
	@command -v goimports >/dev/null 2>&1 || { echo "goimports is not installed (run: make dev-deps)"; exit 1; }
	@command -v editorconfig-checker >/dev/null 2>&1 || { echo "editorconfig-checker is not installed (run: make dev-deps)"; exit 1; }
	@command -v gosec >/dev/null 2>&1 || { echo "gosec is not installed (run: make dev-deps)"; exit 1; }
	@command -v staticcheck >/dev/null 2>&1 || { echo "staticcheck is not installed (run: make dev-deps)"; exit 1; }
	@command -v revive >/dev/null 2>&1 || { echo "revive is not installed (run: make dev-deps)"; exit 1; }
	@command -v checkmake >/dev/null 2>&1 || { echo "checkmake is not installed (run: make dev-deps)"; exit 1; }
	@command -v yamlfmt >/dev/null 2>&1 || { echo "yamlfmt is not installed (run: make dev-deps)"; exit 1; }
	@command -v actionlint >/dev/null 2>&1 || { echo "actionlint is not installed (run: make dev-deps)"; exit 1; }
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

# Code quality targets
fmt: ## Format Go code
	gofmt -w .
	@echo "Go code formatted ✓"

lint: ## Run all linters using pre-commit (preferred method)
	@echo "Running pre-commit linters..."
	@pre-commit run --all-files
	@echo "All linting completed ✓"

lint-legacy: check-deps ## Run individual linters (legacy method)
	@echo "Running Go linters..."
	@go vet ./...
	@golangci-lint run --timeout=5m
	@echo "Go linting ✓"
	@echo ""
	@echo "Running Markdown linter..."
	@markdownlint-cli2 *.md || true
	@echo "Markdown linting ✓"
	@echo ""
	@echo "Running YAML linter..."
	@yamlfmt -lint . || true
	@echo "YAML linting ✓"
	@echo ""
	@echo "Running GitHub Actions linter..."
	@actionlint .github/workflows/*.yml || true
	@echo "GitHub Actions linting ✓"
	@echo ""
	@echo "Running Makefile linter..."
	@checkmake Makefile || true
	@echo "Makefile linting ✓"

lint-strict: ## Run all linters with strict mode using pre-commit
	@echo "Running pre-commit linters (strict)..."
	@pre-commit run --all-files
	@echo "All strict linting completed ✓"

lint-fix: ## Run linters with auto-fix using pre-commit
	@echo "Running pre-commit with auto-fix..."
	@pre-commit run --all-files
	@echo "All fixes applied ✓"

lint-go: ## Run only Go linters
	go vet ./...
	golangci-lint run --timeout=5m

lint-md: ## Run only Markdown linter
	markdownlint-cli2 *.md

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
