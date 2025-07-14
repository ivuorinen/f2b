# f2b Makefile

.PHONY: help build test lint fmt clean install dev-deps check-deps

# Default target
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Build targets
build: ## Build the f2b binary
	go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=dev" -o f2b .

install: ## Install f2b globally
	go install github.com/ivuorinen/f2b@latest

# Development dependencies
dev-deps: ## Install development dependencies
	@echo "Installing development dependencies..."
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "Installing golangci-lint..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin v1.55.2; \
	}
	@command -v markdownlint >/dev/null 2>&1 || { \
		echo "Installing markdownlint..."; \
		npm install -g markdownlint-cli; \
	}
	@command -v yamllint >/dev/null 2>&1 || { \
		echo "Installing yamllint..."; \
		pip install yamllint; \
	}
	@command -v actionlint >/dev/null 2>&1 || { \
		echo "Installing actionlint..."; \
		go install github.com/rhymond/actionlint/cmd/actionlint@latest; \
	}

check-deps: ## Check if all development dependencies are installed
	@echo "Checking development dependencies..."
	@command -v go >/dev/null 2>&1 || { echo "go is not installed"; exit 1; }
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint is not installed (run: make dev-deps)"; exit 1; }
	@command -v markdownlint >/dev/null 2>&1 || { echo "markdownlint is not installed (run: make dev-deps)"; exit 1; }
	@command -v yamllint >/dev/null 2>&1 || { echo "yamllint is not installed (run: make dev-deps)"; exit 1; }
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

lint: check-deps ## Run all linters (non-strict, shows issues but doesn't fail)
	@echo "Running Go linters..."
	@go vet ./...
	@golangci-lint run --timeout=5m
	@echo "Go linting ✓"
	@echo ""
	@echo "Running Markdown linter..."
	@markdownlint *.md || true
	@echo "Markdown linting ✓"
	@echo ""
	@echo "Running YAML linter..."
	@yamllint .github/workflows/ || true
	@echo "YAML linting ✓"
	@echo ""
	@echo "Running GitHub Actions linter..."
	@actionlint .github/workflows/*.yml || true
	@echo "GitHub Actions linting ✓"

lint-strict: check-deps ## Run all linters with strict mode (fails on any issues)
	@echo "Running Go linters (strict)..."
	@go vet ./...
	@golangci-lint run --timeout=5m
	@echo "Go linting ✓"
	@echo ""
	@echo "Running Markdown linter (strict)..."
	@markdownlint *.md
	@echo "Markdown linting ✓"
	@echo ""
	@echo "Running YAML linter (strict)..."
	@yamllint .github/workflows/
	@echo "YAML linting ✓"
	@echo ""
	@echo "Running GitHub Actions linter (strict)..."
	@actionlint .github/workflows/*.yml
	@echo "GitHub Actions linting ✓"

lint-fix: ## Run linters with auto-fix where possible
	@echo "Auto-fixing Go code..."
	@gofmt -w .
	@golangci-lint run --fix --timeout=5m
	@echo "Go fixes applied ✓"
	@echo ""
	@echo "Auto-fixing Markdown..."
	@markdownlint --fix *.md || true
	@echo "Markdown fixes applied ✓"

lint-go: ## Run only Go linters
	go vet ./...
	golangci-lint run --timeout=5m

lint-md: ## Run only Markdown linter
	markdownlint *.md

lint-yaml: ## Run only YAML linter
	yamllint .github/workflows/

lint-actions: ## Run only GitHub Actions linter
	actionlint .github/workflows/*.yml

# CI targets
ci: fmt lint test ## Run all CI checks (format, lint, test)

ci-coverage: fmt lint test-coverage ## Run CI checks with coverage

# Security targets
security: ## Run security checks
	@command -v gosec >/dev/null 2>&1 || { \
		echo "Installing gosec..."; \
		go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
	}
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
	@echo '#!/bin/sh' > .git/hooks/pre-commit
	@echo 'make lint' >> .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Development environment setup complete ✓"

# Release targets
release-dry-run: ## Test release process without creating artifacts
	@echo "Testing release process..."
	@VERSION=$$(git describe --tags --exact-match 2>/dev/null || echo "v0.0.0-dev"); \
	echo "Building version: $$VERSION"; \
	go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=$$VERSION" -o f2b-test .
	@rm -f f2b-test
	@echo "Release dry-run complete ✓"