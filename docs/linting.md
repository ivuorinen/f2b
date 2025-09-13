# Linting and Code Quality

This document describes the linting and code quality tools used in the f2b project.

## Overview

The project uses a unified pre-commit approach for linting and code quality, ensuring consistency across development,
CI, and pre-commit hooks.

### Supported Tools

- **Go**: `gofmt`, `go-build-mod`, `go-mod-tidy`, `golangci-lint`
- **Markdown**: `markdownlint`
- **YAML**: `yamlfmt` (Google's YAML formatter)
- **GitHub Actions**: `actionlint`
- **EditorConfig**: `editorconfig-checker`
- **Makefile**: `checkmake`

## Quick Start

### Install Development Dependencies

```bash
make dev-deps
```

### Set Up Pre-commit (Recommended)

```bash
make pre-commit-setup
# or manually:
pip install pre-commit
pre-commit install
```

### Run All Linters

**Preferred Method (Unified Tooling):**

```bash
# Run all linting and formatting checks
make lint

# Run all linters with strict mode
make lint-strict

# Run linters with auto-fix
make lint-fix
```

**Individual Pre-commit Hooks:**

```bash
# Run specific hook
pre-commit run yamlfmt --all-files
pre-commit run golangci-lint --all-files
pre-commit run markdownlint --all-files
pre-commit run checkmake --all-files
```

**Individual Tool Commands:**

```bash
make lint-go           # Go only
make lint-yaml         # YAML only
make lint-actions      # GitHub Actions only
make lint-make         # Makefile only
```

## Configuration Files

**Read these files BEFORE making changes:**

- **`.editorconfig`**: Indentation, final newlines, encoding
- **`.golangci.yml`**: Go linting rules and timeout settings
- **`.markdownlint.json`**: Markdown formatting rules (120 char limit)
- **`.yamlfmt.yaml`**: YAML formatting rules
- **`.pre-commit-config.yaml`**: Pre-commit hook configuration

## Linting Tools

### Go Linting

#### gofmt (via pre-commit-golang)

- **Purpose**: Code formatting
- **Configuration**: Uses Go standard formatting
- **Hook**: `go-fmt`

#### go-build-mod (via pre-commit-golang)

- **Purpose**: Verify code builds
- **Configuration**: Uses go.mod
- **Hook**: `go-build-mod`

#### go-mod-tidy (via pre-commit-golang)

- **Purpose**: Clean up go.mod and go.sum
- **Configuration**: Automatic
- **Hook**: `go-mod-tidy`

#### golangci-lint (local hook)

- **Purpose**: Comprehensive Go linting with multiple analyzers
- **Configuration**: `.golangci.yml`
- **Features**: 50+ linters, fast caching, detailed reporting
- **Hook**: `golangci-lint`

### Markdown Linting

#### markdownlint (local hook)

- **Purpose**: Markdown formatting and style consistency
- **Configuration**: `.markdownlint.json`
- **Key rules**:
  - Line length limit: 120 characters
  - Disabled: HTML tags, bare URLs, first-line heading requirement
- **Hook**: `markdownlint`

### YAML Linting

#### yamlfmt (official Google repo)

- **Purpose**: YAML formatting and linting
- **Configuration**: `.yamlfmt.yaml`
- **Key features**:
  - Document start markers (`---`)
  - Line length limit: 120 characters
  - Respects .gitignore
  - Retains single line breaks
  - EOF newlines
- **Hook**: `yamlfmt`

### GitHub Actions Linting

#### actionlint (local hook)

- **Purpose**: GitHub Actions workflow validation
- **Configuration**: Default configuration
- **Features**:
  - Syntax validation
  - shellcheck integration
  - Action version checking
  - Expression validation
- **Hook**: `actionlint`

### EditorConfig

#### editorconfig-checker (local hook)

- **Purpose**: Verify EditorConfig compliance
- **Configuration**: `.editorconfig`
- **Features**: Checks indentation, final newlines, encoding
- **Hook**: `editorconfig-checker`

### Makefile Linting

#### checkmake (official repo)

- **Purpose**: Makefile syntax and best practices validation
- **Configuration**: Default rules (no config file needed)
- **Features**:
  - Checks for missing `.PHONY` declarations
  - Validates target dependencies
  - Enforces Makefile best practices
  - Detects syntax errors and common mistakes
- **Hook**: `checkmake`
- **Manual Usage**: `checkmake Makefile`

## Pre-commit Integration

The project uses `.pre-commit-config.yaml` for unified tooling:

### Hook Sources

- **pre-commit/pre-commit-hooks**: Basic file checks
- **tekwizely/pre-commit-golang**: Go-specific hooks
- **google/yamlfmt**: Official YAML formatter
- **mrtazz/checkmake**: Official Makefile linter
- **local**: Custom hooks for project-specific tools

### Automatic Setup

```bash
# Install pre-commit and hooks
make pre-commit-setup

# Hooks will run automatically on commit
git commit -m "your changes"
```

### Manual Execution

```bash
# Run all hooks
pre-commit run --all-files

# Run specific hook
pre-commit run yamlfmt
pre-commit run golangci-lint
pre-commit run checkmake

# Update hook versions
pre-commit autoupdate
```

## CI Integration

### GitHub Actions

Both workflows now use unified pre-commit:

- **`.github/workflows/lint.yml`**: Main linting workflow
- **`.github/workflows/pr-lint.yml`**: Pull request linting

### Workflow Features

- Single `pre-commit/action@v3.0.1` step
- Automatic tool installation and caching
- Consistent behavior with local development
- Python and Go environment setup

## Development Workflow

### Before Committing

1. **Read configuration files first**: `.editorconfig`, `.golangci.yml`,
  `.markdownlint.json`, `.yamlfmt.yaml`, `.pre-commit-config.yaml`
2. **Apply configuration rules** during development
3. **Run pre-commit checks**: `pre-commit run --all-files`
4. **Fix all issues** across the project
5. **Run tests**: `go test ./...`

### Recommended IDE Setup

- **Go**: Use `gopls` language server with auto-format on save
- **Markdown**: Install markdownlint extension
- **YAML**: Install YAML extension with yamlfmt support
- **EditorConfig**: Install EditorConfig plugin

## Configuration Details

### `.yamlfmt.yaml`

```yaml
---
# yaml-language-server: $schema=https://raw.githubusercontent.com/google/yamlfmt/main/schema.json
formatter:
  type: basic
  include_document_start: true
  gitignore_excludes: true
  retain_line_breaks_single: true
  eof_newline: true
  max_line_length: 120
  indent: 2
```

### `.markdownlint.json`

```json
{
  "default": true,
  "MD013": {
    "line_length": 120,
    "headings": false,
    "tables": false,
    "code_blocks": false
  },
  "MD033": false,
  "MD041": false,
  "MD034": false
}
```

### `.golangci.yml`

Comprehensive Go linting configuration with timeout settings and enabled/disabled linters.

## Schema Support

All YAML files include schema references for better IDE support:

- **GitHub workflows**: `$schema=https://json.schemastore.org/github-workflow.json`
- **Pre-commit config**: `$schema=https://json.schemastore.org/pre-commit-config.json`
- **GitHub labels**: `$schema=https://json.schemastore.org/github-labels.json`

## Troubleshooting

### Common Issues

#### Pre-commit hook failures

**Solution**: Run `pre-commit run --all-files` locally to identify issues

#### "command not found" errors

**Solution**: Run `make dev-deps` and `make pre-commit-setup`

#### YAML formatting differences

**Solution**: Use `yamlfmt .` to format files consistently

### Debugging Tips

1. **Run individual hooks** to isolate issues
2. **Use `--verbose` flag** with pre-commit
3. **Check configuration files** for rule customizations
4. **Verify tool versions** match CI environment

## Adding New Linting Rules

### Process

1. Update configuration files (`.markdownlint.json`, `.yamlfmt.yaml`, etc.)
2. Test changes locally: `pre-commit run --all-files`
3. Update `.pre-commit-config.yaml` if adding new hooks
4. Document changes in this file
5. Consider backward compatibility

### Best Practices

- Start with warnings before making rules errors
- Use pre-commit for consistency across environments
- Test with existing codebase before enforcing
- Leverage auto-fix capabilities when available

## Security Considerations

### Tool Installation

- All tools installed from official repositories
- Versions pinned in `.pre-commit-config.yaml`
- Dependencies verified before execution

### Code Analysis

- Linters help identify potential security issues
- Static analysis catches common vulnerabilities
- Configuration validation prevents misconfigurations

## Performance

### Optimization Tips

- Pre-commit caches tool installations
- Hooks run in parallel when possible
- Use `golangci-lint` cache for faster Go linting
- Skip unchanged files automatically

### Benefits of Pre-commit

- **Consistency**: Same tools in dev, CI, and pre-commit
- **Speed**: Cached tool installations
- **Reliability**: No version mismatches
- **Maintenance**: Centralized configuration
