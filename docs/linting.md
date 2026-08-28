# Linting and Code Quality

This document describes the linting and code quality tools used in the f2b project.

## Overview

The project uses a unified [prek](https://github.com/j178/prek) approach for linting and code quality, ensuring
consistency across development, CI, and git hooks. prek is a fast Rust reimplementation of pre-commit; it reads the
same `.pre-commit-config.yaml` and manages its own hook environments, so no Python setup is required.

### Supported Tools

- **Go**: `golangci-lint` (local hook)
- **Markdown**: `markdownlint-cli2`, `mdformat`, `markdown-link-check`
- **YAML**: `yamlfmt` (Google's YAML formatter)
- **Shell**: `shfmt`
- **GitHub Actions**: `actionlint`, `check-github-workflows`
- **EditorConfig**: `editorconfig-checker`
- **Makefile**: `checkmake`
- **Infrastructure/security**: `checkov`
- **Hook hygiene**: `sync-pre-commit-deps`, standard `pre-commit-hooks` file checks

## Quick Start

### Install Development Dependencies

```bash
make dev-setup
```

### Set Up prek (Recommended)

```bash
make prek-setup
# or manually:
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/j178/prek/releases/latest/download/prek-installer.sh | sh
prek install
```

### Run All Linters

**Preferred Method (Unified Tooling):**

```bash
# Run all linting and formatting checks
make lint

# Run only the Go linters
make lint-go
```

**Individual Hooks:**

```bash
# Run specific hook
prek run yamlfmt --all-files
prek run golangci-lint --all-files
prek run markdownlint-cli2 --all-files
prek run checkmake --all-files
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
- **`.pre-commit-config.yaml`**: prek hook configuration

## Linting Tools

### Go Linting

#### golangci-lint (local hook)

- **Purpose**: Comprehensive Go linting with multiple analyzers
- **Configuration**: `.golangci.yml`
- **Features**: 50+ linters, fast caching, detailed reporting
- **Hook**: `golangci-lint`

### Markdown Linting

#### markdownlint-cli2 (DavidAnson/markdownlint-cli2)

- **Purpose**: Markdown formatting and style consistency
- **Configuration**: `.markdownlint.json`
- **Key rules**:
  - Line length limit: 120 characters
  - Disabled: HTML tags, bare URLs, first-line heading requirement
- **Hook**: `markdownlint-cli2`

#### mdformat (hukkin/mdformat)

- **Purpose**: Markdown auto-formatting (with GFM support)
- **Hook**: `mdformat`

#### markdown-link-check (tcort/markdown-link-check)

- **Purpose**: Detect broken links in Markdown files
- **Configuration**: `.markdown-link-check.json`
- **Hook**: `markdown-link-check`

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

#### actionlint (rhysd/actionlint)

- **Purpose**: GitHub Actions workflow validation
- **Configuration**: Default configuration
- **Features**:
  - Syntax validation
  - shellcheck integration
  - Action version checking
  - Expression validation
- **Hook**: `actionlint`

#### check-github-workflows (python-jsonschema/check-jsonschema)

- **Purpose**: Validate workflow files against the GitHub workflow JSON schema
- **Hook**: `check-github-workflows`

### Shell Formatting

#### shfmt (scop/pre-commit-shfmt)

- **Purpose**: Shell script formatting
- **Hook**: `shfmt`

### Security Scanning

#### checkov (bridgecrewio/checkov)

- **Purpose**: Static analysis of infrastructure and CI configuration
- **Hook**: `checkov`

### EditorConfig

#### editorconfig-checker (official repo)

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

## prek Integration

The project uses `.pre-commit-config.yaml` for unified tooling:

### Hook Sources

- **pre-commit/pre-commit-hooks**: Basic file checks
- **pre-commit/sync-pre-commit-deps**: Keeps hook dependency pins in sync
- **google/yamlfmt**: Official YAML formatter
- **DavidAnson/markdownlint-cli2**: Markdown linter
- **hukkin/mdformat**: Markdown formatter
- **tcort/markdown-link-check**: Markdown link checker
- **rhysd/actionlint**: GitHub Actions linter
- **scop/pre-commit-shfmt**: Shell formatter
- **checkmake/checkmake**: Official Makefile linter
- **bridgecrewio/checkov**: Infrastructure/CI security scanner
- **python-jsonschema/check-jsonschema**: Workflow schema validation
- **editorconfig-checker/editorconfig-checker**: EditorConfig compliance
- **local**: `golangci-lint` (run via `go run`)

### Automatic Setup

```bash
# Install prek and its git hooks
make prek-setup

# Hooks will run automatically on commit
git commit -m "your changes"
```

### Manual Execution

```bash
# Run all hooks
prek run --all-files

# Run specific hook
prek run yamlfmt
prek run golangci-lint
prek run checkmake

# Update hook versions
prek update
```

## CI Integration

### GitHub Actions

CI lints Go code directly with the golangci-lint action, and runs the hooks
via the official prek action (no Python setup needed):

- **`.github/workflows/lint.yml`**: Main linting workflow
- **`.github/workflows/pr-lint.yml`**: Pull request linting

### Workflow Features

- `golangci/golangci-lint-action@v9.3.0` step (pinned by commit SHA)
- Go environment setup and built-in caching
- Same `.golangci.yml` configuration as local `make lint-go`

## Development Workflow

### Before Committing

1. **Read configuration files first**: `.editorconfig`, `.golangci.yml`,
   `.markdownlint.json`, `.yamlfmt.yaml`, `.pre-commit-config.yaml`
1. **Apply configuration rules** during development
1. **Run prek checks**: `prek run --all-files`
1. **Fix all issues** across the project
1. **Run tests**: `go test ./...`

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
  "MD024": {
    "siblings_only": true
  },
  "MD033": false,
  "MD041": false,
  "MD034": false,
  "MD007": false,
  "MD029": false
}
```

See [.markdownlint.json](../.markdownlint.json) for the authoritative configuration.

### `.golangci.yml`

Comprehensive Go linting configuration with timeout settings and enabled/disabled linters.

## Schema Support

All YAML files include schema references for better IDE support:

- **GitHub workflows**: `$schema=https://json.schemastore.org/github-workflow.json`
- **Pre-commit config**: `$schema=https://json.schemastore.org/pre-commit-config.json`
- **GitHub labels**: `$schema=https://json.schemastore.org/github-labels.json`

## Troubleshooting

### Common Issues

#### prek hook failures

**Solution**: Run `prek run --all-files` locally to identify issues

#### "command not found" errors

**Solution**: Run `make dev-setup` (which runs `make prek-setup`)

#### YAML formatting differences

**Solution**: Use `yamlfmt .` to format files consistently

### Debugging Tips

1. **Run individual hooks** to isolate issues
1. **Use `--verbose` flag** with prek
1. **Check configuration files** for rule customizations
1. **Verify tool versions** match CI environment

## Adding New Linting Rules

### Process

1. Update configuration files (`.markdownlint.json`, `.yamlfmt.yaml`, etc.)
1. Test changes locally: `prek run --all-files`
1. Update `.pre-commit-config.yaml` if adding new hooks
1. Document changes in this file
1. Consider backward compatibility

### Best Practices

- Start with warnings before making rules errors
- Use prek for consistency across environments
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

- prek caches tool installations
- Hooks run in parallel when possible
- Use `golangci-lint` cache for faster Go linting
- Skip unchanged files automatically

### Benefits of prek

- **Consistency**: Same tools in dev, CI, and git hooks
- **Speed**: Cached tool installations
- **Reliability**: No version mismatches
- **Maintenance**: Centralized configuration
