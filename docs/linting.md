# Linting and Code Quality

This document describes the linting and code quality tools used in the f2b project.

## Overview

The project uses multiple linting tools to ensure code quality, consistency, and security:

- **Go**: `gofmt`, `go vet`, `golangci-lint`
- **Markdown**: `markdownlint`
- **YAML**: `yamllint`
- **GitHub Actions**: `actionlint`

## Quick Start

### Install Development Dependencies

```bash
make dev-deps
```

### Run All Linters

```bash
# Non-strict mode (shows issues but doesn't fail)
make lint

# Strict mode (fails on any issues)
make lint-strict

# Auto-fix issues where possible
make lint-fix
```

### Run Individual Linters

```bash
make lint-go        # Go only
make lint-md        # Markdown only
make lint-yaml      # YAML only
make lint-actions   # GitHub Actions only
```

## Linting Tools

### Go Linting

#### gofmt
- **Purpose**: Code formatting
- **Configuration**: Uses Go standard formatting
- **Usage**: `gofmt -w .`

#### go vet
- **Purpose**: Static analysis for common Go issues
- **Configuration**: Uses Go standard checks
- **Usage**: `go vet ./...`

#### golangci-lint
- **Purpose**: Comprehensive Go linting with multiple analyzers
- **Configuration**: Default configuration
- **Usage**: `golangci-lint run --timeout=5m`

### Markdown Linting

#### markdownlint
- **Purpose**: Markdown formatting and style consistency
- **Configuration**: `.markdownlint.json`
- **Key rules**:
  - Line length limit: 120 characters
  - Disabled: HTML tags, bare URLs, first-line heading requirement
- **Usage**: `markdownlint *.md`

### YAML Linting

#### yamllint
- **Purpose**: YAML syntax and style checking
- **Configuration**: `.yamllint.yml`
- **Key rules**:
  - Line length limit: 120 characters
  - Minimum spaces from content: 1
  - Allows 'true'/'false'/'on'/'off' as truthy values
  - Document start disabled
- **Usage**: `yamllint .github/workflows/`

### GitHub Actions Linting

#### actionlint
- **Purpose**: GitHub Actions workflow validation
- **Configuration**: Default configuration
- **Features**:
  - Syntax validation
  - shellcheck integration
  - Action version checking
  - Expression validation
- **Usage**: `actionlint .github/workflows/*.yml`

## Configuration Files

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

### `.yamllint.yml`
```yaml
extends: default

rules:
  line-length:
    max: 120
  comments:
    min-spaces-from-content: 1
  truthy:
    allowed-values: ['true', 'false', 'on', 'off']
  document-start: disable
```

## Pre-commit Hooks

The project includes pre-commit configuration in `.pre-commit-config.yaml`:

### Install pre-commit
```bash
pip install pre-commit
pre-commit install
```

### Manual pre-commit run
```bash
pre-commit run --all-files
```

## CI Integration

### GitHub Actions

The project includes automated linting in CI:

- **`.github/workflows/lint.yml`**: Dedicated linting workflow
- **`.github/workflows/pr-lint.yml`**: Pull request linting (includes additional checks)

### Workflow Features
- Runs on pull requests and main branch pushes
- Parallel execution of different linters
- Comprehensive dependency installation
- Structured output for easy debugging

## Development Workflow

### Before Committing
1. Format code: `make fmt`
2. Run linters: `make lint`
3. Fix any issues: `make lint-fix`
4. Run tests: `make test`

### Recommended IDE Setup
- **Go**: Use `gopls` language server with auto-format on save
- **Markdown**: Install markdownlint extension
- **YAML**: Install YAML extension with yamllint support

## Troubleshooting

### Common Issues

#### "command not found" errors
**Solution**: Run `make dev-deps` to install missing tools

#### Long lines in generated files
**Solution**: Add files to linter ignore patterns or use `|| true` for non-critical issues

#### YAML workflow syntax errors
**Solution**: Use `yamllint` and `actionlint` to validate before committing

### Debugging Tips

1. **Run individual linters** to isolate issues
2. **Use verbose flags** when available (`-v`, `--verbose`)
3. **Check configuration files** for rule customizations
4. **Verify tool versions** if behavior differs from CI

## Adding New Linting Rules

### Process
1. Update configuration files (`.markdownlint.json`, `.yamllint.yml`, etc.)
2. Test changes locally: `make lint-strict`
3. Update CI workflows if needed
4. Document changes in this file
5. Consider backward compatibility

### Best Practices
- Start with warnings before making rules errors
- Provide clear documentation for new rules
- Test with existing codebase before enforcing
- Consider auto-fix capabilities when available

## Security Considerations

### Tool Installation
- All tools are installed from official sources
- Versions are pinned in CI workflows
- Dependencies are verified before execution

### Code Analysis
- Linters help identify potential security issues
- Static analysis catches common vulnerabilities
- Configuration validation prevents misconfigurations

## Performance

### Optimization Tips
- Use `golangci-lint` cache: `--cache-dir`
- Run linters in parallel when possible
- Skip linting for unchanged files in CI
- Use incremental linting tools when available