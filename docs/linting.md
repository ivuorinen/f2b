# Linting and Code Quality

This document describes the linting and code quality tools used in the f2b project.

## Overview

The project uses a unified [prek](https://github.com/j178/prek) approach for linting and code quality, ensuring
consistency across development, CI, and git hooks. prek is a fast Rust reimplementation of pre-commit; it reads the
same `.pre-commit-config.yaml`. The hooks pin no versions: the file checks are prek built-ins, and every other hook
runs its tool from `mise.toml` through `mise exec` or `mise run`.

### Supported Tools

- **Go**: `golangci-lint` (local hook)
- **Markdown**: `markdownlint-cli2`, `mdformat`, `markdown-link-check`
- **YAML**: `yamlfmt` (Google's YAML formatter)
- **Shell**: `shfmt`
- **GitHub Actions**: `actionlint`, `check-github-workflows`
- **EditorConfig**: `editorconfig-checker`
- **Infrastructure/security**: `checkov`
- **Hook hygiene**: prek's built-in `pre-commit-hooks` file checks

## Quick Start

### Install Development Dependencies

[mise](https://mise.jdx.dev/) installs the tools pinned in `mise.toml` (prek,
golangci-lint and the other Go tools); Go itself comes from `go.mod`.

```bash
mise install
mise run setup   # installs the pre-commit and commit-msg hooks
```

### Run All Linters

```bash
# Run every hook: linting and formatting checks
mise run hooks

# Run only the Go checks (gofmt, go vet, golangci-lint)
mise run lint
```

**Individual Hooks:**

```bash
prek run yamlfmt --all-files
prek run golangci-lint --all-files
prek run markdownlint-cli2 --all-files
prek run actionlint --all-files
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
- **Hook**: `golangci-lint` (runs `mise run lint`)

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

## prek Integration

The project uses `.pre-commit-config.yaml` for unified tooling:

### Hook Sources

- **`repo: builtin`**: prek's own implementations of the pre-commit-hooks file checks
  (whitespace, end of file, line endings, YAML/JSON syntax, large files, merge
  conflicts, shebang permissions), versioned with prek
- **`repo: local`**: `golangci-lint` (runs `mise run lint`), the commit-message and
  test-shape pygrep checks, and yamlfmt, markdownlint-cli2, mdformat,
  markdown-link-check, actionlint, shfmt, checkov, check-jsonschema and
  editorconfig-checker, each run with `mise exec --`

### Automatic Setup

```bash
# Install prek's git hooks (prek itself comes from `mise install`)
mise run setup

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

# Update the tools the hooks run (versions live in mise.toml)
mise run update
```

## CI Integration

### GitHub Actions

CI installs a pinned mise with `jdx/mise-action` and runs the same tasks as a
local checkout, so every tool runs at its `mise.toml` version:

- **`.github/workflows/lint.yml`**: `mise run lint` and `mise run test-race` on `main`
- **`.github/workflows/pr-lint.yml`**: `mise run lint`, `mise run docs-api`,
  `mise run test-cov` and `mise run hooks` on pull requests

### Workflow Features

- No per-tool Actions or version inputs: `mise.toml` is the only tool pin
- mise-action caches the tool installs (except in the release workflow)
- Same `.golangci.yml` configuration as local `mise run lint`

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

Workflow, pre-commit and tool configuration YAML files include schema references
for IDE support:

- **GitHub workflows**: `$schema=https://json.schemastore.org/github-workflow.json`
- **Pre-commit config**: `$schema=https://json.schemastore.org/pre-commit-config.json`
- **GoReleaser config**: `$schema=https://goreleaser.com/static/schema.json`

## Troubleshooting

### Common Issues

#### prek hook failures

**Solution**: Run `prek run --all-files` locally to identify issues

#### "command not found" errors

**Solution**: Run `mise install`, then `mise run setup`

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

- All tools installed by mise from their official releases or package registries
- Versions pinned only in `mise.toml`; Renovate bumps them

### Code Analysis

- Linters help identify potential security issues
- Static analysis catches common vulnerabilities
- Configuration validation prevents misconfigurations

## Performance

### Optimization Tips

- mise installs each tool once and reuses it
- Hooks run in parallel when possible
- Use `golangci-lint` cache for faster Go linting
- Skip unchanged files automatically

### Benefits of prek

- **Consistency**: Same tools in dev, CI, and git hooks
- **Speed**: Tools installed once by mise
- **Reliability**: No version mismatches: one pin per tool, in `mise.toml`
- **Maintenance**: Centralized configuration
