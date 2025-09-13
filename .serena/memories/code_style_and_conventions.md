# f2b Code Style and Conventions

## EditorConfig Rules (.editorconfig)

- **General**: 2 spaces indentation, max line length 120 characters
- **Go files**: Tab indentation with width 2
- **Makefiles**: Tab indentation
- **All files**: Insert final newline, trim trailing whitespace

## Go Linting (golangci-lint)

**Key enabled linters:**

- Core: errcheck, govet, ineffassign, staticcheck, unused
- Security: gosec (security analysis)
- Quality: revive, gocyclo, misspell, unconvert, prealloc
- Context: contextcheck, containedctx, durationcheck
- Error handling: errorlint, errname, nilnil

**Key settings:**

- Cyclomatic complexity limit: 20
- Line length: 120 characters
- US English spelling
- Local import prefixes for project packages

## Import Organization

1. Standard library imports
2. Third-party imports
3. Local project imports (with github.com/ivuorinen/f2b prefix)

## Documentation Standards

- **Markdown**: markdownlint with .markdownlint.json config
- **Link checking**: All external links validated via markdown-link-check
- **Code comments**: Required for exported functions and types

## Configuration Files to Read First

- `.editorconfig`: Indentation and formatting rules
- `.golangci.yml`: Go linting configuration
- `.markdownlint.json`: Markdown rules
- `.yamlfmt.yaml`: YAML formatting
- `.pre-commit-config.yaml`: Pre-commit hooks
