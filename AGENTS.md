# AGENTS Guidelines

## Purpose

Instructions for AI agents and human contributors to maintain consistent, secure, and reviewable code changes.

## Project Context

- **f2b**: Modern, secure Go CLI for managing Fail2Ban jails and bans
- **Stack**: Go >=1.20, Cobra CLI, logrus logging, dependency injection
- **Principles**: Security-first, testability, maintainability, privilege safety

For detailed project architecture and design patterns, see [docs/architecture.md](docs/architecture.md).

## Commit Rules

- **Read configs FIRST**: Study `.editorconfig`, `.golangci.yml`, `.markdownlint.json`,
  `.yamlfmt.yaml`, `.pre-commit-config.yaml`
- **Semantic Commits**: `type(scope): message` (e.g., `feat(cli): add ban command`)
- **Preferred Workflow**: Use `pre-commit run --all-files` for unified linting and formatting
- **Pre-commit Setup**: Run `pre-commit install` for automatic hooks on commit
- **Tests**: Run `go test ./...` after linting for code changes
- **Alternative**: Individual tools available but pre-commit is preferred for consistency

## Security Rules

- **NEVER** execute real sudo commands in tests - always use MockRunner
- **ALWAYS** validate input before privilege escalation
- **ALWAYS** use argument arrays, never shell string concatenation
- **ALWAYS** test both privileged and unprivileged scenarios
- Validate IPs, jail names, and filter names to prevent injection
- Use `MockSudoChecker` and `MockRunner` in tests
- Handle privilege errors gracefully with helpful messages

For comprehensive security guidelines and threat model, see [docs/security.md](docs/security.md).

## Configuration Files

**Read these files BEFORE making ANY changes to ensure proper code style:**

- **`.editorconfig`**: Indentation (tabs for Go, 2 spaces for others), final newlines, encoding
- **`.golangci.yml`**: Go linting rules, enabled/disabled checks, timeout settings
- **`.markdownlint.json`**: Markdown formatting rules, line length (120 chars), disabled rules
- **`.yamlfmt.yaml`**: YAML formatting rules for all YAML files
- **`.pre-commit-config.yaml`**: Pre-commit hook configuration

For detailed information about all linting tools and configuration, see [docs/linting.md](docs/linting.md).

## Code Standards

- Generate idiomatic, readable Go code following project structure
- Use dependency injection and interfaces for testability
- Prefer explicit error handling with logrus logging
- Use `PrintOutput` and `PrintError` helpers for CLI output
- Support both `plain` and `json` output formats
- Handle sudo privileges using established patterns
- **Follow .editorconfig rules**: Use tabs for Go, 2 spaces for other files, add final newlines

## Testing Requirements

- Use `F2B_TEST_SUDO=true` when testing sudo validation
- Mock all system interactions with dependency injection
- Test privilege scenarios: privileged, unprivileged, and edge cases
- Co-locate tests with source files (`*_test.go`)
- Use `integration_test.go` naming for integration tests

For detailed testing patterns, mock usage, and examples, see [docs/testing.md](docs/testing.md).

## Development Workflow

1. **Read configuration files first**:
    - `.editorconfig`,
    - `.golangci.yml`,
    - `.markdownlint.json`,
    - `.yamlfmt.yaml`,
    - `.pre-commit-config.yaml`

2. **Study existing code patterns** and project structure before making changes
3. **Apply configuration rules** during development to avoid style violations
4. **Implement changes** following security and testing requirements
5. **Run pre-commit checks**: `pre-commit run --all-files` to catch all issues
6. **Fix all issues** across the project, not just modified files
7. **Keep PRs focused** with clear descriptions

## AI-Specific Guidelines

- Prioritize user intent and project maintainability
- Avoid large, sweeping changes unless explicitly requested
- Ask for clarification when in doubt
- Include appropriate test coverage for security-sensitive changes
- Respect project's Code of Conduct and community standards

## Common Pitfalls

1. **Testing Sudo Operations**: Always use mocks, never real sudo
2. **Input Validation**: Validate all user input to prevent injection
3. **Path Traversal**: Filter names are validated to prevent directory traversal
4. **Privilege Checking**: Use SudoChecker interface, don't check directly
5. **Command Execution**: Use RunnerCombinedOutputWithSudo for sudo commands

## Environment Variables

- `F2B_LOG_DIR`: Fail2Ban log directory (default: `/var/log`)
- `F2B_FILTER_DIR`: Fail2Ban filter directory (default: `/etc/fail2ban/filter.d`)
- `F2B_LOG_LEVEL`: Application log level (debug, info, warn, error)
- `F2B_TEST_SUDO`: Enable sudo checking in tests (set to "true")

## Contact

For questions about AI-generated contributions:

- [@ivuorinen](https://github.com/ivuorinen)
- ismo@ivuorinen.net
