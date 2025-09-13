# AGENTS Guidelines

## Purpose

Instructions for AI agents and human contributors to maintain consistent, secure, and reviewable code changes.

## Project Context

**f2b** is an **enterprise-grade** Go CLI for managing [Fail2Ban](https://www.fail2ban.org/) jails and bans with:

- **Comprehensive command set** for Fail2Ban management
- **Advanced security features** including extensive path traversal protections
- **Context-aware timeout support** with graceful cancellation
- **Real-time performance monitoring** and metrics collection
- **Multi-architecture Docker deployment** support
- **Sophisticated input validation** and privilege management
- **Modern fluent testing infrastructure** with significant code reduction

**Tech Stack:**

- **Language**: Go 1.25+ with modern idioms and patterns
- **CLI Framework**: Cobra with comprehensive command structure and shell completion
- **Logging**: Structured logging with Logrus and contextual information
- **Testing**: Advanced mock patterns with thread-safe implementations
- **Deployment**: Multi-architecture Docker support (amd64, arm64, armv7) with manifests

For detailed project architecture and design patterns, see [docs/architecture.md](docs/architecture.md).

## Tool Preferences

**When Serena tools are available, prioritize their usage:**

- Use Serena's symbolic tools for code reading and editing
- Leverage Serena's semantic search capabilities
- Prefer Serena's file operations over basic read/write tools
- Use Serena's memory system for project context

**Serena Integration:**

- Use `mcp__serena__find_symbol` for locating code elements
- Use `mcp__serena__get_symbols_overview` for understanding file structure
- Use `mcp__serena__replace_symbol_body` for precise code modifications
- Use `mcp__serena__search_for_pattern` for complex searches

**Memory Management:**

- **Always check existing memories first** before creating new ones
- Use `mcp__serena__list_memories` to see available memories
- **Prefer updating existing memories** over creating duplicates
- Consolidate related information into fewer, more precise files
- Keep memory content accurate and up-to-date

## Commands & Build System

```bash
# Build & Test (Go 1.25.0)
go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=1.2.3" -o f2b .
go test -covermode=atomic -coverprofile=coverage.out ./...
go install github.com/ivuorinen/f2b@latest

# Dependency Management (Added 2025-09-13)
make update-deps            # Update all Go dependencies to latest versions

# Lint & Format
pre-commit run --all-files  # Run all checks (includes link checking)
pre-commit install          # One-time setup

# Release (Multi-Architecture)
make release-check          # Check config
make release-snapshot       # Test (no tag)
git tag -a v1.2.3 -m "Release v1.2.3" && git push origin v1.2.3
make release               # Full release with multi-arch Docker

# Docker Multi-Architecture
# Releases automatically build:
# - ghcr.io/ivuorinen/f2b:latest (manifest)
# - ghcr.io/ivuorinen/f2b:latest-amd64
# - ghcr.io/ivuorinen/f2b:latest-arm64
# - ghcr.io/ivuorinen/f2b:latest-armv7
```

## Project Architecture

**Core Structure:**

- **main.go**: Entry point with secure sudo detection and client initialization
- **cmd/**: Cobra CLI commands with modern fluent testing framework
  - Core: ban, unban, status, list-jails, banned, test
  - Advanced: logs, logs-watch, metrics, service, test-filter
  - Utility: version, completion (multi-shell support)
- **fail2ban/**: Enterprise-grade client logic with comprehensive interfaces
  - Client interface with context-aware operations and timeout handling
  - MockClient/NoOpClient implementations with thread-safe operations
  - Runner with secure command execution and privilege management
  - SudoChecker with advanced privilege detection

**Design Patterns:**

- **Security-First Architecture**: Path traversal protections, zero shell injection, context-aware timeouts
- **Performance-Optimized**: Validation caching with significant improvements, parallel processing, object pooling
- **Interface-Based Design**: Full dependency injection for testing and extensibility
- **Modern Testing**: Fluent framework with substantial test code reduction and comprehensive mocks
- **Enterprise Features**: Real-time metrics, structured logging, multi-architecture deployment

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `F2B_LOG_DIR` | Log directory | `/var/log` |
| `F2B_FILTER_DIR` | Filter directory | `/etc/fail2ban/filter.d` |
| `F2B_LOG_LEVEL` | Log level | `info` |
| `F2B_LOG_FILE` | Log file path | - |
| `F2B_TEST_SUDO` | Enable test sudo | `false` |
| `F2B_VERBOSE_TESTS` | Force verbose logging in CI/tests | - |
| `ALLOW_DEV_PATHS` | Allow /tmp paths (dev only) | - |

**Logging Behavior:**

- In CI environments (GitHub Actions, Travis, etc.) or test mode, logging is automatically set to `error` level to
  reduce noise
- Set `F2B_VERBOSE_TESTS=true` to enable full logging in CI environments
- Set `F2B_LOG_LEVEL=debug` to override automatic CI detection

## Testing Framework

### Modern Fluent Testing Framework (RECOMMENDED)

```go
// Modern fluent interface (significantly less code)
NewCommandTest(t, "ban").
    WithArgs("192.168.1.100", "sshd").
    ExpectSuccess().
    Run()

// Advanced setup with MockClientBuilder
NewCommandTest(t, "banned").
    WithArgs("sshd").
    WithMockBuilder(
        NewMockClientBuilder().
            WithJails("sshd", "apache").
            WithBannedIP("192.168.1.100", "sshd").
            WithStatusResponse("sshd", "Mock status"),
    ).
    WithJSONFormat().
    ExpectSuccess().
    Run().
    AssertJSONField("Jail", "sshd")
```

### Traditional Mock Setup Pattern

```go
// Modern standardized setup with automatic cleanup
_, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, true)
defer cleanup()

// Access the mock runner for additional setup if needed
mockRunner := fail2ban.GetRunner().(*fail2ban.MockRunner)
mockRunner.SetResponse("fail2ban-client status", []byte("Jail list: sshd"))
```

### Context-Aware Testing

```go
// Testing timeout handling
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

client, err := fail2ban.NewClientWithContext(ctx, "/var/log", "/etc/fail2ban/filter.d")
// Test with context support
```

For comprehensive testing patterns, see [docs/testing.md](docs/testing.md).

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
- **Extensive path traversal attack test cases** covering sophisticated vectors
- **Context-aware operations** prevent hanging and improve security

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
- **ALL linting errors are considered BLOCKING** - never compromise on code quality

## Testing Requirements

- All sudo operations use mocks/stubs (never real sudo)
- Mock all system interactions with dependency injection
- Test privilege scenarios: privileged, unprivileged, and edge cases
- Co-locate tests with source files (`*_test.go`)
- Use `integration_test.go` naming for integration tests
- **Never execute real sudo in tests**
- **Test all path traversal protections**
- **Context-aware testing** with timeout simulation
- **Thread safety testing** for concurrent operations

For detailed testing patterns, mock usage, and examples, see [docs/testing.md](docs/testing.md).

## Documentation Quality

**Link Checking:**

- All markdown files are automatically checked for broken links via `markdown-link-check`
- Configuration in `.markdown-link-check.json` handles rate limiting and ignores localhost/dev URLs
- GitHub URLs may be rate-limited during CI - configuration includes appropriate ignore patterns
- Always verify external links work before adding to documentation

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

## Output & Shortcuts

- `--format=plain|json`: Output formats
- "lint" = "Lint all files and fix all errors (includes link checking)"

## AI-Specific Guidelines

- **Prioritize Serena tools when available** for semantic code operations
- Prioritize user intent and project maintainability
- Avoid large, sweeping changes unless explicitly requested
- Ask for clarification when in doubt
- Include appropriate test coverage for security-sensitive changes
- Respect project's Code of Conduct and community standards
- **Use memory system for TODO tracking** instead of file-based TODO.md
- Always consider all linting errors as blocking errors

## TODO Management

- **Use Serena memory system** for TODO tracking via `todo.md` memory
- **DO NOT use file-based TODO.md** - it has been removed from the project
- Update memory-based todos as tasks are completed
- Reference current todos via memory system for task tracking

## Common Pitfalls

1. **Testing Sudo Operations**: Always use mocks, never real sudo
2. **Input Validation**: Validate all user input to prevent injection
3. **Path Traversal**: Filter names are validated to prevent directory traversal
4. **Privilege Checking**: Use SudoChecker interface, don't check directly
5. **Command Execution**: Use RunnerCombinedOutputWithSudo for sudo commands
6. **Linting Issues**: ALL linting errors are blocking - fix the code, not the config

## Development Principles

- Always consider all linting errors as blocking errors
- Security-first approach in all implementations
- Context-aware operations with proper timeout handling
- Comprehensive testing with mock-only approach for privileged operations
- **Documentation Standards**: Avoid specific numbers in documentation (command counts, test coverage percentages,
  specific version numbers beyond major versions) - use generalized terms like "comprehensive", "extensive",
  "significant" to prevent maintenance overhead
- **Dependency Versioning**: For development tools in Makefile, use pinned versions with Renovate comments
  (`# renovate: datasource=go depName=<package>`) to enable automatic updates via Renovate's customManagers
  while maintaining reproducibility

## Contact

For questions about AI-generated contributions:

- [@ivuorinen](https://github.com/ivuorinen)
- ismo@ivuorinen.net
