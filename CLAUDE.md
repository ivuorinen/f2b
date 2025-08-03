# CLAUDE.md

Guidance for Claude Code when working with the f2b repository.

## About f2b

**Enterprise-grade** Go CLI for Fail2Ban management with 21 comprehensive commands, advanced security
features including 17 path traversal protections, context-aware timeout support, real-time performance
monitoring, multi-architecture Docker deployment, sophisticated input validation, and modern fluent
testing infrastructure with 60-70% code reduction.

## Commands

```bash
# Build & Test
go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=1.2.3" -o f2b .
go test ./... && go test -coverprofile=coverage.out ./...
go install github.com/ivuorinen/f2b@latest

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

## Architecture

**Core Structure:**

- **main.go**: Entry point with secure sudo detection and client initialization
- **cmd/**: 21 Cobra CLI commands with modern fluent testing framework
  - Core: ban, unban, status, list-jails, banned, test
  - Advanced: logs, logs-watch, metrics, service, test-filter
  - Utility: version, completion (multi-shell support)
- **fail2ban/**: Enterprise-grade client logic with comprehensive interfaces
  - Client interface with context-aware operations and timeout handling
  - MockClient/NoOpClient implementations with thread-safe operations
  - Runner with secure command execution and privilege management
  - SudoChecker with advanced privilege detection

**Design Patterns:**

- **Security-First Architecture**: 17 path traversal protections, zero shell injection, context-aware timeouts
- **Performance-Optimized**: Validation caching (70% improvement), parallel processing, object pooling
- **Interface-Based Design**: Full dependency injection for testing and extensibility
- **Modern Testing**: Fluent framework reducing test code by 60-70% with comprehensive mocks
- **Enterprise Features**: Real-time metrics, structured logging, multi-architecture deployment

For detailed architecture documentation, see [docs/architecture.md](docs/architecture.md).

## Environment

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

## Testing

### Modern Fluent Testing Framework (RECOMMENDED)

```go
// Modern fluent interface (60-70% less code)
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

## Security

Key security principles:

- Never execute real sudo in tests
- Validate inputs before privilege escalation with comprehensive protection
- Use argument arrays, not shell strings
- 17 path traversal attack test cases covering sophisticated vectors
- Context-aware operations prevent hanging and improve security

For detailed security guidelines, see [docs/security.md](docs/security.md) and [AGENTS.md](AGENTS.md).

## Documentation Quality

**Link Checking:**

- All markdown files are automatically checked for broken links via `markdown-link-check`
- Configuration in `.markdown-link-check.json` handles rate limiting and ignores localhost/dev URLs
- GitHub URLs may be rate-limited during CI - configuration includes appropriate ignore patterns
- Always verify external links work before adding to documentation

## Output & Shortcuts

- `--format=plain|json`: Output formats
- "lint" = "Lint all files and fix all errors (includes link checking)"

## Development Principles

- Always consider all linting errors as blocking errors
