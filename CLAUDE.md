# CLAUDE.md

Guidance for Claude Code when working with the f2b repository.

## About f2b

Go CLI for Fail2Ban management with secure sudo handling, input validation, and comprehensive testing.

## Commands

```bash
# Build & Test
go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=1.2.3" -o f2b .
go test ./... && go test -coverprofile=coverage.out ./...
go install github.com/ivuorinen/f2b@latest

# Lint & Format
pre-commit run --all-files  # Run all checks
pre-commit install          # One-time setup

# Release
make release-check          # Check config
make release-snapshot       # Test (no tag)
git tag -a v1.2.3 -m "Release v1.2.3" && git push origin v1.2.3
make release               # Full release
```

## Architecture

- **main.go**: Entry point, sudo checks
- **cmd/**: Cobra CLI commands
- **fail2ban/**: Core client logic (Client interface, MockClient/NoOpClient, Runner, SudoChecker)

## Key Patterns

- Dependency injection via interfaces
- Security-first: validate before escalate
- Extensive mocking for tests
- Environment config with defaults

## Environment

| Variable | Purpose | Default |
|----------|---------|---------|
| `F2B_LOG_DIR` | Log directory | `/var/log` |
| `F2B_FILTER_DIR` | Filter directory | `/etc/fail2ban/filter.d` |
| `F2B_LOG_LEVEL` | Log level | `info` |
| `F2B_LOG_FILE` | Log file path | - |
| `F2B_TEST_SUDO` | Enable test sudo | `false` |

## Testing

```go
// Mock Setup Pattern
originalChecker := fail2ban.GetSudoChecker()
defer fail2ban.SetSudoChecker(originalChecker)
fail2ban.SetSudoChecker(fail2ban.NewMockSudoCheckerWithPrivileges(true))
os.Setenv("F2B_TEST_SUDO", "true")
defer os.Unsetenv("F2B_TEST_SUDO")

// Mock Runner
mockRunner := fail2ban.NewMockRunner()
originalRunner := fail2ban.GetRunner()
defer fail2ban.SetRunner(originalRunner)
fail2ban.SetRunner(mockRunner)
mockRunner.SetResponse("fail2ban-client status", []byte("Jail list: sshd"))
```

## Security

See AGENTS.md for full guidelines. Key points:

- Never execute real sudo in tests
- Validate inputs before privilege escalation
- Use argument arrays, not shell strings
- Test privileged and unprivileged paths

## Output & Shortcuts

- `--format=plain|json`: Output formats
- "lint" = "Lint all files and fix all errors"
