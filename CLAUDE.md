# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## About f2b

f2b is a modern, secure Go-based CLI tool for managing Fail2Ban jails and bans. It provides a safer, more extensible alternative to Bash scripts for interacting with Fail2Ban, with automatic sudo privilege management, shell completion, and comprehensive security features.

## Common Development Commands

### Building and Testing

```bash
# Build the binary
go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=1.2.3" -o f2b .

# Install globally
go install github.com/ivuorinen/f2b@latest

# Run all tests
go test ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...

# Run integration tests (requires sudo setup)
go test -tags=integration ./...
```

### Code Quality

```bash
# Format code
gofmt -w .

# Run go vet
go vet ./...

# Run golangci-lint (if available)
golangci-lint run --timeout=5m

# Check editorconfig compliance
editorconfig-checker
```

### Testing with Mock Environment

```bash
# Set test environment variable for sudo checking
F2B_TEST_SUDO=true go test ./...
```

## Code Architecture

### Core Components

1. **Main Entry Point** (`main.go`): Initializes the fail2ban client and handles privilege checks before delegating to cmd package.

2. **Command Layer** (`cmd/`):
  - Uses Cobra for CLI structure
  - Handles argument parsing and validation
  - Manages configuration from environment variables and flags
  - Provides JSON and plain text output formats

3. **Fail2Ban Client** (`fail2ban/`):
  - **Client Interface**: Defines operations for jail/ban management
  - **RealClient**: Production implementation using fail2ban-client
  - **MockClient/NoOpClient**: Testing implementations
  - **Runner Interface**: Abstracts command execution (with/without sudo)
  - **SudoChecker**: Handles privilege detection and validation

### Key Design Patterns

- **Dependency Injection**: All components use interfaces to enable testing
- **Security-First**: Input validation, privilege checking, and secure command execution
- **Testability**: Extensive mocking infrastructure for sudo operations
- **Configuration**: Environment variable support with sensible defaults

### Security Architecture

- **Privilege Management**: Automatic sudo detection and escalation only when needed
- **Input Validation**: All IP addresses, jail names, and filter names are validated
- **Secure Execution**: Uses argument arrays, never shell string concatenation
- **Test Isolation**: Mock implementations prevent actual sudo execution in tests

## Environment Variables

- `F2B_LOG_DIR`: Fail2Ban log directory (default: `/var/log`)
- `F2B_FILTER_DIR`: Fail2Ban filter directory (default: `/etc/fail2ban/filter.d`)
- `F2B_LOG_LEVEL`: Application log level (debug, info, warn, error)
- `F2B_LOG_FILE`: Path to application log file
- `F2B_TEST_SUDO`: Enable sudo checking in tests (set to "true")

## Testing Guidelines

### Sudo and Privilege Testing

When writing tests that involve sudo operations:

```go
// Save original checker and set up mock
originalChecker := fail2ban.GetSudoChecker()
defer fail2ban.SetSudoChecker(originalChecker)

// Mock with specific privileges
mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
fail2ban.SetSudoChecker(mockChecker)

// Enable sudo checking in test environment
os.Setenv("F2B_TEST_SUDO", "true")
defer os.Unsetenv("F2B_TEST_SUDO")
```

### Command Runner Mocking

```go
// Set up mock runner
mockRunner := fail2ban.NewMockRunner()
originalRunner := fail2ban.GetRunner()
defer fail2ban.SetRunner(originalRunner)
fail2ban.SetRunner(mockRunner)

// Configure expected responses
mockRunner.SetResponse("fail2ban-client status", []byte("Jail list: sshd"))
```

## File Structure Conventions

- `cmd/`: CLI commands and configuration
- `fail2ban/`: Core fail2ban client implementation
- `main.go`: Application entry point
- Tests are co-located with source files (`*_test.go`)
- Integration tests use `integration_test.go` naming

## Important Security Notes

- NEVER execute real sudo commands in tests - always use MockRunner
- Validate all input before privilege escalation
- Use secure command execution (argument arrays, not shell strings)
- Test both privileged and unprivileged scenarios
- Handle privilege errors gracefully with helpful messages

## Output Formats

The CLI supports two output formats:

- `--format=plain`: Human-readable output (default)
- `--format=json`: Machine-readable JSON for scripting

## Common Pitfalls

1. **Testing Sudo Operations**: Always use mocks, never real sudo in tests
2. **Input Validation**: Validate IPs, jail names, and filter names to prevent injection
3. **Path Traversal**: Filter names are validated to prevent directory traversal
4. **Privilege Checking**: Use the SudoChecker interface, don't check privileges directly
5. **Command Execution**: Use RunnerCombinedOutputWithSudo for commands that may need sudo
