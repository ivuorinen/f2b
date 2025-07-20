# Testing Guide

## Testing Philosophy

f2b follows a comprehensive testing strategy that prioritizes security, reliability, and maintainability.
The core principle is **mock everything** to ensure tests are fast,
reliable, and never execute real system commands.

## Test Organization

### File Structure

- **Unit tests**: Co-located with source files using `*_test.go` suffix
- **Integration tests**: Named `integration_test.go` for end-to-end scenarios
- **Test helpers**: Shared utilities in test files
- **Mocks**: Comprehensive mock implementations in `fail2ban/` package

### Package Organization

```text
cmd/
├── ban_test.go          # Unit tests for ban command
├── cmd_test.go          # Shared test utilities
├── integration_test.go  # End-to-end command tests
└── ...

fail2ban/
├── client_test.go       # Client interface tests
├── mock.go             # MockClient implementation
├── mock_test.go        # Mock behavior tests
└── ...
```

## Mock Patterns

### MockClient Usage

The `MockClient` is a comprehensive, thread-safe mock implementation of the `Client` interface:

```go
// Basic setup
mock := fail2ban.NewMockClient()
mock.Jails = map[string]struct{}{"sshd": {}, "apache": {}}

// Configure responses
mock.StatusAllData = "Jail list: sshd apache"
mock.StatusJailData = map[string]string{
    "sshd": "Status for sshd jail",
}

// Set up banned IPs
mock.Banned = map[string]map[string]time.Time{
    "sshd": {"192.168.1.100": time.Now()},
}
```

### MockRunner Setup

For testing command execution:

```go
// Save original and set up mock
mockRunner := fail2ban.NewMockRunner()
originalRunner := fail2ban.GetRunner()
defer fail2ban.SetRunner(originalRunner)
fail2ban.SetRunner(mockRunner)

// Configure command responses
mockRunner.SetResponse("fail2ban-client status", []byte("Jail list: sshd"))
```

### MockSudoChecker Pattern

For testing privilege scenarios:

```go
// Save original checker and set up mock with privileges
originalChecker := fail2ban.GetSudoChecker()
defer fail2ban.SetSudoChecker(originalChecker)
mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
fail2ban.SetSudoChecker(mockChecker)

// Enable sudo checking in tests
os.Setenv("F2B_TEST_SUDO", "true")
defer os.Unsetenv("F2B_TEST_SUDO")
```

## Testing Requirements

### Security Testing

- **Never execute real sudo commands** - Always use `MockSudoChecker` and `MockRunner`
- **Test both privilege paths** - Include tests for privileged and unprivileged users
- **Validate input sanitization** - Test with malicious inputs
- **Test privilege escalation** - Ensure commands escalate only when necessary

### Test Environment Setup

```go
func TestWithMocks(t *testing.T) {
    // Set up environment for sudo testing
    os.Setenv("F2B_TEST_SUDO", "true")
    defer os.Unsetenv("F2B_TEST_SUDO")

    // Mock all system interactions
    originalChecker := fail2ban.GetSudoChecker()
    defer fail2ban.SetSudoChecker(originalChecker)
    fail2ban.SetSudoChecker(fail2ban.NewMockSudoCheckerWithPrivileges(true))

    originalRunner := fail2ban.GetRunner()
    defer fail2ban.SetRunner(originalRunner)
    fail2ban.SetRunner(fail2ban.NewMockRunner())

    // Test implementation
}
```

## Common Test Scenarios

### Testing Commands with Privileges

```go
func TestBanCommand_RequiresPrivileges(t *testing.T) {
    tests := []struct {
        name        string
        hasPrivileges bool
        expectError  bool
    }{
        {"with privileges", true, false},
        {"without privileges", false, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Set up privilege scenario
            mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(tt.hasPrivileges)
            fail2ban.SetSudoChecker(mockChecker)

            // Test command execution
            // ...
        })
    }
}
```

### Testing Input Validation

```go
func TestValidateIP_SecurityChecks(t *testing.T) {
    tests := []struct {
        name    string
        ip      string
        wantErr bool
    }{
        {"valid IPv4", "192.168.1.1", false},
        {"valid IPv6", "2001:db8::1", false},
        {"invalid IP", "not-an-ip", true},
        {"malicious input", "192.168.1.1; rm -rf /", true},
        {"path traversal", "../../../etc/passwd", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := fail2ban.ValidateIP(tt.ip)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateIP() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Testing Output Formats

```go
func TestCommandOutput_JSONFormat(t *testing.T) {
    mock := fail2ban.NewMockClient()
    config := &cmd.Config{Format: "json"}

    output, err := executeCommandWithConfig(mock, config, "banned", "all")
    if err != nil {
        t.Fatalf("Command failed: %v", err)
    }

    // Validate JSON output
    var result []interface{}
    if err := json.Unmarshal([]byte(output), &result); err != nil {
        t.Errorf("Invalid JSON output: %v", err)
    }
}
```

## Integration Testing

### End-to-End Command Testing

```go
func TestIntegration_BanUnbanFlow(t *testing.T) {
    mock := fail2ban.NewMockClient()
    setupMockEnvironment(t, mock)

    // Test complete workflow
    steps := []struct {
        command     []string
        expectError bool
        validate    func(string) error
    }{
        {[]string{"ban", "192.168.1.100", "sshd"}, false, validateBanOutput},
        {[]string{"test", "192.168.1.100"}, false, validateTestOutput},
        {[]string{"unban", "192.168.1.100", "sshd"}, false, validateUnbanOutput},
    }

    for _, step := range steps {
        output, err := executeCommand(mock, step.command...)
        if (err != nil) != step.expectError {
            t.Errorf("Command %v: error = %v, expectError = %v",
                step.command, err, step.expectError)
        }
        if step.validate != nil {
            if err := step.validate(output); err != nil {
                t.Errorf("Validation failed for %v: %v", step.command, err)
            }
        }
    }
}
```

## Performance Testing

### Benchmarking Critical Paths

```go
func BenchmarkBanCommand(b *testing.B) {
    mock := fail2ban.NewMockClient()
    setupMockEnvironment(b, mock)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := executeCommand(mock, "ban", "192.168.1.100", "sshd")
        if err != nil {
            b.Fatalf("Ban command failed: %v", err)
        }
    }
}
```

## Test Coverage Requirements

### Minimum Coverage

- **Overall**: 85%+ test coverage across the codebase
- **Security-critical code**: 95%+ coverage for privilege handling
- **Command implementations**: 90%+ coverage for all CLI commands
- **Input validation**: 100% coverage for validation functions

### Coverage Verification

```bash
# Run tests with coverage
go test -coverprofile=coverage.out ./...

# View coverage report
go tool cover -html=coverage.out

# Check coverage percentage
go tool cover -func=coverage.out | grep total
```

## Common Testing Pitfalls

### Avoid These Mistakes

1. **Real sudo execution in tests** - Always use MockSudoChecker
2. **Hardcoded file paths** - Use temporary files or mocks
3. **Network dependencies** - Mock all external calls
4. **Race conditions** - Use proper synchronization in concurrent tests
5. **Leaked goroutines** - Clean up background processes
6. **Platform dependencies** - Write portable tests

### Security Testing Checklist

- [ ] All privileged operations use mocks
- [ ] Input validation tested with malicious inputs
- [ ] Both privileged and unprivileged paths tested
- [ ] No real file system modifications
- [ ] No actual network calls
- [ ] Environment variables properly isolated

## Test Utilities

### Shared Test Helpers

```go
// setupMockEnvironment configures standard test environment
func setupMockEnvironment(t testing.TB, mock *fail2ban.MockClient) {
    os.Setenv("F2B_TEST_SUDO", "true")
    t.Cleanup(func() { os.Unsetenv("F2B_TEST_SUDO") })

    originalChecker := fail2ban.GetSudoChecker()
    fail2ban.SetSudoChecker(fail2ban.NewMockSudoCheckerWithPrivileges(true))
    t.Cleanup(func() { fail2ban.SetSudoChecker(originalChecker) })

    originalRunner := fail2ban.GetRunner()
    fail2ban.SetRunner(fail2ban.NewMockRunner())
    t.Cleanup(func() { fail2ban.SetRunner(originalRunner) })
}

// executeCommand runs a command with mock client
func executeCommand(client fail2ban.Client, args ...string) (string, error) {
    config := &cmd.Config{Format: "plain"}
    root := cmd.NewRootCmd(client, config)

    var output bytes.Buffer
    root.SetOutput(&output)
    root.SetArgs(args)

    err := root.Execute()
    return output.String(), err
}
```

## Running Tests

### Basic Test Execution

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run specific test
go test -run TestBanCommand ./cmd

# Run tests with race detection
go test -race ./...
```

### Security-Focused Testing

```bash
# Run tests with sudo checking enabled
F2B_TEST_SUDO=true go test ./...

# Run only security-related tests
go test -run "Security|Sudo|Privilege" ./...
```

### End-to-End Testing

```bash
# Run integration tests only
go test -run Integration ./cmd

# Run with coverage for integration tests
go test -coverprofile=integration.out -run Integration ./cmd
```

This comprehensive testing approach ensures f2b remains secure, reliable, and maintainable while providing confidence
for all changes and contributions.
