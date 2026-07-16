# Testing Guide

## Testing Philosophy

f2b follows a comprehensive testing strategy that prioritizes security, reliability, and maintainability.
The core principle is **mock everything** to ensure tests are fast,
reliable, and never execute real system commands.

Our testing approach includes a **modern fluent testing framework** that substantially reduces test code duplication
while maintaining full functionality and improving readability. Enhanced with context-aware testing patterns,
sophisticated security test coverage including extensive path traversal attack vectors, and thread-safe operations
for comprehensive concurrent testing scenarios.

## Test Organization

### File Structure

- **Unit tests**: Co-located with source files using `*_test.go` suffix
- **Integration tests**: `cmd/cmd_integration_test.go` and the top-level `main_*_test.go` files for end-to-end scenarios
- **Test helpers**: Shared utilities in `cmd/test_helpers_test.go` and `fail2ban/test_helpers.go`
- **Mocks**: Comprehensive mock implementations in `fail2ban/` package

### Package Organization

Representative test files (not exhaustive):

```text
cmd/
├── cmd_commands_test.go            # Command behavior tests using the fluent framework
├── cmd_integration_test.go         # End-to-end command tests
├── cmd_parallel_operations_test.go # Concurrent operation tests
├── cmd_service_test.go             # Service command tests
├── command_test_framework_test.go  # Fluent test framework (builder, result, environment)
├── helpers_test.go                 # Helper function tests
└── ...

fail2ban/
├── client_security_test.go             # Path traversal and injection security tests
├── client_management_test.go           # Client lifecycle tests
├── fail2ban_command_validation_test.go # Command validation tests
├── fail2ban_concurrency_test.go        # Thread safety and race condition tests
├── mock.go                             # Thread-safe MockClient implementation
├── test_helpers.go                     # SetupMockEnvironment* helpers
└── ...

main_config_test.go                     # Top-level configuration tests
main_security_test.go                   # Top-level security tests
```

## Testing Framework

### Modern Fluent Interface (RECOMMENDED)

f2b provides a modern fluent testing framework that dramatically reduces test code duplication:

#### Basic Usage

```go
// Simple command test (replaces 10+ lines with 4)
NewCommandTest(t, "ban").
    WithArgs("192.168.1.100", "sshd").
    ExpectSuccess().
    Run()

// Error testing
NewCommandTest(t, "ban").
    WithArgs("invalid-ip", "sshd").
    ExpectError().
    Run().
    AssertContains("invalid IP address")

// JSON output validation
NewCommandTest(t, "banned").
    WithArgs("sshd").
    WithJSONFormat().
    ExpectSuccess().
    Run().
    AssertJSONField("Jail", "sshd")
```

#### Advanced Framework Features

```go
// Environment setup with automatic cleanup
env := NewTestEnvironment().
    WithPrivileges(true).
    WithMockRunner()
defer env.Cleanup()

// Complex test with chained assertions
result := NewCommandTest(t, "status").
    WithArgs("sshd").
    WithEnvironment(env).
    WithSetup(func(mock *fail2ban.MockClient) {
        setMockJails(mock, []string{"sshd", "apache"})
        mock.StatusJailData = map[string]string{
            "sshd": "Status for sshd jail",
        }
    }).
    ExpectSuccess().
    Run()

// Multiple validations on the same result
result.AssertContains("Status for sshd").
    AssertNotContains("apache").
    AssertNotEmpty()
```

#### Mock Client Builder Pattern (Advanced Configuration)

The framework includes a fluent MockClientBuilder for complex mock scenarios:

```go
// Advanced mock setup with builder pattern
mockBuilder := NewMockClientBuilder().
    WithJails("sshd", "apache").
    WithBannedIP("192.168.1.100", "sshd").
    WithBanRecord("sshd", "192.168.1.100", "01:30:00").
    WithLogLine("2024-01-01 12:00:00 [sshd] Ban 192.168.1.100").
    WithStatusResponse("sshd", "Mock status for jail sshd").
    WithBanError("apache", "192.168.1.101", errors.New("ban failed"))

// Use builder in test
NewCommandTest(t, "banned").
    WithArgs("sshd").
    WithMockBuilder(mockBuilder).
    ExpectSuccess().
    ExpectOutput("sshd | 192.168.1.100").
    Run()
```

#### Builder Methods

- `WithJails(jails...)` - Configure available jails
- `WithBannedIP(ip, jail)` - Mark an IP as already banned in a jail
- `WithBanRecord(jail, ip, remaining)` - Add ban record with time
- `WithLogLine(line)` - Add log entry
- `WithStatusResponse(target, response)` - Configure status responses
- `WithBanError(jail, ip, err)` - Configure ban operation errors
- `WithUnbanError(jail, ip, err)` - Configure unban operation errors

#### Table-Driven Tests with Framework

**Standardized Field Naming:** f2b uses consistent field naming conventions across all table-driven tests:

```go
func TestCommandsWithFramework(t *testing.T) {
    tests := []struct {
        name       string   // Test case name - REQUIRED
        command    string   // Command to test
        args       []string // Command arguments
        wantError  bool     // Whether error is expected (not expectError)
        wantOutput string   // Expected output content (not expectedOut/expectedOutput)
        wantErrorMsg string // Specific error message (not expectedError)
    }{
        {"ban_success", "ban", []string{"192.168.1.100", "sshd"}, false, "Banned", ""},
        {"invalid_jail", "ban", []string{"192.168.1.100", "invalid"}, true, "", "not found"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            builder := NewCommandTest(t, tt.command).
                WithArgs(tt.args...)

            if tt.wantError {
                builder = builder.ExpectError()
            } else {
                builder = builder.ExpectSuccess()
            }

            if tt.wantOutput != "" {
                builder.ExpectOutput(tt.wantOutput)
            }

            builder.Run()
        })
    }
}
```

#### Standardized Field Naming Conventions

**✅ Consistent Patterns:**

- `wantOutput` - Expected output content
- `wantError` - Whether error is expected
- `wantErrorMsg` - Specific error message to check

This standardization improves code maintainability and aligns with Go testing conventions.

### Framework Benefits

**✅ Production Results:**

- **Substantial code reduction**: Fluent interface reduces boilerplate
- **Comprehensive test suite**: All tests converted successfully maintain functionality
- **Complete standardization**: Full migration of cmd test files
- **Consistent naming**: Standardized field names across all table tests

**Key Improvements:**

- **Consistent patterns**: Standardized across all tests
- **Better readability**: Self-documenting test intentions
- **Powerful assertions**: Built-in JSON, error, and output validation
- **Environment management**: Automated setup and cleanup
- **Advanced mock patterns**: MockClientBuilder for complex scenarios
- **Backward compatible**: Works alongside existing test patterns

**File-Specific Achievements:**

- `cmd_commands_test.go`, `cmd_service_test.go`, and `cmd_integration_test.go`:
  substantially reduced by migrating to the fluent framework
- `cmd_root_test.go`: Completion and execute tests standardized
- `cmd_logswatch_test.go`: Logs watch tests standardized

### Framework Example

The modern testing framework provides a clean, fluent interface:

```go
// Modern framework approach
NewCommandTest(t, "status").
    WithArgs("all").
    WithSetup(func(mock *fail2ban.MockClient) {
        setMockJails(mock, []string{"sshd"})
        mock.StatusAllData = "Status for all jails"
    }).
    ExpectSuccess().
    ExpectOutput("Status for all jails").
    Run()
```

This approach provides **excellent readability** and **reduced boilerplate**.

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
// Modern standardized setup with automatic cleanup
_, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, true)
defer cleanup()

// The mock environment is now fully configured with privileges
```

## Testing Requirements

### Advanced Security Testing

- **Never execute real sudo commands** - Always use `MockSudoChecker` and `MockRunner`
- **Test both privilege paths** - Include tests for privileged and unprivileged users with context support
- **Validate input sanitization** - Test with malicious inputs including extensive path traversal attack vectors
- **Test privilege escalation** - Ensure commands escalate only when necessary with timeout protection
- **Context-aware security testing** - Test timeout and cancellation behavior in security scenarios
- **Thread-safe security operations** - Test concurrent access to security-critical functions
- **Input validation security testing** - Test that malicious input is rejected before execution
- **Advanced path traversal protection** - Test Unicode normalization, mixed case, and Windows-style attacks

### Test Environment Setup

```go
func TestWithMocks(t *testing.T) {
    // Modern standardized setup with automatic cleanup and context support
    _, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, true)
    defer cleanup()

    // Create context for timeout testing
    ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
    defer cancel()

    // All mock environment is configured with:
    // - Thread-safe operations
    // - Context-aware timeout handling
    // - Security test coverage patterns
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
        timeout     time.Duration
    }{
        {"with privileges", true, false, time.Second*5},
        {"without privileges", false, true, time.Second*5},
        {"with privileges timeout", true, false, time.Millisecond*100},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Set up privilege scenario using modern helper with context support
            _, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, tt.hasPrivileges)
            defer cleanup()

            // Create context with timeout for the test
            ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
            defer cancel()

            // Test command execution with context support
            client := fail2ban.GetClient()
            err := client.BanIPWithContext(ctx, "192.168.1.100", "sshd")

            if (err != nil) != tt.expectError {
                t.Errorf("BanIPWithContext() error = %v, expectError %v", err, tt.expectError)
            }

            // Test context cancellation behavior
            if ctx.Err() != nil {
                t.Logf("Context cancelled as expected: %v", ctx.Err())
            }
        })
    }
}
```

### Advanced Security Input Validation Testing

```go
func TestValidateIP_AdvancedSecurityChecks(t *testing.T) {
    tests := []struct {
        name      string
        ip        string
        wantErr   bool
        attackType string
    }{
        {"valid IPv4", "192.168.1.1", false, ""},
        {"valid IPv6", "2001:db8::1", false, ""},
        {"invalid IP", "not-an-ip", true, "basic"},
        {"malicious input", "192.168.1.1; rm -rf /", true, "command_injection"},
        {"basic path traversal", "../../../etc/passwd", true, "path_traversal"},
        {"url encoded traversal", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", true, "url_encoding"},
        {"null byte injection", "192.168.1.1\x00/../../../etc/passwd", true, "null_byte"},
        {"unicode normalization", "/var/log/\u002e\u002e/\u002e\u002e/etc/passwd", true, "unicode_attack"},
        {"mixed case traversal", "/var/LOG/../../../etc/passwd", true, "mixed_case"},
        {"multiple slashes", "/var/log////../../etc/passwd", true, "multiple_slashes"},
        {"windows style", "/var/log\\..\\..\\..\etc\passwd", true, "windows_style"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := fail2ban.ValidateIP(tt.ip)

            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateIP() error = %v, wantErr %v", err, tt.wantErr)
            }

            // Log attack type for security analysis
            if tt.attackType != "" {
                t.Logf("Successfully blocked %s attack: %s", tt.attackType, tt.ip)
            }
        })
    }
}

// Test concurrent validation safety
func TestValidateIP_ConcurrentSafety(t *testing.T) {
    testIPs := []string{
        "192.168.1.1",
        "192.168.1.2",
        "invalid-ip",
        "../../../etc/passwd",
    }

    var wg sync.WaitGroup
    results := make(chan error, len(testIPs)*10)

    // Test concurrent validation calls
    for i := 0; i < 10; i++ {
        for _, ip := range testIPs {
            wg.Add(1)
            go func(testIP string) {
                defer wg.Done()
                err := fail2ban.ValidateIP(testIP)
                results <- err
            }(ip)
        }
    }

    wg.Wait()
    close(results)

    // Verify no race conditions occurred
    errorCount := 0
    for err := range results {
        if err != nil {
            errorCount++
        }
    }

    t.Logf("Concurrent validation completed with %d errors out of %d calls",
        errorCount, len(testIPs)*10)
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
    // Modern setup with automatic cleanup
    _, cleanup := fail2ban.SetupMockEnvironment(t)
    defer cleanup()

    // Get the configured mock client
    mock := fail2ban.GetClient().(*fail2ban.MockClient)

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
    // Modern setup for benchmarks
    _, cleanup := fail2ban.SetupMockEnvironment(b)
    defer cleanup()

    mock := fail2ban.GetClient().(*fail2ban.MockClient)

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

### Enhanced Coverage Requirements

- **Overall**: High test coverage across the codebase
- **Security-critical code**: Comprehensive coverage for privilege handling with context support
- **Command implementations**: Extensive coverage for all CLI commands including timeout scenarios
- **Input validation**: Complete coverage for validation functions including extensive path traversal cases
- **Context operations**: Comprehensive coverage for timeout and cancellation behavior
- **Concurrent operations**: Extensive coverage for thread-safe functions
- **Performance features**: Coverage for object pooling and parallel processing

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
1. **Hardcoded file paths** - Use temporary files or mocks
1. **Network dependencies** - Mock all external calls
1. **Race conditions** - Use proper synchronization in concurrent tests
1. **Leaked goroutines** - Clean up background processes
1. **Platform dependencies** - Write portable tests

### Enhanced Security Testing Checklist

- [ ] All privileged operations use mocks with context support
- [ ] Input validation tested with malicious inputs including extensive path traversal attack vectors
- [ ] Both privileged and unprivileged paths tested with timeout scenarios
- [ ] No real file system modifications
- [ ] No actual network calls
- [ ] Environment variables properly isolated
- [ ] Context-aware timeout behavior tested
- [ ] Thread-safe concurrent operations verified
- [ ] Performance degradation attack scenarios covered
- [ ] Unicode normalization attacks tested
- [ ] Mixed case and Windows-style path attacks covered

## Test Utilities

### Modern Test Helpers (RECOMMENDED)

The framework provides standardized helpers that reduce duplication:

```go
// Standardized error checking (replaces 6 lines with 1)
fail2ban.AssertError(t, err, expectError, testName)

// Command output validation
fail2ban.AssertCommandSuccess(t, err, output, expectedOutput, testName)
fail2ban.AssertCommandError(t, err, output, expectedError, testName)

// Environment setup with automatic cleanup
_, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, hasPrivileges)
defer cleanup()
```

### Framework Components

#### CommandTestBuilder Methods

**Basic Configuration:**

- `WithArgs(args...)` - Set command arguments
- `WithMockClient(mock)` - Use specific mock client
- `WithMockBuilder(builder)` - Use MockClientBuilder for advanced setup
- `WithJSONFormat()` - Enable JSON output testing
- `WithSetup(func)` - Configure mock client
- `WithEnvironment(env)` - Use test environment

**Expectations:**

- `ExpectSuccess()` / `ExpectError()` - Set error expectations
- `ExpectOutput(text)` - Validate output contains text
- `ExpectExactOutput(text)` - Validate exact output match

**Service Commands:**

- `WithServiceSetup(func(*fail2ban.MockRunner))` - Configure service command mocks
- Service commands support stdout/stderr capture automatically

#### CommandTestResult Assertions

- `AssertContains(text)` - Output contains text
- `AssertNotContains(text)` - Output doesn't contain text
- `AssertEmpty()` / `AssertNotEmpty()` - Output emptiness
- `AssertJSONField(path, value)` - JSON field validation
- `AssertExactOutput(text)` - Exact output match

#### TestEnvironment Setup

- `WithPrivileges(bool)` - Configure sudo privileges
- `WithMockRunner()` - Set up command runner mocks
- `WithStdoutCapture()` - Capture stdout for validation
- `Cleanup()` - Restore original environment

### Standard Test Setup Example

```go
// SetupMockEnvironmentWithSudo configures standard test environment with privileges
func TestExample(t *testing.T) {
    _, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, true)
    defer cleanup()

    // Test implementation here
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

### Enhanced Security-Focused Testing

```bash
# Run tests with sudo checking enabled
F2B_TEST_SUDO=true go test ./...

# Run comprehensive security tests including path traversal
go test -run "Security|Sudo|Privilege|PathTraversal|Context|Timeout" ./...

# Run concurrent safety tests
go test -run "Concurrent|Race|ThreadSafe" -race ./...

# Run validation and performance tests
go test -run "Performance|Validation" ./...

# Run advanced path traversal security tests
go test -run "PathTraversal|Unicode|Mixed|Windows" ./fail2ban

# Run context and timeout behavior tests
go test -run "Context|Timeout|Cancel" ./...
```

### End-to-End Testing

```bash
# Run integration tests only
go test -run Integration ./cmd

# Run with coverage for integration tests
go test -coverprofile=integration.out -run Integration ./cmd
```

This comprehensive testing approach ensures f2b remains secure, reliable, and maintainable while providing confidence
for all changes and contributions. The enhanced testing framework includes context-aware operations, sophisticated
security coverage with extensive path traversal attack vectors, thread-safe concurrent testing, performance-oriented
validation tests, and comprehensive timeout handling verification for enterprise-grade reliability.
