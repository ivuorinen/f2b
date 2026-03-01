# Security Guide

## Security Model

f2b is designed with security as a fundamental principle. The tool handles privileged operations safely
while maintaining usability and providing clear security boundaries. Enhanced with context-aware timeout
handling, comprehensive path traversal protection, and advanced security testing with extensive
sophisticated attack vectors.

### Threat Model

**Assumptions:**

- Users may have varying privilege levels (root, sudo, regular user)
- Input may be malicious or crafted to exploit vulnerabilities
- The system may be under attack when f2b is used for incident response
- Tests should never compromise the host system
- Operations may timeout or hang, requiring graceful handling
- Advanced path traversal attacks using Unicode normalization and mixed cases may be attempted

**Protected Assets:**

- System integrity through safe privilege escalation with timeout protection
- Fail2Ban configuration and state
- User data and system logs
- Test environment isolation with comprehensive mock setup
- Path traversal protection against sophisticated attack vectors
- Context-aware operations preventing resource exhaustion

## Privilege Management

### Automatic Privilege Detection

f2b intelligently manages sudo requirements through a comprehensive privilege checking system:

#### User Categories

- **Root users (UID 0)**: Commands run directly without sudo
- **Sudo group members**: Automatic escalation for privileged operations
- **Users with sudo access**: Detected via `sudo -n true` test
- **Regular users**: Clear error messages with guidance

#### Command Classification

**Require sudo:**

- `ban`, `unban` operations
- `service` control commands
- Configuration modifications

**No sudo needed:**

- `status`, `list-jails`, `test`
- `logs`, `version`, `completion`
- Read-only operations

### Privilege Escalation Process

1. **Pre-flight Check**: Determine user capabilities before command execution
1. **Context Creation**: Create context with timeout for the operation
1. **Command Classification**: Identify if the operation requires privileges
1. **Smart Escalation**: Only add sudo when necessary for specific commands
1. **Validation**: Ensure privilege escalation succeeded with timeout protection
1. **Execution**: Run command with appropriate privileges and context
1. **Timeout Handling**: Gracefully handle hanging operations with cancellation
1. **Audit**: Log privileged operations with context information

### Error Handling

When privileges are insufficient:

```text
Error: fail2ban operations require sudo privileges. Current user: username (UID: 1000).
Please run with sudo or ensure user is in sudo group
Hint: Try running with 'sudo' or ensure your user is in the sudo group
Example: sudo f2b ban 192.168.1.100
```

## Input Validation

### IP Address Validation

Comprehensive validation with caching prevents injection attacks:

```go
func ValidateIP(ip string) error {
    if ip == "" {
        return fmt.Errorf("IP address cannot be empty")
    }

    // Check validation cache first for performance
    if IsIPValidCached(ip) {
        return nil
    }

    // Check for valid IPv4 or IPv6 address
    parsed := net.ParseIP(ip)
    if parsed == nil {
        return fmt.Errorf("invalid IP address: %s", ip)
    }

    // Cache successful validation
    CacheIPValidation(ip, true)
    return nil
}
```

**Protected against:**

- Command injection via IP parameters
- Path traversal attempts
- Buffer overflow attacks
- Format string vulnerabilities
- Performance degradation through validation caching

### Jail Name Validation

Prevents directory traversal and command injection:

```go
func ValidateJail(jail string) error {
    if jail == "" {
        return fmt.Errorf("jail name cannot be empty")
    }

    // Allow only alphanumeric, dash, underscore, dot
    validJailRegex := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
    if !validJailRegex.MatchString(jail) {
        return fmt.Errorf("invalid jail name: %s", jail)
    }

    return nil
}
```

### Advanced Path Traversal Protection

Comprehensive protection against sophisticated path traversal attacks:

```go
func ValidateFilter(filter string) error {
    if filter == "" {
        return fmt.Errorf("filter name cannot be empty")
    }

    // Path traversal protection checking for:
    // - Basic directory traversal (..)
    // - URL encoding (%2e%2e, %2f, %5c)
    // - Null byte injection (\x00)
    // - Unicode normalization attacks (\u002e\u002e, \u002f, \u005c)

    if containsPathTraversal(filter) {
        return fmt.Errorf("invalid filter name contains path traversal: %s", filter)
    }

    return nil
}

func containsPathTraversal(path string) bool {
    // Comprehensive path traversal detection
    dangerous := []string{
        "..", "\x00",
        "%2e%2e", "%2f", "%5c",
        "\u002e\u002e", "\u002f", "\u005c",
    }

    normalized := strings.ToLower(path)
    for _, pattern := range dangerous {
        if strings.Contains(normalized, pattern) {
            return true
        }
    }

    return false
}
```

## Safe Command Execution

### Argument Array Pattern

**Never use shell string concatenation:**

```go
// DANGEROUS - DON'T DO THIS
cmd := exec.Command("sh", "-c", fmt.Sprintf("fail2ban-client ban %s %s", ip, jail))

// SAFE - Use argument arrays
cmd := exec.Command("fail2ban-client", "ban", ip, jail)
```

### Context-Aware Secure Runner Interface

The `Runner` interface provides safe command execution with timeout handling:

```go
type Runner interface {
    CombinedOutput(name string, args ...string) ([]byte, error)
    CombinedOutputWithSudo(name string, args ...string) ([]byte, error)
    CombinedOutputWithContext(ctx context.Context, name string, args ...string) ([]byte, error)
    CombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error)
}
```

### Context-Aware Implementation

```go
func (r *RealRunner) CombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error) {
    // Validate inputs
    if name == "" {
        return nil, fmt.Errorf("command name cannot be empty")
    }

    // Build command with argument array
    cmdArgs := append([]string{name}, args...)
    cmd := exec.CommandContext(ctx, "sudo", cmdArgs...)

    // Execute safely with timeout protection
    output, err := cmd.CombinedOutput()
    if ctx.Err() != nil {
        return nil, fmt.Errorf("command timeout: %w", ctx.Err())
    }

    return output, err
}
```

**Security enhancements:**

- Context-based timeout prevention
- Graceful cancellation of hanging operations
- Resource cleanup on timeout
- Enhanced error reporting with context information

## Testing Security

### Mock-Only Testing

**Critical Rule**: Never execute real sudo commands in tests

```go
// CORRECT - Use modern standardized helpers with context support
func TestBanCommand_WithPrivileges(t *testing.T) {
    // Modern standardized setup with automatic cleanup and context support
    _, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, true)
    defer cleanup()

    // Create context with timeout for the test
    ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
    defer cancel()

    // Test implementation with context-aware operations
    err := client.BanIPWithContext(ctx, "192.168.1.100", "sshd")
    // Test assertions...
}
```

### Advanced Security Test Coverage

The system includes comprehensive security testing with extensive sophisticated attack vectors:

```go
func TestPathTraversalProtection(t *testing.T) {
    testCases := []struct {
        name   string
        input  string
        expect bool // true if should be blocked
    }{
        {"Basic traversal", "../../../etc/passwd", true},
        {"URL encoded", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", true},
        {"Null byte injection", "valid\x00/../../../etc/passwd", true},
        {"Unicode normalization", "/var/log/\u002e\u002e/\u002e\u002e/etc/passwd", true},
        {"Mixed case", "/var/LOG/../../../etc/passwd", true},
        {"Multiple slashes", "/var/log////../../etc/passwd", true},
        {"Windows style", "/var/log\\..\\..\\..\etc\passwd", true},
        {"Valid path", "/var/log/fail2ban.log", false},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            blocked := containsPathTraversal(tc.input)
            assert.Equal(t, tc.expect, blocked)
        })
    }
}
```

### Test Environment Isolation

```go
func setupSecureTestEnvironment(t *testing.T) {
    // Modern standardized setup with complete isolation and context support
    _, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, true)
    defer cleanup()

    // All mock environment is configured with:
    // - Proper isolation and privilege handling
    // - Context-aware timeout operations
    // - Thread-safe mock operations
    // - Comprehensive path traversal protection testing
}
```

## Security Checklist

### For Contributors

**Before submitting code:**

- [ ] All user input is validated before use with caching where appropriate
- [ ] No shell string concatenation used
- [ ] Privilege escalation only when necessary with timeout protection
- [ ] Tests use mocks exclusively with context support
- [ ] No hardcoded credentials or paths
- [ ] Error messages don't leak sensitive information
- [ ] Input sanitization prevents injection attacks including advanced path traversal
- [ ] Context-aware operations implemented with proper timeout handling
- [ ] Path traversal protection covers all sophisticated attack vectors
- [ ] Thread-safe operations for concurrent access

### For Security-Critical Changes

**Additional requirements:**

- [ ] Threat model updated if attack surface changes
- [ ] Security tests added for new attack vectors with context support
- [ ] Privilege boundaries clearly documented with timeout behavior
- [ ] Code review by maintainer required
- [ ] Integration tests verify security behavior including timeout scenarios
- [ ] Path traversal protection tested against sophisticated attack vectors
- [ ] Context-aware timeout handling properly implemented
- [ ] Thread safety verified for concurrent operations

## Known Security Issues (Fixed)

### Historical Vulnerabilities

#### 1. Sudo Timeout (Fixed)

- **Issue**: Infinite wait on sudo prompt
- **Impact**: Denial of service via hanging processes
- **Fix**: 5-second timeout added to `CanUseSudo()`

#### 2. Service Command Injection (Fixed)

- **Issue**: Insufficient validation of service actions
- **Impact**: Command injection via service parameters
- **Fix**: Strict action validation implemented

#### 3. Memory Exhaustion (Fixed)

- **Issue**: Unbounded log reading
- **Impact**: Memory exhaustion via large log files
- **Fix**: Incremental reading with 1000 lines/100MB limits

#### 4. Path Traversal (Enhanced Protection)

- **Issue**: Insufficient path validation against sophisticated attacks
- **Impact**: Access to files outside intended directories
- **Fix**: Comprehensive path traversal protection with extensive test cases covering:
  - Unicode normalization attacks (\\u002e\\u002e)
  - Mixed case traversal (/var/LOG/../../../etc/passwd)
  - Multiple slashes (/var/log////../../etc/passwd)
  - Windows-style paths on Unix (/var/log\\..\\..\\etc\\passwd)
  - URL encoding variants (%2e%2e%2f)
  - Null byte injection attacks

#### 5. Race Conditions (Fixed)

- **Issue**: Concurrent access to shared state
- **Impact**: Data corruption in multi-threaded scenarios
- **Fix**: Thread-safe runner management with RWMutex and atomic operations

#### 6. Hanging Operations (Fixed)

- **Issue**: Operations could hang indefinitely without timeout protection
- **Impact**: Resource exhaustion and denial of service
- **Fix**: Context-aware operations with configurable timeouts and graceful cancellation

## Security Architecture

### Defense in Depth

1. **Input Validation**: First line of defense against malicious input with caching
1. **Advanced Path Traversal Protection**: Extensive sophisticated attack vector protection
1. **Privilege Validation**: Ensure user has necessary permissions with timeout protection
1. **Context-Aware Execution**: Use argument arrays with timeout and cancellation support
1. **Safe Execution**: Never use shell strings, always use context-aware operations
1. **Error Handling**: Fail safely without information leakage, include context information
1. **Audit Logging**: Track privileged operations with contextual information
1. **Test Isolation**: Prevent test-time security compromises with comprehensive mocks
1. **Performance Security**: Validation caching prevents DoS through repeated validation
1. **Timeout Protection**: Prevent resource exhaustion through hanging operations

### Security Boundaries

```text
User Input → Context → Validation → Path Traversal → Privilege Check → Safe Execution → Timeout → Audit
    ↓          ↓         ↓            ↓               ↓              ↓             ↓        ↓
  Sanitize → Create → Cache Check → Block Attack → Verify Perms → Exec w/Context → Cancel → Log
```

**Enhanced Security Flow:**

1. **Context Creation**: Establish timeout and cancellation context
1. **Input Sanitization**: Clean and validate all user input
1. **Cache Validation**: Check validation cache for performance and DoS protection
1. **Path Traversal Protection**: Block extensive sophisticated attack vectors
1. **Privilege Verification**: Confirm user permissions with timeout protection
1. **Context-Aware Execution**: Execute with timeout and cancellation support
1. **Timeout Handling**: Gracefully handle hanging operations
1. **Comprehensive Auditing**: Log all operations with context information

## Incident Response

### Security Issue Reporting

**For security vulnerabilities:**

1. **Do not** open public GitHub issues
1. Email: `ismo@ivuorinen.net` with subject "SECURITY: f2b vulnerability"
1. Include: Description, impact assessment, reproduction steps
1. Expect: Acknowledgment within 48 hours

### Security Update Process

1. **Assessment**: Evaluate impact and affected versions
1. **Development**: Create fix with security tests
1. **Testing**: Comprehensive security testing
1. **Release**: Coordinated disclosure with security advisory
1. **Communication**: Notify users via GitHub security advisories

## Security Best Practices

### For Users

- Run with minimal privileges necessary
- Regularly update to latest version
- Monitor logs for unexpected privilege escalations
- Use structured logging for audit trails
- Validate f2b binary checksums after download

### For Developers

- Follow secure coding guidelines
- Use static analysis tools (gosec, golangci-lint)
- Implement comprehensive security tests
- Document security assumptions
- Regular security code reviews

### For Deployment

- Use principle of least privilege
- Monitor privileged command execution
- Implement log aggregation and monitoring
- Regular security updates
- Network segmentation where applicable

## Security Monitoring

### Audit Points

- Privilege escalation attempts
- Failed authentication events
- Malformed input attempts
- Unusual command patterns
- File access outside expected directories

### Logging Security Events

```go
logger.WithFields(logrus.Fields{
    "user":      os.Getenv("USER"),
    "uid":       os.Getuid(),
    "command":   "ban",
    "target_ip": ip,
    "jail":      jail,
    "sudo_used": true,
}).Info("Privileged operation executed")
```

This comprehensive security model ensures f2b can be used safely in production environments
while maintaining the flexibility needed for effective Fail2Ban management. The enhanced security
features include context-aware timeout handling, sophisticated path traversal protection with
extensive attack vector coverage, performance-optimized validation caching, and comprehensive
audit logging for enterprise-grade security monitoring.
