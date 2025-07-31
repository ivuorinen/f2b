# Security Guide

## Security Model

f2b is designed with security as a fundamental principle. The tool handles privileged operations safely while
maintaining usability and providing clear security boundaries.

### Threat Model

**Assumptions:**

- Users may have varying privilege levels (root, sudo, regular user)
- Input may be malicious or crafted to exploit vulnerabilities
- The system may be under attack when f2b is used for incident response
- Tests should never compromise the host system

**Protected Assets:**

- System integrity through safe privilege escalation
- Fail2Ban configuration and state
- User data and system logs
- Test environment isolation

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
2. **Command Classification**: Identify if the operation requires privileges
3. **Smart Escalation**: Only add sudo when necessary for specific commands
4. **Validation**: Ensure privilege escalation succeeded
5. **Execution**: Run command with appropriate privileges
6. **Audit**: Log privileged operations

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

Comprehensive validation prevents injection attacks:

```go
func ValidateIP(ip string) error {
    if ip == "" {
        return fmt.Errorf("IP address cannot be empty")
    }

    // Check for valid IPv4 or IPv6 address
    parsed := net.ParseIP(ip)
    if parsed == nil {
        return fmt.Errorf("invalid IP address: %s", ip)
    }

    return nil
}
```

**Protected against:**

- Command injection via IP parameters
- Path traversal attempts
- Buffer overflow attacks
- Format string vulnerabilities

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

### Filter Name Validation

Protects against path traversal in filter operations:

```go
func ValidateFilter(filter string) error {
    if filter == "" {
        return fmt.Errorf("filter name cannot be empty")
    }

    // Prevent path traversal
    if strings.Contains(filter, "..") ||
      strings.Contains(filter, "/") ||
      strings.Contains(filter, "\\") {
        return fmt.Errorf("invalid filter name: %s", filter)
    }

    return nil
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

### Secure Runner Interface

The `Runner` interface provides safe command execution:

```go
type Runner interface {
    CombinedOutput(name string, args ...string) ([]byte, error)
    CombinedOutputWithSudo(name string, args ...string) ([]byte, error)
}
```

### Implementation Example

```go
func (r *RealRunner) CombinedOutputWithSudo(name string, args ...string) ([]byte, error) {
    // Validate inputs
    if name == "" {
        return nil, fmt.Errorf("command name cannot be empty")
    }

    // Build command with argument array
    cmdArgs := append([]string{name}, args...)
    cmd := exec.Command("sudo", cmdArgs...)

    // Execute safely
    return cmd.CombinedOutput()
}
```

## Testing Security

### Mock-Only Testing

**Critical Rule**: Never execute real sudo commands in tests

```go
// CORRECT - Use modern standardized helpers
func TestBanCommand_WithPrivileges(t *testing.T) {
    // Modern standardized setup with automatic cleanup
    _, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, true)
    defer cleanup()

    // Test implementation - environment is fully configured
}
```

### Test Environment Isolation

```go
func setupSecureTestEnvironment(t *testing.T) {
    // Modern standardized setup with complete isolation
    _, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, true)
    defer cleanup()

    // All mock environment is configured with proper isolation and privilege handling
}
```

## Security Checklist

### For Contributors

**Before submitting code:**

- [ ] All user input is validated before use
- [ ] No shell string concatenation used
- [ ] Privilege escalation only when necessary
- [ ] Tests use mocks exclusively
- [ ] No hardcoded credentials or paths
- [ ] Error messages don't leak sensitive information
- [ ] Input sanitization prevents injection attacks

### For Security-Critical Changes

**Additional requirements:**

- [ ] Threat model updated if attack surface changes
- [ ] Security tests added for new attack vectors
- [ ] Privilege boundaries clearly documented
- [ ] Code review by maintainer required
- [ ] Integration tests verify security behavior

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

#### 4. Path Traversal (Fixed)

- **Issue**: Insufficient path validation
- **Impact**: Access to files outside intended directories
- **Fix**: Advanced path traversal protection, symlink prevention

#### 5. Race Conditions (Fixed)

- **Issue**: Concurrent access to shared state
- **Impact**: Data corruption in multi-threaded scenarios
- **Fix**: Thread-safe runner management with RWMutex

## Security Architecture

### Defense in Depth

1. **Input Validation**: First line of defense against malicious input
2. **Privilege Validation**: Ensure user has necessary permissions
3. **Safe Execution**: Use argument arrays, never shell strings
4. **Error Handling**: Fail safely without information leakage
5. **Audit Logging**: Track privileged operations
6. **Test Isolation**: Prevent test-time security compromises

### Security Boundaries

```text
User Input → Validation → Privilege Check → Safe Execution → Audit
  ↓            ↓             ↓              ↓           ↓
  Sanitize → Verify Perms → Escalate → Exec Safely → Log Action
```

## Incident Response

### Security Issue Reporting

**For security vulnerabilities:**

1. **Do not** open public GitHub issues
2. Email: `ismo@ivuorinen.net` with subject "SECURITY: f2b vulnerability"
3. Include: Description, impact assessment, reproduction steps
4. Expect: Acknowledgment within 48 hours

### Security Update Process

1. **Assessment**: Evaluate impact and affected versions
2. **Development**: Create fix with security tests
3. **Testing**: Comprehensive security testing
4. **Release**: Coordinated disclosure with security advisory
5. **Communication**: Notify users via GitHub security advisories

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

This comprehensive security model ensures f2b can be used safely in production environments while maintaining the
flexibility needed for effective Fail2Ban management.
