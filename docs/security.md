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

**No privilege check:**

- `version`, `completion`, `help`
- These never contact the fail2ban server socket

Note: read operations such as `status`, `list-jails`, `banned`, and `logs`
DO require sudo/root, because fail2ban's control socket
(`/var/run/fail2ban/fail2ban.sock`) is root-only.

### Allowed Paths

`test-filter` runs `sudo fail2ban-regex <logpath> <filter>`, and fail2ban-regex
prints the lines it reads, so every allowed directory is one root can be made to
read. The allowlists are therefore limited to fail2ban's own locations:

- Log directories (`--log-dir`, `F2B_LOG_DIR`, filter `logpath`, `--log-file`):
  under `/var/log`
- Filter directories (`--filter-dir`, `F2B_FILTER_DIR`): under `/etc/fail2ban`,
  `/usr/local/etc/fail2ban` or `/opt/fail2ban`
- `ALLOW_DEV_PATHS` (development only) additionally allows `/tmp` and macOS
  temporary directories

`/home`, `/opt` and `/usr/local` as whole trees are not allowed: under
`sudo f2b` they let a filter file name another user's private files as its
logpath.

### Trusted Binary Directories

The sudo-executed binaries (`fail2ban-client`, `fail2ban-regex`,
`fail2ban-server`) must resolve to an FHS directory (`/usr/bin`, `/usr/sbin`,
`/usr/local/bin`, ...), which stops a hostile `PATH` from choosing what sudo
runs. `F2B_TRUSTED_BIN_DIR` may name ONE additional absolute, clean directory
for non-FHS installs. Leave it unset unless fail2ban lives elsewhere: it widens
which binaries f2b will run as root.

### Privilege Escalation Process

1. **Pre-flight Check**: Determine user capabilities before command execution
1. **Context Creation**: Create context with timeout for the operation
1. **Command Classification**: Identify if the operation requires privileges
1. **Escalation**: Add sudo for every command that touches the root-only server
   socket — all `fail2ban-client` subcommands except `-V`/no-args version output
1. **Validation**: Ensure privilege escalation succeeded with timeout protection
1. **Execution**: Run command with appropriate privileges and context
1. **Timeout Handling**: Gracefully handle hanging operations with cancellation
1. **Audit**: Log privileged operations with context information

### Error Handling

When privileges are insufficient, f2b prints one line (wrapped here):

```text
Error: fail2ban operations require sudo privileges. Current user: username (UID: 1000).
Please run with sudo or ensure user is in sudo group
```

## Input Validation

### IP Address Validation

Comprehensive validation prevents injection attacks.
The snippet below is a simplified illustration; the authoritative
implementation is `ValidateIP` in `fail2ban/validation.go`:

```go
func ValidateIP(ip string) error {
    if ip == "" {
        return ErrIPRequiredError
    }

    // Check for valid IPv4 or IPv6 address
    parsed := net.ParseIP(ip)
    if parsed == nil {
        // Don't echo potentially malicious input back in the error
        if containsCommandInjectionPatterns(ip) || len(ip) > constants.MaxIPAddressLength {
            return fmt.Errorf("invalid IP address format")
        }
        return NewInvalidIPError(ip)
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

Prevents directory traversal and command injection. Simplified illustration;
the authoritative implementation is `ValidateJail` in `fail2ban/validation.go`,
which additionally enforces a maximum length of 64 characters, requires the
first character to be a letter or digit, and accepts Unicode letters/digits
plus dash, underscore, and dot:

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

### Path Traversal Protection

Names and paths are checked by different validators.

**Names** (filter and command names) must be local names. `ValidateFilter`
(`fail2ban/validation.go`) and `ValidateCommand` call
`ContainsPathTraversal` (`fail2ban/security_utils.go`), which rejects
URL-encoded separators and traversals (`%2e%2e`, `%2f`, `%5c`), null bytes, and
any name that `filepath.IsLocal` rejects: absolute paths, `..` escapes and the
empty string. `ValidateFilter` then adds length, command-injection and
per-character checks.

```go
func ContainsPathTraversal(input string) bool {
    inputLower := strings.ToLower(input)
    for _, pattern := range []string{"%2e%2e", "%2f", "%5c", "\x00"} {
        if strings.Contains(inputLower, pattern) {
            return true
        }
    }
    if !filepath.IsLocal(input) {
        return true
    }
    cleaned := filepath.Clean(input)
    return strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || cleaned == ".."
}
```

**Paths** (log and filter directories, `--log-file`) go through
`ValidatePathWithSecurity` (`fail2ban/pathsecurity.go`), which canonicalizes the
path, resolves symlinks and requires the result to stay inside one of the
allowed base directories listed under [Allowed Paths](#allowed-paths).

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

`OSRunner.CombinedOutputWithSudoContext` (fail2ban/fail2ban.go) decides per call:

1. Validate the command against the allowlist and its arguments
   (`validateCommandExecution`); an absolute path must sit in a trusted directory.
1. Root runs the command directly.
1. A non-root user with sudo privileges gets `sudo <command> <args...>` only when
   `RequiresSudo` says the command needs it (every fail2ban-client subcommand
   except `-V`, fail2ban-regex, and service control).
1. Otherwise the command runs without sudo.

Every call is an argument array (never a shell string) and is bounded by the
context: on cancellation the child gets SIGTERM, which sudo relays to the
command it started, and `WaitDelay` stops waiting on pipes an orphaned child
still holds.

## Testing Security

### Mock-Only Testing

**Critical Rule**: Never execute real sudo commands in tests

```go
// CORRECT - Use modern standardized helpers with context support
func TestBanCommand_WithPrivileges(t *testing.T) {
    // Mock runner + mock sudo checker; no real command can execute
    client, cleanup := fail2ban.SetupMockEnvironmentWithSudo(t, true)
    defer cleanup()

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    code, err := client.BanIPWithContext(ctx, "192.168.1.100", "sshd")
    require.NoError(t, err)
    assert.Equal(t, 0, code) // 0 = newly banned, 1 = already banned
}
```

### Advanced Security Test Coverage

The system includes comprehensive security testing with extensive sophisticated attack vectors:

Path traversal is tested against the real validator and an allowlist
(`TestPathTraversalDetection` in `fail2ban/fail2ban_path_security_test.go`):

```go
func TestPathTraversalDetection(t *testing.T) {
    maliciousPaths := []string{
        "../../../etc/passwd",
        "/var/log/../../../etc/shadow",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",               // URL encoded ../../../etc/passwd
        "/var/log/\uff0e\uff0e/\uff0e\uff0e/etc/passwd", // Full-width Unicode ..
        "log\x00/../../etc/passwd",                      // Null byte injection
    }

    config := PathSecurityConfig{
        AllowedBasePaths: []string{t.TempDir()},
        MaxPathLength:    4096,
        AllowSymlinks:    false,
        ResolveSymlinks:  true,
    }

    for _, maliciousPath := range maliciousPaths {
        t.Run("malicious_path", func(t *testing.T) {
            if _, err := ValidatePathWithSecurity(maliciousPath, config); err == nil {
                t.Errorf("expected error for malicious path %q, but validation passed", maliciousPath)
            }
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

- [ ] All user input is validated before use
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
  - Windows-style paths on Unix (`/var/log\..\..\..\etc\passwd`)
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

1. **Input Validation**: First line of defense against malicious input
1. **Advanced Path Traversal Protection**: Extensive sophisticated attack vector protection
1. **Privilege Validation**: Ensure user has necessary permissions with timeout protection
1. **Context-Aware Execution**: Use argument arrays with timeout and cancellation support
1. **Safe Execution**: Never use shell strings, always use context-aware operations
1. **Error Handling**: Fail safely without information leakage, include context information
1. **Audit Logging**: Track privileged operations with contextual information
1. **Test Isolation**: Prevent test-time security compromises with comprehensive mocks
1. **Timeout Protection**: Prevent resource exhaustion through hanging operations

### Security Boundaries

```text
User Input → Context → Validation → Path Traversal → Privilege Check → Safe Execution → Timeout → Audit
    ↓          ↓         ↓            ↓               ↓              ↓             ↓        ↓
  Sanitize → Create → Validate → Block Attack → Verify Perms → Exec w/Context → Cancel → Log
```

**Enhanced Security Flow:**

1. **Context Creation**: Establish timeout and cancellation context
1. **Input Sanitization**: Clean and validate all user input
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

Each ban/unban emits a structured audit line through `ContextualLogger.LogBanOperation`
(cmd/logging.go). It goes to stderr as text, or to `--log-file` as one JSON
object per line (wrapped here for reading):

```json
{"timestamp":"2026-10-27T22:53:17.640091297+01:00","level":"info","message":"Ban operation completed",
 "command_path":"f2b ban","service":"f2b","version":"dev","operation":"ban","ip":"192.168.1.100",
 "jail":"sshd","command":"ban","success":true,"duration_ms":12}
```

Failures log `Ban operation failed` at error level with `success: false`.

This comprehensive security model ensures f2b can be used safely in production environments
while maintaining the flexibility needed for effective Fail2Ban management. The enhanced security
features include context-aware timeout handling, sophisticated path traversal protection with
extensive attack vector coverage, argument-array command execution, and comprehensive
audit logging for enterprise-grade security monitoring.
