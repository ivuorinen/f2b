# TODO.md

This document tracks technical debt, improvements, and issues identified through code analysis.

## 🚨 Critical Security Issues (Priority: IMMEDIATE)

### 0. NEW: Sudo Command Timeout Vulnerability

**File:** `fail2ban/sudo.go`
**Lines:** 87-96

- [ ] **URGENT: Add timeout handling for sudo commands**
- [ ] Implement context.WithTimeout for CanUseSudo() function
- [ ] Add 5-second timeout to prevent hanging processes
- [ ] Consider retry logic for transient failures
- [ ] Add logging for timeout scenarios

```go
func (r *RealSudoChecker) CanUseSudo() bool {
    if isTest() {
        return false
    }

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    cmd := exec.CommandContext(ctx, "sudo", "-n", "true")
    err := cmd.Run()
    return err == nil
}
```

### 1. Sudo Command Execution Security Review

**File:** `fail2ban/sudo.go`
**Lines:** 87-96, 131-160, 64-84

- [ ] **Security audit** of all sudo command execution paths
- [ ] Review `CanUseSudo()` function for command injection vulnerabilities (lines 87-96)
- [ ] Replace hardcoded group ID checks in `InSudoGroup()` with dynamic group resolution (lines 64-84)
- [ ] Audit `RequiresSudo()` complex conditional logic for edge cases (lines 131-160)
- [ ] Consider sandboxing or additional validation for sudo path manipulation
- [ ] Add comprehensive security tests for privilege escalation scenarios

### 2. External Command Execution Hardening

**File:** `fail2ban/fail2ban.go`
**Lines:** 56-78, 314, 352, 375, 404, 568, 602

- [ ] **Input sanitization review** for all external command calls
- [ ] Audit `OSRunner` methods for command injection risks (lines 56-78)
- [ ] Review fail2ban-client command execution points (lines 314, 352, 375, 404)
- [ ] Secure fail2ban-regex execution in filter testing (lines 568, 602)
- [ ] Implement argument validation before command execution
- [ ] Add command execution logging for security monitoring

### 3. Path Traversal Protection Enhancement 🟡 **PARTIALLY COMPLETED**

**File:** `fail2ban/fail2ban.go`
**Lines:** 572-604, 607-620

- [x] ✅ Basic path traversal protection implemented in `isValidFilter()`
- [x] ✅ Character validation for filter names
- [ ] Add fuzzing tests for filter name validation
- [ ] Implement additional path canonicalization checks
- [ ] Consider allowlist-based approach for filter names
- [ ] Add null byte and dangerous character checks

**Recommended Enhancement:**

```go
func isValidFilter(filter string) bool {
    if filter == "" {
        return false
    }

    // Check for dangerous characters including null bytes
    if strings.ContainsAny(filter, "/\\\x00") {
        return false
    }

    // Use allowlist approach
    matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, filter)
    return matched && len(filter) <= 64
}
```

## 🔥 High Priority Performance & Complexity Issues

### 4. Ban Record Parsing Complexity Reduction

**File:** `fail2ban/fail2ban.go`
**Lines:** 390-458

- [ ] **Refactor `GetBanRecords()`** to reduce cyclomatic complexity
- [ ] Break down complex time parsing logic (lines 418-449) into separate functions
- [ ] Extract ban record format parsing into dedicated parsers
- [ ] Add comprehensive unit tests for all parsing edge cases
- [ ] Consider using a state machine for format detection
- [ ] Improve error handling and reporting for parsing failures

### 5. Log Processing Performance Optimization

**File:** `fail2ban/logs.go`
**Lines:** 46-68, 119-159

- [ ] **Optimize gzip detection** and file handling (lines 119-159)
- [ ] Improve log file sorting and numbering logic (lines 46-68)
- [ ] Add memory usage limits for large log file processing
- [ ] Implement streaming processing for large files
- [ ] Add performance benchmarks for log operations
- [ ] Consider using file system notifications instead of polling

### 6. Log Watch Performance Critical Fix ⚠️ **CRITICAL - PRODUCTION BLOCKING**

**File:** `cmd/logswatch.go`
**Lines:** 42-61

- [ ] **URGENT: Implement incremental log reading** instead of full file reads
- [ ] Replace inefficient `equal()` comparison (lines 55-58)
- [ ] Add file position tracking for tail-like functionality
- [ ] Implement memory-efficient log streaming
- [ ] Add configurable polling intervals
- [ ] Consider using inotify/fsnotify for real-time updates

**Impact:** Current implementation reads entire log files on every poll, causing:

- O(n) memory growth with log file size
- Unusable performance for production log files
- Potential system resource exhaustion

**Recommended Fix:**

```go
type LogWatcher struct {
    lastPosition int64
    lastSize     int64
}

func (w *LogWatcher) ReadNewLines(filepath string) ([]string, error) {
    // Implementation with file position tracking
}
```

## 🛠️ Medium Priority Improvements

### 7. Error Handling Consistency 🟡 **PARTIALLY COMPLETED**

**File:** `fail2ban/fail2ban.go`
**Lines:** 405-407, 424-443

- [x] ✅ Improved error logging with structured logging (logrus)
- [x] ✅ Better error context in ban record parsing
- [ ] **Fix silent error swallowing** in `GetBanRecords()` (lines 405-407)
- [ ] Implement error aggregation instead of fail-fast behavior
- [ ] Standardize error reporting across similar operations
- [ ] Consider implementing retry logic for transient failures
- [ ] Add error categorization (permanent vs temporary failures)

### 8. Client Initialization Robustness

**File:** `fail2ban/client.go`
**Lines:** 57-101

- [ ] **Simplify complex initialization sequence**
- [ ] Make version checking more robust (lines 84-94)
- [ ] Add timeout handling for external command dependencies
- [ ] Implement graceful degradation for optional features
- [ ] Add initialization health checks
- [ ] Consider lazy initialization for expensive operations

### 9. Input Validation Standardization 🟡 **PARTIALLY COMPLETED**

**File:** `fail2ban/fail2ban.go`
**Lines:** 622-637, 639-662

- [x] ✅ IP address validation implemented (`isValidIP()` function)
- [x] ✅ Jail name validation implemented (`isValidJail()` function)
- [x] ✅ Filter name validation implemented (`isValidFilter()` function)
- [x] ✅ IPv6 validation included
- [ ] Make hardcoded limits (64-char) configurable
- [ ] Add comprehensive input validation tests
- [ ] Implement consistent validation error messages

### 10. Parallel Processing Implementation 🔴 **NOT STARTED - HIGH PRIORITY**

**File:** `cmd/ban.go`
**Lines:** 43-59

- [ ] **Implement parallel jail processing** for ban operations
- [ ] Add worker pool pattern for multiple jail operations
- [ ] Implement error aggregation for parallel operations
- [ ] Add configurable concurrency limits
- [ ] Consider rate limiting for external commands
- [ ] Add progress reporting for long-running operations

**Recommended Implementation:**

```go
func (c *RealClient) BanIPParallel(ip string, jails []string) ([]BanResult, error) {
    sem := make(chan struct{}, 5) // Limit concurrency
    resultChan := make(chan BanResult, len(jails))

    for _, jail := range jails {
        go func(jail string) {
            sem <- struct{}{}
            defer func() { <-sem }()

            result, err := c.BanIP(ip, jail)
            resultChan <- BanResult{Jail: jail, Result: result, Error: err}
        }(jail)
    }

    // Collect results...
}
```

## 🔧 Technical Debt & Architecture Improvements

### 11. Global State Elimination

**File:** `fail2ban/fail2ban.go`
**Lines:** 30-44, 81-89

- [ ] **Remove global variables** for log and filter directories (lines 30-44)
- [ ] Replace global runner with dependency injection (lines 81-89)
- [ ] Implement proper dependency injection pattern
- [ ] Improve testability by removing global state
- [ ] Add configuration management system
- [ ] Consider using context.Context for request-scoped data

### 12. Test Code Organization 🟡 **PARTIALLY COMPLETED**

**Files:** `fail2ban/fail2ban_test.go` (1,169 lines), `main_test.go` (897 lines)

- [x] ✅ Integration tests separated into `integration_test.go`
- [x] ✅ Mock utilities extracted and improved
- [x] ✅ Test naming and documentation improved
- [ ] **Break down large test files** into focused unit tests (still >500 lines)
- [ ] Organize tests by functionality rather than file structure
- [ ] Add property-based testing for complex functions

**Current Status:** Files are still too large for maintainability

### 13. Configuration Management ✅ **COMPLETED**

**File:** `cmd/config_utils.go`

- [x] ✅ **Comprehensive configuration system implemented**
- [x] ✅ Environment variable support with defaults
- [x] ✅ Configuration validation implemented
- [x] ✅ Configuration documentation added
- [x] ✅ Configuration inheritance and overrides working
- [ ] Add configuration file support (YAML/TOML) - enhancement
- [ ] Add configuration migration system - enhancement

## 📊 Monitoring & Observability

### 14. Logging and Monitoring Enhancement

- [ ] **Add structured logging** throughout the application
- [ ] Implement performance metrics collection
- [ ] Add command execution timing and monitoring
- [ ] Implement audit logging for security operations
- [ ] Add health check endpoints
- [ ] Consider adding OpenTelemetry integration

### 15. Documentation Improvements ✅ **COMPLETED**

- [x] ✅ **Comprehensive API documentation added**
- [x] ✅ Security considerations and best practices documented
- [x] ✅ Troubleshooting guides added (FAQ.md)
- [x] ✅ Performance characteristics documented
- [x] ✅ Developer setup guides created (CLAUDE.md, AGENTS.md)
- [ ] Add architecture decision records (ADRs) - enhancement

## 🧪 Testing Improvements

### 16. Security Testing 🔴 **NOT STARTED - CRITICAL**

- [ ] **Add comprehensive security test suite**
- [ ] Implement fuzzing tests for input validation
- [ ] Add privilege escalation tests
- [ ] Test command injection scenarios
- [ ] Add penetration testing automation
- [ ] Implement security regression tests

**Priority raised due to security vulnerabilities found in analysis.**

### 17. Performance Testing ✅ **COMPLETED**

- [x] ✅ **Performance benchmarks added** for critical paths (12 benchmark functions)
- [x] ✅ Benchmarks cover argument parsing, main logic, sudo checking, service commands
- [x] ✅ Memory usage profiling included in benchmarks
- [x] ✅ Testing with various dataset sizes
- [ ] Add performance regression detection - enhancement
- [ ] Implement continuous performance monitoring - enhancement

### 18. Integration Testing ✅ **COMPLETED**

- [x] ✅ **End-to-end integration tests added**
- [x] ✅ Tests with real fail2ban instances implemented
- [x] ✅ Cross-platform compatibility tests added
- [x] ✅ Privilege scenarios tested comprehensively
- [x] ✅ Integration test suite comprehensive
- [ ] Add chaos engineering tests - enhancement
- [ ] Implement contract testing - enhancement

## 🆕 New Critical Issues (From Recent Analysis)

### 21. Context Support Implementation

**Priority:** 🚨 **IMMEDIATE**
**Files:** All command files in `cmd/`

- [ ] **Add context.Context support** to all command operations
- [ ] Implement timeout handling for external command execution
- [ ] Add cancellation support for long-running operations
- [ ] Implement proper context propagation
- [ ] Add context-aware logging

### 22. Memory Usage Limits

**Priority:** 🔥 **HIGH**
**File:** `fail2ban/logs.go`

- [ ] **Implement memory limits** for log processing
- [ ] Add streaming processing for large files
- [ ] Implement backpressure handling
- [ ] Add memory usage monitoring
- [ ] Consider memory-mapped file access for large logs

### 23. Structured Logging Migration

**Priority:** 🛠️ **MEDIUM**
**Files:** All files using logrus

- [ ] **Migrate from logrus to slog** (Go 1.21+)
- [ ] Implement structured logging throughout
- [ ] Add log level configuration
- [ ] Implement log rotation
- [ ] Add audit logging for security operations

## 🚀 Future Enhancements

### 19. Feature Improvements

- [ ] **Add configuration management commands**
- [ ] Implement jail configuration validation
- [ ] Add bulk operations support
- [ ] Implement export/import functionality
- [ ] Add notification system integration
- [ ] Consider web UI or API interface

### 20. Developer Experience

- [ ] **Improve development workflow**
- [ ] Add pre-commit hooks for security checks
- [ ] Implement automated dependency updates
- [ ] Add code quality gates
- [ ] Improve debugging capabilities
- [ ] Add development environment automation

---

## Priority Legend

- 🚨 **IMMEDIATE**: Security vulnerabilities, data loss risks
- 🔥 **HIGH**: Performance issues, critical bugs
- 🛠️ **MEDIUM**: Quality improvements, technical debt
- 🔧 **LOW**: Architecture improvements, nice-to-have features
- 📊 **MONITORING**: Observability and maintenance
- 🧪 **TESTING**: Test improvements and coverage
- 🚀 **FUTURE**: Enhancement and new features

## Status Legend

- ✅ **COMPLETED**: Item fully implemented and working
- 🟡 **PARTIALLY COMPLETED**: Some progress made, needs finishing
- 🔴 **NOT STARTED**: No implementation, needs immediate attention
- 🆕 **NEW**: Recently identified issues from analysis

## Recent Analysis Summary (2025-07-15)

**Completed Items:** 4 major items (Configuration Management, Documentation, Performance Testing, Integration Testing)
**Partially Completed:** 4 items (Path Traversal Protection, Input Validation, Error Handling, Test Organization)
**Critical Issues Added:** 3 new critical issues (Context Support, Memory Limits, Sudo Timeouts)
**Security Priority:** Elevated due to new vulnerability discoveries

## Contributing

When working on items from this TODO list:

1. Create an issue referencing the specific TODO item
2. Include security impact assessment for security-related items
3. Add comprehensive tests for any changes
4. Update documentation as needed
5. Consider backward compatibility implications
6. **For 🚨 IMMEDIATE items**: Get security review before merging
7. **For 🔥 HIGH items**: Add performance benchmarks
8. **For completed items**: Update status in this file
