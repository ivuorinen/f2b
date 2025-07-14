# TODO.md

This document tracks technical debt, improvements, and issues identified through code analysis.

## 🚨 Critical Security Issues (Priority: IMMEDIATE)

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

### 3. Path Traversal Protection Enhancement

**File:** `fail2ban/fail2ban.go`
**Lines:** 572-604, 607-620

- [ ] **Comprehensive path traversal testing** and verification
- [ ] Strengthen `isValidFilter()` validation (lines 607-620)
- [ ] Review filter file reading security in `TestFilter()` (lines 572-604)
- [ ] Add fuzzing tests for filter name validation
- [ ] Implement additional path canonicalization checks
- [ ] Consider allowlist-based approach for filter names

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

### 6. Log Watch Performance Critical Fix

**File:** `cmd/logswatch.go`
**Lines:** 42-61

- [ ] **URGENT: Implement incremental log reading** instead of full file reads
- [ ] Replace inefficient `equal()` comparison (lines 55-58)
- [ ] Add file position tracking for tail-like functionality
- [ ] Implement memory-efficient log streaming
- [ ] Add configurable polling intervals
- [ ] Consider using inotify/fsnotify for real-time updates

## 🛠️ Medium Priority Improvements

### 7. Error Handling Consistency

**File:** `fail2ban/fail2ban.go`
**Lines:** 405-407, 424-443

- [ ] **Fix silent error swallowing** in `GetBanRecords()` (lines 405-407)
- [ ] Implement error aggregation instead of fail-fast behavior
- [ ] Standardize error reporting across similar operations
- [ ] Add context to error messages for better debugging
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

### 9. Input Validation Standardization

**File:** `fail2ban/fail2ban.go`
**Lines:** 622-637, 639-662

- [ ] **Standardize IP address validation** handling (lines 622-637)
- [ ] Review jail name validation constraints (lines 639-662)
- [ ] Make hardcoded limits (64-char) configurable
- [ ] Add comprehensive input validation tests
- [ ] Implement consistent validation error messages
- [ ] Consider IPv6 validation improvements

### 10. Parallel Processing Implementation

**File:** `cmd/ban.go`
**Lines:** 43-59

- [ ] **Implement parallel jail processing** for ban operations
- [ ] Add worker pool pattern for multiple jail operations
- [ ] Implement error aggregation for parallel operations
- [ ] Add configurable concurrency limits
- [ ] Consider rate limiting for external commands
- [ ] Add progress reporting for long-running operations

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

### 12. Test Code Organization

**Files:** `fail2ban/fail2ban_test.go` (1,169 lines), `main_test.go` (961 lines)

- [ ] **Break down large test files** into focused unit tests
- [ ] Extract common test utilities and helpers
- [ ] Organize tests by functionality rather than file structure
- [ ] Add integration test separation
- [ ] Improve test naming and documentation
- [ ] Add property-based testing for complex functions

### 13. Configuration Management

**File:** `cmd/config_utils.go`

- [ ] **Implement comprehensive configuration system**
- [ ] Add configuration file support (YAML/TOML)
- [ ] Implement configuration validation
- [ ] Add configuration documentation
- [ ] Support configuration inheritance and overrides
- [ ] Add configuration migration system

## 📊 Monitoring & Observability

### 14. Logging and Monitoring Enhancement

- [ ] **Add structured logging** throughout the application
- [ ] Implement performance metrics collection
- [ ] Add command execution timing and monitoring
- [ ] Implement audit logging for security operations
- [ ] Add health check endpoints
- [ ] Consider adding OpenTelemetry integration

### 15. Documentation Improvements

- [ ] **Add comprehensive API documentation**
- [ ] Document security considerations and best practices
- [ ] Add troubleshooting guides
- [ ] Document performance characteristics
- [ ] Add architecture decision records (ADRs)
- [ ] Create developer setup guides

## 🧪 Testing Improvements

### 16. Security Testing

- [ ] **Add comprehensive security test suite**
- [ ] Implement fuzzing tests for input validation
- [ ] Add privilege escalation tests
- [ ] Test command injection scenarios
- [ ] Add penetration testing automation
- [ ] Implement security regression tests

### 17. Performance Testing

- [ ] **Add performance benchmarks** for critical paths
- [ ] Implement load testing for log processing
- [ ] Add memory usage profiling
- [ ] Test with large datasets
- [ ] Add performance regression detection
- [ ] Implement continuous performance monitoring

### 18. Integration Testing

- [ ] **Add end-to-end integration tests**
- [ ] Test with real fail2ban instances
- [ ] Add cross-platform compatibility tests
- [ ] Test privilege scenarios comprehensively
- [ ] Add chaos engineering tests
- [ ] Implement contract testing

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

## Contributing

When working on items from this TODO list:

1. Create an issue referencing the specific TODO item
2. Include security impact assessment for security-related items
3. Add comprehensive tests for any changes
4. Update documentation as needed
5. Consider backward compatibility implications
