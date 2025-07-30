# TODO.md

Technical debt and improvements tracker.

## ✅ COMPLETED - CodeRabbit Review Issues (2025-07-30)

All critical issues from PR #9 CodeRabbit review have been resolved:

### High Priority (COMPLETED ✅)

- **Resource leak fixes**: Added proper cleanup with signal handling and error logging
- **Input validation and security**: Enhanced validation with comprehensive security checks
- **Command injection prevention**: Multi-layered argument validation with pattern detection
- **Timeout infrastructure**: Complete context-based timeout support across all operations
- **Error handling standardization**: Consistent error types and messaging from centralized errors.go
- **Silent error handling**: Added proper logging for previously silent errors

### Medium Priority (COMPLETED ✅)

- **String operation optimizations**: Optimized hot path parsing functions
- **File resource management**: Proper cleanup with error logging throughout
- **Code standardization**: Consistent patterns across the entire codebase

## 📈 Current Priorities

### Performance Optimizations (MEDIUM)

- [ ] Memory Usage - Remove legacy log processing, optimize ban record handling
- [ ] Algorithm Efficiency - Improve path validation, add time parsing cache
- [ ] Resource Management - Buffer pooling, proper file handle management

### Quality Issues

- [ ] Global State Elimination - Remove global variables, proper DI patterns
- [ ] Client Initialization - Simplify init, robust version checking
- [ ] Structured Logging - Migrate from logrus to slog

## 🎯 Test Framework (COMPLETED ✅)

**Achievements:** 60-70% code reduction, 168+ tests passing, 5 files converted

- ✅ `CommandTestBuilder` framework - Fluent interface for test creation
- ✅ `MockClientBuilder` pattern - Advanced mock configuration
- ✅ Table test standardization - 63+ field names standardized
- ✅ Error checking consolidation - `AssertError()` helper applied

**Remaining:**

- [ ] Apply framework to specialized test files (fail2ban/*.go)
- [ ] Performance benchmarking integration
- [ ] Test result reporting and analytics

## 🎯 Mock Setup Deduplication (HIGH PRIORITY)

**Target:** 197+ instances across fail2ban test files

**Pattern to Replace:**

```go
// OLD (5-8 lines each):
originalChecker := fail2ban.GetSudoChecker()
defer fail2ban.SetSudoChecker(originalChecker)
mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
// ... more setup

// NEW (2 lines):
mockClient, cleanup := fail2ban.SetupMockEnvironment(t)
defer cleanup()
```

**Target Files:**

- `fail2ban/fail2ban_mock_test.go` (17 instances)
- `fail2ban/fail2ban_fail2ban_test.go` (38 instances)
- `fail2ban/fail2ban_sudo_test.go` (9 instances)
- Other fail2ban test files (remaining instances)

**Estimated:** 590 lines → 118 lines (80% reduction)

## 🔄 Security & Testing

- [ ] Security Testing - Fuzzing, privilege escalation, penetration tests
- [ ] Logging Enhancement - Performance metrics, audit logging, OpenTelemetry
- [ ] Error Message Security - Sanitize sensitive info, configurable verbosity

## 🚀 Future Enhancements

- [ ] Advanced Features - Config commands, bulk operations, export/import
- [ ] Developer Experience - Pre-commit security, auto dependency updates
- [ ] Concurrent Processing - Parallel multi-jail operations
- [ ] Caching & Optimization - Time parsing cache, validation caching

## ✅ Completed (2025)

**Pre-Release Modernization (10/10):** Path traversal protection, thread-safe global state,
race condition fixes, code deduplication, test infrastructure, performance optimizations
(15-26% faster, 39-64% less memory), security hardening, documentation reorganization,
100% linting compliance.

**Test Framework:** Complete cmd package migration with 630 line reduction,
fluent testing interface, mock builder patterns, field name standardization.

## Status Legend

- ✅ COMPLETED  - 🟡 PARTIAL  - 🔴 NOT STARTED
