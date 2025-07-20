# TODO.md

Technical debt and improvements tracker.

## 🚨 Critical Security (IMMEDIATE)

### Security Vulnerabilities ✅/🔴

- [x] **Sudo Timeout** - 5s timeout added to CanUseSudo()
- [x] **Service Injection** - Strict action validation implemented
- [x] **Memory Exhaustion** - Incremental log reading, 1000 lines/100MB limits
- [x] **File Security** - Advanced path traversal protection, symlink prevention
- [x] **Race Conditions** - Thread-safe runner management with RWMutex
- [ ] **Sudo Security Audit** - Review execution paths, dynamic group resolution
- [ ] **Command Injection** - Input sanitization for external commands

## 🔥 High Priority Performance

### Core Performance Issues 🔴/🟡

- [x] **Log Watch** - Memory-efficient streaming implemented
- [x] **Context Support** - All Client/Runner methods support context
- [x] **Memory Limits** - Implemented via LogReadConfig
- [ ] **Ban Record Parsing** - Reduce complexity, extract time parsing logic
- [ ] **Log Performance** - Optimize gzip detection, improve file sorting
- [ ] **Parallel Processing** - Multi-jail operations, worker pools, error aggregation

### Code Quality Issues 🔴

- [ ] **Code Deduplication** - Eliminate ~300 lines of duplicate MockClient/context code
- [ ] **Performance Optimization** - Memory usage and algorithm efficiency improvements
- [ ] **Global State Elimination** - Remove global variables, proper DI patterns

## 🛠️ Medium Priority

### Architecture & Quality ✅/🔴

- [x] **Input Validation** - IP/Jail/Filter validation with IPv6 support
- [x] **Config Management** - Environment variables with validation
- [x] **Documentation** - Comprehensive docs completed
- [x] **Release Automation** - GoReleaser with multi-platform builds, Docker, packages
- [ ] **Error Handling** - Fix silent error swallowing, categorization
- [ ] **Client Initialization** - Simplify init, robust version checking
- [ ] **Test Organization** - Break down large test files (1000+ lines)
- [ ] **Structured Logging** - Migrate from logrus to slog

## 📊 Monitoring & Testing

### Observability 🧪/📊

- [x] **Performance Testing** - 12 benchmarks added
- [x] **Integration Testing** - End-to-end tests implemented
- [ ] **Security Testing** - Fuzzing, privilege escalation, penetration tests
- [ ] **Logging Enhancement** - Performance metrics, audit logging, OpenTelemetry
- [ ] **Error Message Security** - Sanitize sensitive info, configurable verbosity

## 🚀 Future Enhancements

### New Features 🔴

- [ ] **Advanced Features** - Config commands, bulk operations, export/import, notifications
- [ ] **Developer Experience** - Pre-commit security, auto dependency updates, dev automation
- [ ] **Concurrent Processing** - Parallel multi-jail operations with proper synchronization
- [ ] **Caching & Optimization** - Time parsing cache, validation result caching, buffer pooling

## New Critical Items (2025)

### 🔧 Code Quality (HIGH PRIORITY)

- [ ] **MockClient Consolidation** - Remove duplicate implementations in cmd/cmd_test.go
- [ ] **Context Wrapper Generator** - Eliminate ~150 lines of WithContext boilerplate
- [ ] **Validation Centralization** - Single source for IP/jail/filter validation
- [ ] **Error Message Standardization** - Use constants for repeated error strings

### 📈 Performance Optimizations (MEDIUM PRIORITY)

- [ ] **Memory Usage** - Remove legacy log processing, optimize ban record handling
- [ ] **Algorithm Efficiency** - Improve path validation, add time parsing cache
- [ ] **Resource Management** - Buffer pooling, proper file handle management
- [ ] **Test File Organization** - Break down cmd_test.go (1169 lines) and main_test.go (897 lines)

## Status Legend

- ✅ COMPLETED  - 🟡 PARTIAL  - 🔴 NOT STARTED

## Priority Legend

- 🚨 IMMEDIATE: Security vulnerabilities
- 🔥 HIGH: Performance/critical bugs
- 🛠️ MEDIUM: Quality/tech debt
- 📊 MONITORING: Observability
- 🧪 TESTING: Test coverage
- 🚀 FUTURE: Enhancements
