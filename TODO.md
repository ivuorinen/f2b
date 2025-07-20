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

## 📚 Documentation Reorganization ✅ FULLY COMPLETED

### File Organization

- [x] **Move FAQ.md** - Move FAQ.md to docs/faq.md and update all references ✅ COMPLETED
- [x] **Move CODE_OF_CONDUCT.md** - Move from .github/ to root directory ✅ COMPLETED
- [x] **Create docs/architecture.md** - Extract architecture content from README.md and CLAUDE.md ✅ COMPLETED
- [x] **Create docs/testing.md** - Consolidate testing guidelines from multiple files ✅ COMPLETED
- [x] **Create docs/security.md** - Consolidate security practices from multiple files ✅ COMPLETED

### Content Updates

- [x] **Update README.md links** - Fix broken relative paths and add links to new docs ✅ COMPLETED
- [x] **Update CLAUDE.md** - Remove duplicated content, add references to detailed docs ✅ COMPLETED
- [x] **Update AGENTS.md** - Remove duplicated content, reference new specialized docs ✅ COMPLETED
- [x] **Update CONTRIBUTING.md** - Remove duplicated patterns, reference new docs ✅ COMPLETED
- [x] **Update copilot-instructions.md** - Reference new documentation structure ✅ COMPLETED
- [x] **Update bug_report.md template** - Customize for CLI tool context ✅ COMPLETED
- [x] **Review code documentation** - Check godoc comments for accuracy ✅ COMPLETED
- [x] **Remove duplication** - Eliminate redundant content across all files ✅ COMPLETED

### Code Quality & Linting

- [x] **Add line length limits** - 120-character limit enforced via EditorConfig ✅ COMPLETED
- [x] **Enable comprehensive linting** - golines, lll, usetesting, gosec, revive ✅ COMPLETED
- [x] **Fix all revive issues** - 86 issues resolved (unused parameters, export comments) ✅ COMPLETED
- [x] **Fix security issues** - File permissions 0644→0600, gosec warnings ✅ COMPLETED
- [x] **Update testing patterns** - Replace os.Setenv with t.Setenv ✅ COMPLETED
- [x] **Configure auto-fix** - golangci-lint with formatters and auto-fix ✅ COMPLETED
- [x] **Enhance pre-commit** - Comprehensive hooks and improved configuration ✅ COMPLETED

## New Critical Items (2025)

### 🔧 Code Quality (HIGH PRIORITY)

- [x] **MockClient Consolidation** - Remove duplicate implementations in cmd/cmd_test.go ✅ COMPLETED
- [x] **Context Wrapper Generator** - Eliminate ~150 lines of WithContext boilerplate ✅ COMPLETED
- [x] **Validation Centralization** - Single source for IP/jail/filter validation ✅ COMPLETED
- [x] **Error Message Standardization** - Use constants for repeated error strings ✅ COMPLETED

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
