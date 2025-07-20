# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- Initial public release of `f2b` Go CLI.
- Support for listing jails, banning/unbanning IPs, checking status, viewing logs, testing filters,
  and controlling the Fail2Ban service.
- Configuration via environment variables and CLI flags.
- Basic test suite and CI workflows.
- **Comprehensive sudo privilege management system** for secure fail2ban operations:
  - Automatic detection of root users, sudo group membership, and sudo capabilities
  - Smart command classification (which commands require sudo vs. read-only)
  - Automatic sudo escalation for privileged operations when user has permissions
  - Clear error messages with helpful hints when sudo privileges are missing
  - Support for testing with comprehensive mock sudo checkers
- Shell completion command for bash, zsh, fish, and PowerShell.
- Command aliases for common commands (`list-jails`, `ban`, `unban`, `status`).
- Log level configuration via `--log-level` flag and `F2B_LOG_LEVEL` env var.
- Log file output support via `--log-file` flag and `F2B_LOG_FILE` env var.
- Consistent output and error handling using logrus and helpers.
- Pagination/tailing for logs with `--limit` flag.
- JSON output for all commands via `--format=json`.
- Extensive input validation for all user-supplied data.
- Modular, testable architecture with dependency injection.
- `.github/AGENTS.md` for LLM/AI agent contribution guidelines.
- Initial `CHANGELOG.md` for tracking releases and changes.
- Comprehensive documentation updates across all markdown files.

### Changed

- **Enhanced Runner interface** to support both regular and sudo command execution
- **Updated all fail2ban operations** to use appropriate privilege escalation
- **Improved client initialization** to check sudo requirements upfront
- **Enhanced error messages** for privilege-related failures with actionable hints
- **Comprehensive documentation updates**:
  - Updated README.md with complete feature overview and security guidance
  - Enhanced CONTRIBUTING.md with security and testing guidelines
  - Expanded docs/faq.md with sudo troubleshooting and new features
  - Updated .github/README.md to reflect modern Go implementation
  - Enhanced .github/AGENTS.md with privilege handling guidelines
- Refactored CLI to use dependency injection for all commands.
- Enhanced security and error handling throughout the codebase.

### Security

- **Privilege validation**: All user input validated before privilege escalation
- **Secure command execution**: Uses argument arrays instead of shell string concatenation
- **Test isolation**: Comprehensive mocking prevents accidental privileged operations in tests
- **Principle of least privilege**: Only escalates privileges when required for specific commands

### Fixed

- Various minor bug fixes and improved test coverage.
- **Test safety**: Eliminated potential for real sudo execution during testing

---
