# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and releases use [CalVer](https://calver.org/) tags (`YYYY.MM.MICRO`).

______________________________________________________________________

## [Unreleased]

### Added

- Initial public release of `f2b` Go CLI.
- Support for listing jails, banning/unbanning IPs, checking status, viewing logs, testing filters,
  and controlling the Fail2Ban service.
- Configuration via environment variables and CLI flags.
- Basic test suite and CI workflows.
- **Comprehensive sudo privilege management system** for secure fail2ban operations:
  - Automatic detection of root users, sudo group membership, and sudo capabilities
  - Command classification: every `fail2ban-client` subcommand requires sudo (the
    server socket is root-only); only `-V`/no-args version output does not
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
- `AGENTS.md` for LLM/AI agent contribution guidelines.
- Initial `CHANGELOG.md` for tracking releases and changes.
- Comprehensive documentation updates across all markdown files.
- Granular timeout env vars `F2B_COMMAND_TIMEOUT`, `F2B_FILE_TIMEOUT`, and
  `F2B_PARALLEL_TIMEOUT`, replacing the single `F2B_TIMEOUT`.
- Releases attach `THIRD_PARTY_LICENSES.txt`, the license texts of every
  bundled third-party module.
- Release checksums are signed with cosign keyless signing (a `.bundle` next to
  the checksums file).

### Changed

- **BREAKING (for external importers)**: renamed the `shared` package to
  `constants`; the import path changed from `github.com/ivuorinen/f2b/shared`
  to `github.com/ivuorinen/f2b/constants`.
- **Enhanced Runner interface** to support both regular and sudo command execution
- **Updated all fail2ban operations** to use appropriate privilege escalation
- **Improved client initialization** to check sudo requirements upfront
- **Enhanced error messages** for privilege-related failures with actionable hints
- **Comprehensive documentation updates**:
  - Updated README.md with complete feature overview and security guidance
  - Enhanced CONTRIBUTING.md with security and testing guidelines
  - Expanded docs/faq.md with sudo troubleshooting and new features
  - Updated README.md to reflect modern Go implementation
  - Enhanced AGENTS.md with privilege handling guidelines
- Refactored CLI to use dependency injection for all commands.
- Enhanced security and error handling throughout the codebase.
- `NoOpClient` removed in favor of lazy client construction: the real client is
  only built when a command actually needs fail2ban.
- Jail names are now treated as case-sensitive and passed through verbatim,
  matching fail2ban semantics.
- Bumped Go to 1.26.
- Toolchain go1.27.3 (language floor stays `go 1.26`); golangci-lint v2.15.0,
  goreleaser v2.19.0, gosec v2.30.0, prek v0.5.7, and current action pins.
- **Security**: log directories are restricted to `/var/log` and filter
  directories to `/etc/fail2ban`, `/usr/local/etc/fail2ban` and
  `/opt/fail2ban` (`/home`, `/opt`, `/usr/local` trees are no longer allowed),
  because `test-filter` makes root read the filter's logpath.
- goreleaser no longer pushes a Homebrew formula (`brews` removed):
  ivuorinen/homebrew-tap generates it from the release's binaries.
- Releases publish raw binaries (`f2b_<os>-<arch>`) instead of archives, for
  Linux amd64/arm64/armv6/armv7, macOS amd64/arm64 and Windows amd64.
- **BREAKING**: `banned --format json` uses lowercase keys (`jail`, `ip`,
  `banned_at`, `remaining`) like the `ban`/`unban` JSON output.
- **BREAKING (for external importers)**: every `fail2ban.Client` method takes a
  `context.Context` (the context-free twins are gone) and the interface gains
  `GetLogLinesWithLimitContext`. `ContextualLogger.LogOperation` passes the
  enriched context to its callback, `PrintOutput`/`PrintOutputTo` return an
  error, `SetLogger` takes a `LoggerEntry`, `OperationType.MetricsType` is now
  `Operation`, and validators that ignored their context argument no longer
  take one.
- `logs` prints one line per entry (it printed a single Go-formatted slice),
  returns the newest lines across rotated logs, and honors a `--limit` above
  the default.
- A failed write to stdout is returned as the command's error and sets the exit
  status.
- `--log-level` help lists every accepted level.
- Release notes exclude scoped `chore(...)`, `docs(...)` and `test(...)` commits.
- Development tasks and tool pins moved from the Makefile to `mise.toml`, and
  `codex.sh` is removed. The prek hooks and CI workflows run every tool through
  mise, so `mise.toml` is the only version pin.
- Releases use CalVer tags: `mise run release` pushes the next one (from
  gh-calver), and CI builds and signs the release.

### Removed

- Removed the `metrics` command and its performance-metrics subsystem.
- Dropped the `google/uuid` and `hashicorp/go-version` dependencies.
- Release builds for the BSDs, Linux 386/mips64/mips64le/ppc64le/s390x and
  Windows 386/arm64, the `ghcr.io/ivuorinen/f2b` container image, and the
  deb/rpm/apk packages.
- Go API: `HandlePermissionError`, `NewPermissionError` and the unused error
  categories; `ProcessOperation`, `ProcessBanOperation`,
  `ProcessUnbanOperation` and their non-context parallel variants;
  `OutputResults` and `TrimmedOutput`; the package-level `GetLogLines`
  functions, `OptimizedLogProcessor` and the `GzipDetector` type; the
  `RunnerCombinedOutput*` helpers other than the sudo-context one;
  `ConfigureCITestLogging`, `LoggerInterface` and `LogCollectionConfig`; the ban
  record parser's object pools and `GetStats`; the `cmd` wrappers around the
  `fail2ban` context helpers; `ValidateFilterName` (use `ValidateFilter`).

### Security

- **Privilege validation**: All user input validated before privilege escalation
- **Secure command execution**: Uses argument arrays instead of shell string concatenation
- **Test isolation**: Comprehensive mocking prevents accidental privileged operations in tests
- **Principle of least privilege**: Escalates via sudo only for commands that touch the
  root-only fail2ban socket — which is every `fail2ban-client` subcommand except `-V`/no-args
- `--log-file` must be inside the allowed log directories.

### Fixed

- Various minor bug fixes and improved test coverage.
- **Test safety**: Eliminated potential for real sudo execution during testing
- Ban/unban status parsing now follows fail2ban >= 0.11 semantics, correctly
  distinguishing "banned/unbanned" from "already banned/not banned".
- Non-root users with sudo rights now run `fail2ban-client` through sudo; the
  privilege check compared the resolved absolute path against a bare command
  name and never matched.
- A sudoers grant scoped to `fail2ban-client` is accepted (`sudo -n -l fail2ban-client`), not only unrestricted sudo.
- A canceled command no longer blocks on an orphaned child of sudo.
- `ban`, `unban` and `test <ip>` parse the last output line of
  `fail2ban-client`, so warnings on stderr no longer break them.
- `service` and `banned all` honor Ctrl-C and their timeouts; the client is
  built under the caller's context.
- `logs` reports an error when no log file could be read instead of an empty
  result.

______________________________________________________________________
