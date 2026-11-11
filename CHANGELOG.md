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
- Consistent output and error handling using log/slog and helpers.
- Pagination/tailing for logs with `--limit` flag.
- JSON output for all commands via `--format=json`.
- Extensive input validation for all user-supplied data.
- Modular, testable architecture with dependency injection.
- `AGENTS.md` for LLM/AI agent contribution guidelines.
- Initial `CHANGELOG.md` for tracking releases and changes.
- Comprehensive documentation updates across all markdown files.
- Granular timeout env vars `F2B_COMMAND_TIMEOUT`, `F2B_FILE_TIMEOUT`, and
  `F2B_PARALLEL_TIMEOUT`, replacing the single `F2B_TIMEOUT`.
- `F2B_TRUSTED_BIN_DIR` to trust one extra directory for the sudo-executed
  fail2ban binaries (non-FHS installs).
- Releases attach `THIRD_PARTY_LICENSES.txt`, the license texts of every
  bundled third-party module.
- Release checksums are signed with cosign keyless signing (a `.bundle` next to
  the checksums file).
- Commit-message hooks rejecting non-semantic subjects and Claude session links.
- `ban` and `unban` accept a CIDR range (`f2b ban 198.51.100.0/24`). fail2ban
  bans a range as one entry, and unbanning a range also removes every banned
  address inside it. `test` stays address-only.

### Changed

- **BREAKING (for external importers)**: `BanRecordParser`,
  `NewBanRecordParser` and its `ParseBanRecordLine` method are removed;
  `ParseBanRecords` is a plain function. `PathSecurityConfig.ResolveSymlinks`
  is removed: symlinks are always resolved before the base check.
- **BREAKING (for external importers)**: the test doubles (`MockClient`,
  `MockRunner`, `MockSudoChecker`, `SetupMockEnvironment*`, `WithTestRunner`,
  `StandardMockSetup`, `MustMock*`, `AssertError`) moved from `fail2ban` to
  the test-only `fail2ban/fail2bantest` package, and their helpers take
  `testing.TB` (`TestingInterface` is gone).
- The vendored graphify skill is pinned to the version it was reviewed at
  (0.9.16), and its PATH-resolved `hook-guard` hooks are removed.
- **BREAKING**: `test-filter` takes an optional log file as its second argument,
  because stock filters declare no logpath; the `Client` method gained a
  `logFile` parameter. The `Runner` interface is reduced to
  `CombinedOutputWithSudoContext`, and `ServiceCmd` takes a `Runner`.
- `logs` and `logs-watch` fail when the log directory holds no fail2ban log,
  instead of printing nothing and exiting 0.
- `logs-watch --format json` prints an array of lines per batch, as `logs` does.
- Every command except `completion` rejects surplus positional arguments.
- `banned` reports `permanent` for bans that never expire.
- `service` calls are bounded by the 10-minute command ceiling.
- A failed command prints one error on the terminal; the structured record is
  kept only when logs go to a `--log-file`.
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
- Logging migrated from logrus to the standard library's `log/slog`.
- Toolchain go1.27.4 (language floor stays `go 1.26`); golangci-lint v2.15.0,
  goreleaser v2.19.0, gosec v2.30.0, prek v0.5.7, and current action pins.
- **Security**: log directories are restricted to `/var/log` and filter
  directories to `/etc/fail2ban`, `/usr/local/etc/fail2ban` and
  `/opt/fail2ban` (`/home`, `/opt`, `/usr/local` trees are no longer allowed),
  because `test-filter` makes root read the filter's logpath.
- goreleaser no longer pushes a Homebrew formula (`brews` removed):
  ivuorinen/homebrew-tap generates it from the release's binaries.
- Releases publish raw binaries (`f2b_<os>-<arch>`) instead of archives, for
  Linux amd64/arm64/armv6/armv7, macOS amd64/arm64 and Windows amd64.
- **BREAKING**: the `metrics` command removal (refactor in cb292a3) was not
  marked breaking in its commit.
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
- `mise run test-cov` also reports branch coverage per package with `gobco`.
- Releases use CalVer tags: `mise run release` pushes the next one (from
  gh-calver), and CI builds and signs the release.

### Removed

- `F2B_VERBOSE_TESTS` and the CI log quieting it overrode, which never took
  effect on a real run.
- `BoundedTimeCache`, `FastTimeCache` and their constants, `SetLogDir`/`GetLogDir`,
  `GetDangerousCommandPatterns`, `RunnerCombinedOutputWithSudoContext`, `IsCI`,
  and the allowlist entry for `fail2ban-server`, which nothing executes.
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

- An empty path allowlist refuses every path; it used to mean no restrictions.
- The vendored graphify skill no longer sends documents to Gemini when
  `GEMINI_API_KEY` or `GOOGLE_API_KEY` is set, runs extraction subagents with
  only Read and Write, passes questions, answers and node labels to the shell
  in quoted heredocs, and takes the Neo4j password from `NEO4J_PASSWORD`
  instead of the command line.
- The project settings no longer pre-approve the context-mode code execution
  tools, and `git commit` and `git push` always ask.
- Pull requests to `main` require the PR Lint and prek checks, and two unused
  repository secrets are removed.
- Path validation resolves every path component, so a symlinked ancestor can no
  longer carry a path outside the allowlist.
- `--log-file` is resolved in full and opened through an `os.Root` anchored at
  its allowed log base, so neither a leaf symlink nor a directory swapped for a
  symlink can redirect it outside the allowlist; a leaf symlink to a file inside
  the allowlist opens.
- Plain `logs`, `logs-watch` and `test-filter` output shows control characters
  from log lines as `\xHH` escapes instead of passing them to the terminal.
- `sudo`, `fail2ban-regex`, `service` and `systemctl` are resolved to trusted
  absolute paths, as `fail2ban-client` already was.
- `ALLOW_DEV_PATHS` is parsed as a boolean; `0` and `false` no longer enable it.
- `test-filter` records the filter and log path it reads as root.
- When f2b runs as root, `test-filter` reads the log through the allowlisted
  directory and hands fail2ban-regex a private copy, so swapping the file for a
  symlink after validation no longer makes root read another file.
- The release workflow runs lint and tests before publishing, and pull requests
  check the title and commit messages and run `govulncheck`.
- Test fixtures no longer contain publicly routable IP addresses.
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
- `banned` lists CIDR ranges banned through `fail2ban-client`, in `--format json`
  as the `ip` value; they were dropped from the output.
- `banned` reports an error when fail2ban lists bans for a jail and none can be
  read (for example, bans on a non-address ID) instead of showing no bans. In
  `banned all`, the other jails are still listed.
- After a run with `--log-file`, `Logger` writes to stderr again instead of the
  closed file, so later `Execute` runs in the same process keep their logs.

______________________________________________________________________
