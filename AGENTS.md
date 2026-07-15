# Repository Guidelines

Use this guide to contribute effectively to f2b, the Go-based CLI for managing Fail2Ban jails.

## Project Structure & Module Organization

- `main.go` wires logging, sudo detection, and client startup.
- `cmd/` contains Cobra commands and fluent command tests.
  Mirror changes under `cmd/*_test.go` when adding scenarios.
- `fail2ban/` hosts the client interfaces, runners, and mocks used across commands.
- `constants/` holds shared constants (`package constants`) used across `cmd` and `fail2ban`.
- `docs/` centralizes architecture, testing, and security references; keep updates in sync with code changes.

## Build, Test, and Development Commands

- Build the CLI with:
  `go build -ldflags "-X github.com/ivuorinen/f2b/cmd.Version=1.2.3" -o f2b .`
  This embeds the release version string in the binary.
- Run tests with coverage:
  `go test -covermode=atomic -coverprofile=coverage.out ./...`
  This generates a coverage profile with race-safe metrics.
- `pre-commit run --all-files` applies formatting, linting, and link checks; run before every push.
- `make update-deps` refreshes Go dependencies when coordinating dependency upgrades.

## Coding Style & Naming Conventions

- Follow `.editorconfig`: tabs for Go, two-space indentation elsewhere, max line length 120.
- Format Go code with `gofmt` (automatically enforced by pre-commit); keep package aliases clear and explicit.
- Name tests as `<feature>_test.go` and exported Cobra command constructors as
  `<Feature>Cmd` (e.g. `BanCmd`, `StatusCmd`) for discoverability.
- Keep docs concise and avoid hard-coded numeric claims unless required for accuracy.

## Testing Guidelines

- Use the fluent helpers such as `NewCommandTest` and `NewMockClientBuilder` for CLI coverage.
- Co-locate unit tests with their packages and create `*_integration_test.go` only for integration scenarios.
- Mock sudo interactions with the provided `MockRunner` and `MockSudoChecker`; never issue real sudo.
- Ensure security cases include path traversal, privilege errors, and context timeouts.

## Commit & Pull Request Guidelines

- Write semantic commits (`type(scope): message`) that describe the observable change, such as:
  `feat(cli): add logs-watch command`.
- Include rationale, testing evidence, and configuration updates in PR descriptions; link issues when relevant.
- Run `pre-commit run --all-files` and `go test ./...` before requesting review and mention the results.
- Keep PRs focused; split large features into reviewable increments and update docs alongside code.

## Agent Context Discipline (context-mode)

- Coding agents MUST route read/inspect work through the context-mode tools —
  `ctx_execute` / `ctx_batch_execute` for shell output (searches, git reads, test/build/lint
  output, anything with unpredictable size) and `ctx_execute_file` for analyzing file
  contents — so raw bytes stay in the sandbox and only derived answers enter context.
- Plain Bash is reserved for state mutations (git writes, `mkdir`/`rm`/`mv`/`cp`,
  installs) and tiny fixed outputs. If raw Bash output is genuinely required, append
  `# ctx-ok` to the command.
- Direct file `Read` is only for files you are about to edit; analysis and extraction
  go through `ctx_execute_file`.
- Enforcement: the context-mode plugin's PreToolUse hook blocks non-conforming Bash
  calls. Agents without the plugin follow this section as written.

## Security & Configuration Tips

- Validate all user inputs, especially jail names and filesystem paths, before invoking runners.
- Respect privilege boundaries: prefer dependency injection so tests and CLI paths use mocks by default.
- Configure logging through the `F2B_LOG_LEVEL` environment variable.
  Use `F2B_VERBOSE_TESTS` to enable verbose test output.
