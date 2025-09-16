# Repository Guidelines

Use this guide to contribute effectively to f2b, the Go-based CLI for managing Fail2Ban jails.

## Project Structure & Module Organization

- `main.go` wires logging, sudo detection, and client startup.
- `cmd/` contains Cobra commands and fluent command tests; mirror changes under `cmd.test/` when adding scenarios.
- `fail2ban/` hosts the client interfaces, runners, and mocks used across commands.
- `docs/` centralizes architecture, testing, and security references; keep updates in sync with code changes.

## Build, Test, and Development Commands

- Build the CLI with:
  `go build -ldflags "-X github.com/ivuorinen/f2b/cmd.version=1.2.3" -o f2b .`
  This embeds the release version string in the binary.
- `go test -covermode=atomic -coverprofile=coverage.out ./...` runs the full suite with race-safe coverage metrics.
- `pre-commit run --all-files` applies formatting, linting, and link checks; run before every push.
- `make update-deps` refreshes Go dependencies when coordinating dependency upgrades.

## Coding Style & Naming Conventions

- Follow `.editorconfig`: tabs for Go, two-space indentation elsewhere, max line length 120.
- Format Go code with `gofmt` (automatically enforced by pre-commit); keep package aliases clear and explicit.
- Name tests as `<feature>_test.go` and exported Cobra commands as `New<Feature>Command` for discoverability.
- Keep docs concise and avoid hard-coded numeric claims unless required for accuracy.

## Testing Guidelines

- Use the fluent helpers such as `NewCommandTest` and `NewMockClientBuilder` for CLI coverage.
- Co-locate unit tests with their packages and create `*_integration_test.go` only for integration scenarios.
- Mock sudo interactions with the provided `MockRunner` and `MockSudoChecker`; never issue real sudo.
- Ensure security cases include path traversal, privilege errors, and context timeouts.

## Commit & Pull Request Guidelines

- Write semantic commits (`type(scope): message`) that describe the observable change, such as:
  `feat(cli): add metrics command`.
- Include rationale, testing evidence, and configuration updates in PR descriptions; link issues when relevant.
- Run `pre-commit run --all-files` and `go test ./...` before requesting review and mention the results.
- Keep PRs focused; split large features into reviewable increments and update docs alongside code.

## Security & Configuration Tips

- Validate all user inputs, especially jail names and filesystem paths, before invoking runners.
- Respect privilege boundaries: prefer dependency injection so tests and CLI paths use mocks by default.
- Configure logging through the `F2B_LOG_LEVEL` and `F2B_VERBOSE_TESTS` environment variables for deterministic output.
