# AGENTS Guidelines

## Purpose

Define clear instructions so AI or human contributors keep changes consistent and easy to review. Keep commits small and messages short.

## Commit Rules

- **Semantic Commits**: use `type(scope): message` (for example `feat(cli): add ban command`). Match PR titles to this style.
- **Formatting**: run `go fmt ./...` and `goimports -w .` before committing.
- **Linting**: read `.golangci.yml` and `.editorconfig` before changing code. Run `golangci-lint run` for any code change and correct all issues across the project, not just touched files. Use additional static analysis tools if needed.
- **Tests**: run `go test ./...` after linting whenever code changes. Skip when editing comments or docs only.
- **Package Manager**: always use `yarn` if installing npm packages.

## Best Practices

- Match the project's Go style and configurations.
- Fix lint warnings or formatting issues on all reported files, not just the ones modified.
- Keep PRs focused and well described.

