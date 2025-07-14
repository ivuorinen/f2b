# Contributing to f2b

Thank you for your interest in contributing to **f2b**! Your help is appreciated,
whether you are fixing bugs, adding features, improving documentation, or helping others.

---

## How to Contribute

### 1. Open an Issue

- **Bugs:** Please include steps to reproduce, expected vs. actual behavior, and your environment.
- **Feature Requests:** Describe the problem you want to solve and your proposed solution.
- **Questions:** If you’re unsure about something, open an issue for discussion.

### 2. Fork and Branch

- Fork the repository to your own GitHub account.
- Create a new branch for your change:
  `git checkout -b my-feature-branch`

### 3. Make Your Changes

- Follow the existing code style and structure.
- Use dependency injection and interfaces for testability.
- Validate all user input and avoid shell string concatenation.
- Handle sudo privileges appropriately - use mocks for testing.
- Add or update tests for your changes, including privilege scenarios.
- Update documentation and usage examples as needed.

### 4. Run Tests

- Ensure all tests pass before submitting:

  ```bash
  go test ./...
  ```

### 5. Commit and Push

- Write clear, descriptive commit messages.
- Keep commits focused and atomic.
- Push your branch to your fork.

### 6. Open a Pull Request

- Go to the main repo and open a PR from your branch.
- Describe your changes, reference related issues, and explain any design decisions.
- Be ready to discuss and revise your code based on feedback.

---

## Code Style

- Use idiomatic Go and follow the [Effective Go][effective_go] guidelines.
- Use tabs for Go code (see `.editorconfig`).
- Use structured logging (`logrus`) and the provided output helpers.
- Validate all user input, especially IP addresses and jail names.
- Prefer explicit error handling and error wrapping (`fmt.Errorf("...: %w", err)`).
- Add GoDoc comments to all exported functions, types, and interfaces.
- Handle sudo privileges securely - validate before escalation, use mocks in tests.
- Use argument arrays for command execution, never shell string concatenation.

---

## Security Guidelines

### Sudo and Privilege Handling

- **Never execute real sudo commands in tests** - always use `MockSudoChecker` and `MockRunner`
- **Validate all input** before privilege escalation - IP addresses, jail names, etc.
- **Use secure command execution** - argument arrays, not shell strings
- **Test privilege scenarios** - include tests for both privileged and unprivileged users
- **Set F2B_TEST_SUDO=true** in tests that need to verify sudo checking behavior

### Example Test Pattern

```go
// Save original checker and set up mock with privileges
originalChecker := fail2ban.GetSudoChecker()
defer fail2ban.SetSudoChecker(originalChecker)
mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
fail2ban.SetSudoChecker(mockChecker)

// Set environment variable to force sudo checking in tests
os.Setenv("F2B_TEST_SUDO", "true")
defer os.Unsetenv("F2B_TEST_SUDO")
```

---

## Communication

- Be respectful and constructive in all discussions.
- Review the [Code of Conduct](../.github/CODE_OF_CONDUCT.md).
- For large or breaking changes, open an issue to discuss your approach before submitting a PR.

---

## Additional Notes

- All contributions require review and approval before merging.
- Security-related changes require extra scrutiny and testing.
- If you are an AI/LLM agent, please see [AGENTS.md](.github/AGENTS.md) for additional guidelines.
- By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make **f2b** better!

[effective_go]: https://golang.org/doc/effective_go.html
[contributing](CONTRIBUTING.md)
