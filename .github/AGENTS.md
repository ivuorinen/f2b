# AGENTS.md

## Guidelines for LLMs and AI Agents Contributing to This Repository

Welcome, AI agents and large language models! This document provides context and best practices for automated or AI-assisted contributions to the `ivuorinen/f2b` project.

---

### 1. Project Context

- **Project:** `f2b` — A modern, secure, and extensible Go CLI for managing Fail2Ban jails and bans.
- **Tech Stack:** Go (>=1.20), Cobra CLI, logrus for logging, modular architecture with dependency injection.
- **Key Principles:** Security, testability, maintainability, user experience, and privilege safety.
- **Security Features:** Automatic sudo privilege management, comprehensive input validation, secure command execution.

---

### 2. Contribution Guidelines for AI Agents

#### a. Code Quality

- Generate idiomatic, readable, and well-documented Go code.
- Follow the existing project structure and naming conventions.
- Use dependency injection and interfaces for testability.
- Prefer explicit error handling and logging (use logrus).
- Handle sudo privileges appropriately using the established patterns.

#### b. Security

- Validate all user input (especially IP addresses and jail names).
- Never use shell string concatenation for system commands; always use argument lists.
- Use `MockSudoChecker` and `MockRunner` in tests - never execute real sudo commands.
- Handle privilege escalation securely - validate input before escalation.
- Follow the principle of least privilege - only escalate when absolutely necessary.
- Test both privileged and unprivileged user scenarios.

#### c. Output & Logging

- Use the provided `PrintOutput` and `PrintError` helpers for CLI output.
- Support both `plain` and `json` output formats where applicable.
- Log important actions and errors using logrus.
- Provide clear, actionable error messages for privilege-related failures.

#### d. Documentation

- Update or create relevant documentation (README, code comments, usage examples) for any new feature or change.
- If you add new commands or flags, document them in the README and help output.

#### e. Testing

- Add or update unit tests for all new logic.
- Use dependency injection and mocks for testing system interactions.
- Use `MockSudoChecker` for privilege testing - never real sudo in tests.
- Test privilege scenarios: privileged users, unprivileged users, and edge cases.
- Set `F2B_TEST_SUDO=true` when testing sudo validation behavior.
- Ensure all tests pass (`go test ./...`) before submitting changes.

#### f. Pull Requests

- Clearly describe the motivation, scope, and impact of your changes.
- Reference related issues or discussions if applicable.
- Use conventional commit messages and keep PRs focused.

---

### 3. AI/LLM-Specific Notes

- If you are an LLM acting on behalf of a user, always prioritize user intent and project maintainability.
- Avoid generating large, sweeping changes unless explicitly requested.
- When in doubt, ask for clarification or propose incremental improvements.
- Respect the project's Code of Conduct and community standards.
- Pay special attention to security implications when modifying privilege-related code.
- Always include appropriate test coverage for security-sensitive changes.

---

### 4. Example Good Practices

- Add a new CLI flag: Document it in the README, add a test, and ensure it is parsed and validated correctly.
- Refactor a command: Use dependency injection, update all usages, and ensure backward compatibility.
- Add a new feature: Provide usage examples, update help output, and add tests.
- Add privileged operation: Use `RequiresSudo()` to classify, handle with `RunnerCombinedOutputWithSudo()`, test with mocks.
- Modify security-sensitive code: Include both privileged and unprivileged test scenarios.

---

### 5. Contact

For questions or to report issues with AI-generated contributions, contact the project maintainer:

- [@ivuorinen](https://github.com/ivuorinen)
- ismo@ivuorinen.net

---

Thank you for helping make `f2b` better—whether you are human or machine!
