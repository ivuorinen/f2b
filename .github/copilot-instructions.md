# GitHub Copilot Instructions

## Primary Guidelines

**Follow all rules and guidelines in [AGENTS.md](../AGENTS.md)** - this is the authoritative source for all AI agents
working on this project.

## Quick Reference

- **Security**: Never execute real sudo commands in tests, always use MockRunner
- **Testing**: Use `F2B_TEST_SUDO=true` and mock all system interactions
- **Format**: Run `go fmt ./...` and `golangci-lint run` before suggesting changes
- **Commits**: Use semantic commit format: `type(scope): message`
- **Validation**: Validate all input before privilege escalation
- **Testing**: Include both privileged and unprivileged test scenarios

## Project Context

f2b is a security-focused Go CLI for managing Fail2Ban. All code suggestions must prioritize security, testability,
and maintainability.

## Documentation References

- [AGENTS.md](../AGENTS.md) - Complete AI/LLM contributor guidelines
- [docs/security.md](../docs/security.md) - Security practices and threat model
- [docs/testing.md](../docs/testing.md) - Testing strategies and mock patterns
- [docs/architecture.md](../docs/architecture.md) - System architecture and design
