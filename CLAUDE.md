# CLAUDE.md

**IMPORTANT**: All instructions for working with the f2b repository have been moved to [AGENTS.md](AGENTS.md).

## Mandatory Instructions

Claude Code **MUST** follow ALL instructions in [AGENTS.md](AGENTS.md) when working with this repository. This includes:

- **Security guidelines** - Never execute real sudo in tests, use mocks
- **Code standards** - Follow .editorconfig, linting rules, testing patterns
- **Development workflow** - Read config files first, run pre-commit checks

## Key References

- **Complete Instructions**: [AGENTS.md](AGENTS.md) - ALL instructions MUST be followed
- **Architecture Details**: [docs/architecture.md](docs/architecture.md)
- **Security Guidelines**: [docs/security.md](docs/security.md)
- **Testing Patterns**: [docs/testing.md](docs/testing.md)

## Current Project Status

Run `make ci` (or check the CI badges in the README) for the current build,
lint, coverage, and test status. Avoid hard-coding point-in-time numbers here.

- **Go Version**: see `go.mod` for the authoritative version.

______________________________________________________________________

**📋 For all development work, refer to [AGENTS.md](AGENTS.md) for complete instructions.**

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:

- For codebase questions, first run `graphify query "<question>"` when
  graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for
  relationships and `graphify explain "<concept>"` for focused concepts. These
  return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw
  grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of
  raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when
  query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
