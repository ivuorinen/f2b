# CLAUDE.md

@AGENTS.md

AGENTS.md (imported above) holds the project instructions for every agent.
The graphify section below is Claude Code-specific.

## Key References

- **Architecture Details**: [docs/architecture.md](docs/architecture.md)
- **Security Guidelines**: [docs/security.md](docs/security.md)
- **Testing Patterns**: [docs/testing.md](docs/testing.md)

## Current Project Status

Run `mise run all` (or check the CI badges in the README) for the current build,
lint, vulnerability, and test status.

- **Go Version**: see `go.mod` for the authoritative version.

______________________________________________________________________

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:

- For codebase questions, first run `graphify query "<question>"` when
  graphify-out/graph.json exists. Run it, and `graphify path "<A>" "<B>"` for
  relationships or `graphify explain "<concept>"` for focused concepts, through
  `ctx_execute` (language `shell`) and print only the nodes you need.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of
  raw source browsing.
- For broad architecture review, analyze graphify-out/GRAPH_REPORT.md with
  `ctx_execute_file`; never read it whole.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
