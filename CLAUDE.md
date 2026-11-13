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

- Run graphify as `$(cat graphify-out/.graphify_python) -m graphify`: that is
  the interpreter the skill installed at the vendored version
  (`.claude/skills/graphify/.graphify_version`). The `graphify` found on the
  executable search path (`PATH`) can be a different release.
- For codebase questions, first run `graphify query` when
  graphify-out/graph.json exists. Run it, and `graphify path` for
  relationships or `graphify explain` for focused concepts, through
  `ctx_execute` (language `shell`) and print only the nodes you need. Write the
  question or concept names to a file and read them back with `"$(cat file)"`,
  as `.claude/skills/graphify/references/query.md` shows: typed inside double
  quotes, a `$(...)` in that text runs as a command.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of
  raw source browsing.
- For broad architecture review, analyze graphify-out/GRAPH_REPORT.md with
  `ctx_execute_file` instead of reading it whole. When that cannot answer the
  question, say so and ask before reading the report directly.
- After modifying code, run
  `$(cat graphify-out/.graphify_python) -m graphify update .` to keep the graph
  current (abstract syntax tree only, no API cost), but only when
  `graphify-out/.graphify_python` exists. graphify-out/ is not committed, so a
  fresh clone has neither the file nor a graph: run `/graphify` first, which
  records the interpreter. Without the file, `$(cat ...)` expands to nothing
  and the shell runs `-m` as the command.
