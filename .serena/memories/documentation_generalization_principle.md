# Documentation Generalization Principle

## Purpose

Avoid specific numerical claims in documentation to prevent maintenance overhead and outdated information.

## Guidelines

### Numbers to Avoid

- **Command counts** (e.g., "21 commands") → Use "comprehensive command set"
- **Test coverage percentages** (e.g., "73.9% coverage") → Use "comprehensive coverage"
- **Code reduction percentages** (e.g., "60-70% reduction") → Use "significant reduction"
- **Specific test case counts** (e.g., "17 path traversal tests") → Use "extensive test coverage"
- **Performance improvements** (e.g., "70% improvement") → Use "significant improvements"

### Acceptable Numbers

- **Major version numbers** (e.g., "Go 1.25+") - OK for major requirements
- **Critical security counts when necessary** - Only if the exact number is architecturally important

### Recommended Alternatives

- "comprehensive" instead of specific counts
- "extensive" for large numbers
- "significant" for percentages and improvements
- "substantial" for major changes
- "advanced" for feature sets

## Implementation Status

- ✅ AGENTS.md updated with principle
- ✅ CLAUDE.md generalized
- ✅ Memory files updated
- ✅ Core project files addressed

## Rationale

Specific numbers in documentation:

1. Go stale quickly as code evolves
2. Require updates in multiple places
3. Create maintenance burden
4. May become inaccurate without notice
5. Don't add significant value to understanding

Generalized terms provide the same level of understanding without the maintenance overhead.
