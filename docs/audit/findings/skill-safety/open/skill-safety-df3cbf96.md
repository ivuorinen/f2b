---
id: skill-safety-df3cbf96
auditor: skill-safety
severity: medium
category: security
area: .claude/skills/graphify
status: open
found: 2026-10-27
location: .claude/skills/graphify/SKILL.md:248-252
location_sha: a4738a7f00b712ac
---

# Vendored graphify skill: full-tool subagents read untrusted documents, and model-written text is spliced into double-quoted shell

## Problem

excessive-permission + dangerous-command. Extraction must use `general-purpose` subagents (Bash, Write, network) over ingested docs and fetched pages, and `save-result` puts the agent's answer, which quotes graph labels from that content, inside double quotes where `$(...)` expands.

## Evidence

`.claude/skills/graphify/SKILL.md:252` "Always use `subagent_type=\"general-purpose\"`"; `references/query.md:171` `--answer "ANSWER"`; also `:80`, `:206`, `:274` splice terms into `-c "..."`.

## Impact

A prompt-injection payload in an ingested page reaches an agent holding Bash and the user's credentials; a quoted label like `$(curl ...|sh)` executes.

## Fix

Upstream: a Read/Write-only extractor agent; pass free text via quoted heredocs. Locally: a `.claude/agents/graphify-extractor.md` with `tools: Read, Write`. Owner decision required (vendored third-party text kept unmodified this run).

## Status

Left open 2026-10-27: the vendored skill was kept by owner decision; the fix belongs upstream or in an owner-approved local agent definition.
