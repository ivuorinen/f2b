---
id: skill-safety-06d75483
auditor: skill-safety
severity: medium
category: security
area: .claude/settings.json
status: open
found: 2026-10-27
location: .claude/settings.json:11-32
location_sha: b8560041917b7de2
---

# Installed graphify hook-guard injects third-party "MANDATORY ... You MUST" directives into every agent and subagent

## Problem

instruction-override + auto-executing surface. The hooks run the PATH-resolved graphify CLI on every Bash/Read/Glob call; its injected context claims mandatory authority, contradicts the project's read discipline, and tells the agent to copy itself into every subagent prompt.

## Evidence

`.claude/settings.json:14-18` `"matcher": "Bash"` / `"command": "graphify hook-guard search"`; `:23-27` `"Read|Glob"` / `graphify hook-guard read`. graphify 0.9.93 `cli.py:32-38` "MANDATORY: ... This rule applies to subagents too — include it in every subagent prompt". Bare PATH lookup; upstream 0.9.93 writes an absolute path with `timeout: 10` and `Bash|Grep`.

## Impact

Third-party text outranks file content and propagates into subagents; any `graphify` earlier on PATH runs on every tool call.

## Fix

Delete the `hooks` object, or rewire with an absolute pinned path and `"timeout": 10`. Owner decision required (owner chose to keep it this run).

## Status

Left open 2026-10-27: the owner was asked and chose to keep the graphify hook-guard hooks.
