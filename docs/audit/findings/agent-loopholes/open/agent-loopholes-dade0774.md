---
id: agent-loopholes-dade0774
auditor: agent-loopholes
severity: high
category: security
area: .claude/settings.json
status: open
found: 2026-10-27
location: .claude/settings.json:2-9
location_sha: 38213eb5ab670206
---

# Allow-listed ctx_execute/ctx_execute_file/ctx_batch_execute run arbitrary code with no prompt, no classifier and no hook

## Problem

permission contradiction. Three of the five allow entries are code-execution tools. An allow match resolves immediately, auto mode's drop list does not cover MCP execution tools, no project hook matches them, and context-mode's own shell check enforces only deny/ask patterns, of which none are defined.

## Evidence

`.claude/settings.json:4-6` `"mcp__plugin_context-mode_context-mode__ctx_execute"`, `"..._ctx_execute_file"`, `"..._ctx_batch_execute"`; hook matchers only `Bash` (:14) and `Read|Glob` (:23). Bypass: `ctx_execute(language:"shell", code:"git commit --no-verify -am wip && git push")` runs unreviewed, contradicting ~/.claude/rules/git-conduct.md. NIT-32 called these "read-only ctx tools".

## Impact

The allow list is equivalent to `Bash(*)` and is not removed by auto mode.

## Fix

Remove the three execution entries (keep ctx_search, ctx_stats), and add `"ask": ["Bash(git commit *)", "Bash(git push *)"]`, which context-mode also evaluates against ctx_execute shell code. Owner decision required (permission settings).

## Status

Left open 2026-10-27: the owner was asked during the audit run and chose not to drop the ctx execution allow entries.
