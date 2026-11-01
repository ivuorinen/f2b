---
id: skill-safety-c2098eb7
auditor: skill-safety
severity: medium
category: maintainability
area: .claude/skills/graphify
status: open
found: 2026-10-27
location: .claude/skills/graphify/.graphify_version:1
location_sha: 842026a49acbaa0c
---

# Three graphify installs drive one graphify-out/; the vendored 0.9.16 skill is shadowed on the maintainer machine

## Problem

Provenance/version split. The vendored tree matches the PyPI 0.9.16 wheel, but the agent hooks run 0.9.93 from PATH, the git post-commit hook runs a separate uv-tool 0.9.16, and a personal ~/.claude/skills/graphify overrides the project skill.

## Evidence

`.claude/skills/graphify/.graphify_version` `0.9.16`; `graphify --version` → 0.9.93; `.git/hooks/post-commit:59` pins uv-tool graphifyy 0.9.16. SKILL.md:88 `uv tool install --upgrade graphifyy` (unpinned).

## Impact

graph.json is written alternately by two versions, and reviewing the committed skill does not cover what runs.

## Fix

Unvendor (`git rm -r .claude/skills/graphify`) or pin one version for all paths. Owner decision required (owner chose to keep the vendored copy this run).

## Status

Left open 2026-10-27: the owner was asked and chose to keep the vendored graphify skill.
