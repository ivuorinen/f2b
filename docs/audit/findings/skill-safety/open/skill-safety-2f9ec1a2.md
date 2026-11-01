---
id: skill-safety-2f9ec1a2
auditor: skill-safety
severity: low
category: security
area: .claude/skills/graphify
status: open
found: 2026-10-27
location: .claude/skills/graphify/SKILL.md:154-159
location_sha: e2782c82facf862e
---

# Vendored graphify skill sends documents to Gemini whenever GEMINI_API_KEY/GOOGLE_API_KEY is set, and puts the Neo4j password on argv

## Problem

exfiltration + credential-reach. Backend selection depends on an env var's presence with "do not wait for the user"; the Neo4j export passes the password as a CLI argument.

## Evidence

`.claude/skills/graphify/SKILL.md:159` "If `GEMINI_API_KEY` or `GOOGLE_API_KEY` IS set, use ... backend=\"gemini\""; `references/exports.md:26` `--password PASSWORD`.

## Impact

Untracked local documents go to a third party because a key exported for another tool exists; the password appears in the process list and transcript.

## Fix

Upstream: explicit `--backend gemini` opt-in and env/file-sourced password. Locally run graphify under `env -u GEMINI_API_KEY -u GOOGLE_API_KEY`. Owner decision required.

## Status

Left open 2026-10-27: the vendored skill was kept by owner decision; the fix belongs upstream.
