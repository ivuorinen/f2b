---
id: ci-dd3d72f2
auditor: ci
severity: medium
category: reliability
area: .github/workflows/pr-lint.yml
status: open
found: 2026-10-27
location: .github/workflows/pr-lint.yml:16-93
location_sha: c16478081a9f43a0
---

# PR gate jobs (PR Lint, prek) are not required status checks — Verified

## Problem

non-gating-check. `pr-lint.yml` is the only `pull_request` workflow and runs golangci-lint, the race-enabled test suite and every prek hook, but nothing requires it. Branch protection on `main` is absent and both active rulesets contain only `deletion`, `non_fast_forward` and `copilot_code_review` rules.

## Evidence

`gh api repos/ivuorinen/f2b/branches/main/protection` → `404 Branch not protected`. `gh api repos/ivuorinen/f2b/rulesets/1889289` (`main`) rules: deletion, non_fast_forward; `rulesets/8714365` rules: deletion, non_fast_forward, copilot_code_review. No `required_status_checks` rule. Verified. Concrete case: PR #235 is `mergeStateStatus: UNSTABLE` with `prek` FAILURE and is still `MERGEABLE`.

## Impact

A red PR — failing tests or lint — can be merged into main; repo auto-merge settings would not wait on these jobs either.

## Fix

User action (rulesets are never changed by this audit): add a required_status_checks rule to ruleset 1889289, e.g. `gh api -X PUT repos/ivuorinen/f2b/rulesets/1889289 --input ruleset.json` where `ruleset.json` keeps the existing deletion/non_fast_forward rules and adds `{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":false,"required_status_checks":[{"context":"PR Lint"},{"context":"prek"}]}}`. Verify with `gh api repos/ivuorinen/f2b/rulesets/1889289 --jq '.rules[].type'`.

## Status

Left open 2026-10-27: ruleset changes are the owner's action; the audit never changes branch protection.
