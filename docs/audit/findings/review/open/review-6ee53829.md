---
id: review-6ee53829
auditor: review
severity: medium
category: conventions
area: .github/workflows/commit-messages.yml
status: open
found: 2026-11-11
location: .github/workflows/commit-messages.yml:28-29
location_sha: 34a5bf504b2f9178
---

# The Commit messages check is not a required status check

## Problem

Ruleset 1889289 requires only "PR Lint" and "prek", so a failing "Commit messages" result does not block the squash merge. The job itself is in place: commit-messages.yml runs it on opened, synchronize, reopened and edited, with its own concurrency group, so editing the title re-runs it.

## Evidence

`gh api repos/ivuorinen/f2b/rulesets/1889289` lists required contexts ["PR Lint","prek"] (checked 2026-11-15). commit-messages.yml:8-15 sets the triggers and the concurrency group. The squash merge uses COMMIT_OR_PR_TITLE.

## Impact

A non-semantic or session-linked title or commit can still land on main while the check reports the failure.

## Fix

Add "Commit messages" to the ruleset's required checks once commit-messages.yml is on main. Adding it before then blocks every PR whose branch lacks the workflow, because the required context never reports.
