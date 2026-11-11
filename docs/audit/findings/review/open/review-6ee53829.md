---
id: review-6ee53829
auditor: review
severity: medium
category: conventions
area: .github/workflows/pr-lint.yml
status: open
found: 2026-11-11
location: .github/workflows/pr-lint.yml:1-12
location_sha: eae03929d896000f
---

# The commit-messages check is not required and never re-runs when the PR title is edited

## Problem

Ruleset 1889289 requires only "PR Lint" and "prek", so a red "Commit messages" result does not block the squash merge. The job sits in pr-lint.yml, whose pull_request trigger has no `types:`, so editing the title after the check passed triggers nothing.

## Evidence

`gh api repos/ivuorinen/f2b/rulesets/1889289` lists required contexts ["PR Lint","prek"]. pr-lint.yml: `on: pull_request: branches: [master, main]` (opened/synchronize/reopened only). Renaming a passed PR to "update stuff" or "Claude-Session: abc" leaves the check green; squash merge uses COMMIT_OR_PR_TITLE.

## Impact

A non-semantic or session-linked title or commit can still land on main.

## Fix

Move the job to its own workflow triggered on [opened, synchronize, reopened, edited] with its own concurrency group (adding `edited` to pr-lint.yml would cancel the required jobs), and add "Commit messages" to the ruleset's required checks.
