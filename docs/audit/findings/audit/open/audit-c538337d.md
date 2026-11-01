---
id: audit-c538337d
auditor: audit
severity: low
category: security
area: repository secrets
status: open
found: 2026-10-27
---

# Two repository secrets have no consumer: CLAUDE_CODE_OAUTH_TOKEN and SONAR_TOKEN

## Problem

Config lens: committed-secret surface outside the tree. `gh secret list` shows two long-lived credentials stored as repository secrets, but no workflow or config references either. SonarCloud runs in automatic-analysis mode (the `sonarqubecloud` app check), which does not use `SONAR_TOKEN`, and no workflow invokes Claude Code.

## Evidence

`gh secret list` → `CLAUDE_CODE_OAUTH_TOKEN 2025-07-21`, `SONAR_TOKEN 2025-10-06`. `rg 'CLAUDE_CODE_OAUTH_TOKEN|SONAR_TOKEN'` over the tree (hidden files included) → no match. Check runs on main: `SonarCloud Code Analysis` from app `sonarqubecloud`; no sonar-scanner step in any workflow.

## Impact

Any future workflow or compromised action step with `secrets` access can read an account-level OAuth token that nothing needs.

## Fix

User action (secrets are never changed by this audit): `gh secret delete CLAUDE_CODE_OAUTH_TOKEN --repo ivuorinen/f2b` and `gh secret delete SONAR_TOKEN --repo ivuorinen/f2b`, then revoke the OAuth token at its issuer.

## Status

Left open 2026-10-27: secret deletion and token revocation are the owner's action.
