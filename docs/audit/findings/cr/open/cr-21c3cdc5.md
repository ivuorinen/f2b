---
id: cr-21c3cdc5
auditor: cr
severity: low
category: tests
area: cmd/cmd_commands_test.go
status: open
found: 2026-11-15
location: cmd/cmd_commands_test.go:15-26
location_sha: fa8c2e7c7023bb15
---

# cmd path tests fail when TMPDIR is outside the dev-path allowlist

## Problem

The cmd tests that write log files or log directories under t.TempDir() and set ALLOW_DEV_PATHS assume TMPDIR lies under /tmp or /var/folders, the only roots ALLOW_DEV_PATHS adds. With TMPDIR elsewhere, such as a directory in the home tree, they fail validation instead of testing anything. The fail2ban package has the same dependency removed by its TestMain in fail2ban/dev_temp_dir_test.go (ae89598); cmd's TestMain does not do the same.

## Evidence

On c6951ce, `TMPDIR=$HOME/.cache/f2b-tmpdir-probe go test ./...` fails seven cmd tests and passes every other package: TestPersistentPreRun, TestLogFormatChosenOnce, TestLazyClientForwardsFileOperations, TestLazyClientForwardsLineLimit, TestExecuteRestoresStderrLoggingAfterALogFileRun, TestOpenLogFileRefusesADirectorySwappedForASymlink and TestOpenLogFileFollowsAnAbsoluteSymlinkInsideTheAllowlist, each with "path outside allowed directories" for a path under the probe directory. With the default TMPDIR all of them pass.

## Impact

A developer or CI runner whose TMPDIR is outside /tmp and /var/folders sees seven cmd failures unrelated to their change, and those tests check nothing on that host.

## Fix

In cmd's existing TestMain (cmd/cmd_commands_test.go), apply the fail2ban approach before m.Run: with ALLOW_DEV_PATHS on, ask fail2ban.ValidateClientLogPath whether it admits os.TempDir(), and point TMPDIR at /tmp when it does not. Do not widen the production allowlist. Left as a follow-up by the maintainer's decision on 2026-11-15, because it changes the part of PR #257 that CodeRabbit had already approved.
