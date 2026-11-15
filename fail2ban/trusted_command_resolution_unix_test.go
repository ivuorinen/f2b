//go:build unix

package fail2ban

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeStub writes an executable shell script named name into dir, standing
// in for sudo or an admin binary. osrunner_sudo_unix_test.go has the same
// helper for package fail2ban_test: these tests need unexported internals and
// gobco cannot instrument external tests that use internal test helpers.
func writeStub(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	// #nosec G306 -- test stub must be executable; it lives in t.TempDir()
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755))
}

// TestOSRunnerFindsAdminBinaryOutsideUserPATH pins the Debian case: the default
// non-root PATH has no sbin and service lives in /usr/sbin. sudo's secure_path
// used to find it, so resolving through PATH alone broke `f2b service`.
func TestOSRunnerFindsAdminBinaryOutsideUserPATH(t *testing.T) {
	sbin := t.TempDir()
	writeStub(t, sbin, "service", `echo "PLAIN $*"`)
	t.Setenv("PATH", t.TempDir())
	t.Setenv("F2B_TRUSTED_BIN_DIR", sbin)
	orig := adminCommandDirs
	adminCommandDirs = []string{sbin}
	t.Cleanup(func() { adminCommandDirs = orig })

	// A checker without sudo rights: root and an unprivileged user both run the
	// command directly, so the result does not depend on who runs the test and
	// no sudo is involved. The seams keep the host's groups and sudo out of it.
	origChecker := GetSudoChecker()
	SetSudoChecker(&RealSudoChecker{
		groupNames:   func() ([]string, error) { return nil, nil },
		runSudoProbe: func(context.Context) error { return errors.New("no sudo") },
	})
	t.Cleanup(func() { SetSudoChecker(origChecker) })

	out, err := (&OSRunner{}).CombinedOutputWithSudoContext(context.Background(), "service", "fail2ban", "status")
	require.NoError(t, err)
	assert.Equal(t, "PLAIN fail2ban status", strings.TrimSpace(string(out)))
}

// TestDefaultSudoProbeRefusesUntrustedSudo pins that the privilege probe goes
// through the same resolution as every other execution: it runs before any
// command, so a sudo from a hostile PATH entry would otherwise still execute.
func TestDefaultSudoProbeRefusesUntrustedSudo(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "executed")
	writeStub(t, dir, "sudo", `: > "`+marker+`"`)
	t.Setenv("PATH", dir)
	t.Setenv("F2B_TRUSTED_BIN_DIR", "")

	require.Error(t, defaultSudoProbe(context.Background()))
	assert.NoFileExists(t, marker, "the probe executed a sudo from an untrusted directory")
}

func TestResolveTrustedCommandReportsAMissingBinary(t *testing.T) {
	empty := t.TempDir()
	t.Setenv("PATH", empty)
	t.Setenv("F2B_TRUSTED_BIN_DIR", empty)
	orig := adminCommandDirs
	adminCommandDirs = []string{empty}
	t.Cleanup(func() { adminCommandDirs = orig })

	_, err := resolveTrustedCommand("fail2ban-client")

	require.ErrorContains(t, err, "not found")
}

// TestDefaultSudoProbeRunsATrustedSudo is the positive half of the probe's
// PATH-hijack defense: a sudo in a trusted directory does get executed.
func TestDefaultSudoProbeRunsATrustedSudo(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "executed")
	writeStub(t, dir, "sudo", `: > "`+marker+`"`)
	t.Setenv("PATH", dir)
	t.Setenv("F2B_TRUSTED_BIN_DIR", dir)

	require.NoError(t, defaultSudoProbe(context.Background()))

	assert.FileExists(t, marker)
}
