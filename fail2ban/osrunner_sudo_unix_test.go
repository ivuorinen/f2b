//go:build unix

package fail2ban

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeStub writes an executable shell script named name into dir. The stubs
// stand in for sudo and fail2ban-client so OSRunner's real exec path runs
// without touching the host's binaries.
func writeStub(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	// #nosec G306 -- test stub must be executable; it lives in t.TempDir()
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755))
}

// useSudoStubs makes a stub directory the whole PATH and a trusted bin dir,
// with stub sudo and fail2ban-client scripts that echo how they were called.
// It fails the test unless LookPath resolves sudo to the stub, so the real
// sudo can never run, and returns the directory.
func useSudoStubs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeStub(t, dir, "sudo", `echo "SUDO $*"`)
	writeStub(t, dir, "fail2ban-client", `echo "PLAIN $*"`)
	t.Setenv("PATH", dir)
	t.Setenv("F2B_TRUSTED_BIN_DIR", dir) // lets the absolute stub path pass ValidateCommand

	sudoPath, err := exec.LookPath("sudo")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "sudo"), sudoPath, "real sudo must be unreachable")
	return dir
}

// runWithSudoChecker runs command through OSRunner's real sudo-prefix decision
// with checker installed and returns the trimmed output. MockRunner
// reimplements that decision, so mock-based tests could not catch a regression
// in it (including RequiresSudo ignoring the absolute LookPath path).
func runWithSudoChecker(t *testing.T, checker SudoChecker, command string, args ...string) string {
	t.Helper()
	orig := GetSudoChecker()
	SetSudoChecker(checker)
	t.Cleanup(func() { SetSudoChecker(orig) })

	out, err := (&OSRunner{}).CombinedOutputWithSudoContext(context.Background(), command, args...)
	require.NoError(t, err)
	return strings.TrimSpace(string(out))
}

// TestOSRunnerSudoDecisionPrefixesSudo pins that a privileged non-root user
// runs fail2ban-client through sudo, given the bare name or the absolute
// LookPath result.
func TestOSRunnerSudoDecisionPrefixesSudo(t *testing.T) {
	dir := useSudoStubs(t)
	privileged := &MockSudoChecker{MockHasPrivileges: true, ExplicitPrivilegesSet: true}

	commands := map[string]string{
		"bare name":                "fail2ban-client",
		"absolute LookPath result": filepath.Join(dir, "fail2ban-client"),
	}
	for name, command := range commands {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, "SUDO "+command+" status", runWithSudoChecker(t, privileged, command, "status"))
		})
	}
}

// TestOSRunnerSudoDecisionRunsDirectly pins the cases that skip sudo: root, a
// user without sudo rights, and a version query that needs no privileges.
func TestOSRunnerSudoDecisionRunsDirectly(t *testing.T) {
	useSudoStubs(t)

	tests := []struct {
		name    string
		checker *MockSudoChecker
		args    []string
		want    string
	}{
		{
			name:    "root",
			checker: &MockSudoChecker{MockIsRoot: true, MockHasPrivileges: true, ExplicitPrivilegesSet: true},
			args:    []string{"status"},
			want:    "PLAIN status",
		},
		{
			name:    "unprivileged user",
			checker: &MockSudoChecker{ExplicitPrivilegesSet: true},
			args:    []string{"status"},
			want:    "PLAIN status",
		},
		{
			name:    "version query",
			checker: &MockSudoChecker{MockHasPrivileges: true, ExplicitPrivilegesSet: true},
			args:    []string{"-V"},
			want:    "PLAIN -V",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, runWithSudoChecker(t, tt.checker, "fail2ban-client", tt.args...))
		})
	}
}
