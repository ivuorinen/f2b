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

// TestOSRunnerSudoDecision exercises OSRunner's real sudo-prefix decision.
// MockRunner reimplements that decision, so mock-based tests could not catch a
// regression in it (including RequiresSudo ignoring the absolute LookPath
// path). PATH holds only the stub directory and LookPath must resolve sudo
// there, so the real sudo can never run.
func TestOSRunnerSudoDecision(t *testing.T) {
	dir := t.TempDir()
	writeStub(t, dir, "sudo", `echo "SUDO $*"`)
	writeStub(t, dir, "fail2ban-client", `echo "PLAIN $*"`)
	t.Setenv("PATH", dir)
	t.Setenv("F2B_TRUSTED_BIN_DIR", dir) // lets the absolute stub path pass ValidateCommand

	sudoPath, err := exec.LookPath("sudo")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "sudo"), sudoPath, "real sudo must be unreachable")

	absClient := filepath.Join(dir, "fail2ban-client")
	privileged := &MockSudoChecker{MockHasPrivileges: true, ExplicitPrivilegesSet: true}

	tests := []struct {
		name    string
		checker *MockSudoChecker
		command string
		args    []string
		want    string
	}{
		{
			name:    "root runs directly",
			checker: &MockSudoChecker{MockIsRoot: true, MockHasPrivileges: true, ExplicitPrivilegesSet: true},
			command: "fail2ban-client",
			args:    []string{"status"},
			want:    "PLAIN status",
		},
		{
			name:    "privileged non-root uses sudo",
			checker: privileged,
			command: "fail2ban-client",
			args:    []string{"status"},
			want:    "SUDO fail2ban-client status",
		},
		{
			name:    "absolute LookPath result uses sudo",
			checker: privileged,
			command: absClient,
			args:    []string{"status"},
			want:    "SUDO " + absClient + " status",
		},
		{
			name:    "unprivileged runs directly",
			checker: &MockSudoChecker{ExplicitPrivilegesSet: true},
			command: "fail2ban-client",
			args:    []string{"status"},
			want:    "PLAIN status",
		},
		{
			name:    "version query needs no sudo",
			checker: privileged,
			command: "fail2ban-client",
			args:    []string{"-V"},
			want:    "PLAIN -V",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := GetSudoChecker()
			SetSudoChecker(tt.checker)
			t.Cleanup(func() { SetSudoChecker(orig) })

			out, err := (&OSRunner{}).CombinedOutputWithSudoContext(context.Background(), tt.command, tt.args...)
			require.NoError(t, err)
			assert.Equal(t, tt.want, strings.TrimSpace(string(out)))
		})
	}
}
