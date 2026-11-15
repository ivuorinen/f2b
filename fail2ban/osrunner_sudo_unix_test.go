//go:build unix

package fail2ban_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
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
func runWithSudoChecker(t *testing.T, checker fail2ban.SudoChecker, command string, args ...string) string {
	t.Helper()
	orig := fail2ban.GetSudoChecker()
	fail2ban.SetSudoChecker(checker)
	t.Cleanup(func() { fail2ban.SetSudoChecker(orig) })

	out, err := (&fail2ban.OSRunner{}).CombinedOutputWithSudoContext(context.Background(), command, args...)
	require.NoError(t, err)
	return strings.TrimSpace(string(out))
}

// TestOSRunnerSudoDecisionPrefixesSudo pins that a privileged non-root user
// runs fail2ban-client through sudo, given the bare name or the absolute
// LookPath result.
func TestOSRunnerSudoDecisionPrefixesSudo(t *testing.T) {
	dir := useSudoStubs(t)
	privileged := &fail2bantest.MockSudoChecker{MockHasPrivileges: true, ExplicitPrivilegesSet: true}

	// A bare name is resolved before it reaches sudo: left bare, sudo would
	// search the caller's PATH wherever sudoers sets no secure_path.
	resolved := filepath.Join(dir, "fail2ban-client")
	commands := map[string]string{
		"bare name":                "fail2ban-client",
		"absolute LookPath result": resolved,
	}
	for name, command := range commands {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, "SUDO "+resolved+" status", runWithSudoChecker(t, privileged, command, "status"))
		})
	}
}

// TestOSRunnerRefusesBinariesFromUntrustedDirectories pins the PATH-hijack
// defense for every privileged execution: a sudo or inner binary found outside
// the trusted directories never runs. Each stub records that it executed, so
// the assertion is on the side effect rather than on an error message.
func TestOSRunnerRefusesBinariesFromUntrustedDirectories(t *testing.T) {
	tests := []struct {
		name          string
		checker       *fail2bantest.MockSudoChecker
		untrustedStub string
		trustedStub   string
	}{
		{
			name:          "sudo outside trusted directories",
			checker:       &fail2bantest.MockSudoChecker{MockHasPrivileges: true, ExplicitPrivilegesSet: true},
			untrustedStub: "sudo",
			trustedStub:   "fail2ban-regex",
		},
		{
			name:          "inner command outside trusted directories",
			checker:       &fail2bantest.MockSudoChecker{MockHasPrivileges: true, ExplicitPrivilegesSet: true},
			untrustedStub: "fail2ban-regex",
			trustedStub:   "sudo",
		},
		{
			name: "command run directly as root",
			checker: &fail2bantest.MockSudoChecker{
				MockIsRoot:            true,
				MockHasPrivileges:     true,
				ExplicitPrivilegesSet: true,
			},
			untrustedStub: "fail2ban-regex",
			trustedStub:   "sudo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			untrusted, trusted := t.TempDir(), t.TempDir()
			marker := filepath.Join(t.TempDir(), "executed")
			writeStub(t, untrusted, tt.untrustedStub, `: > "`+marker+`"`)
			writeStub(t, trusted, tt.trustedStub, `: > "`+marker+`"`)
			t.Setenv("PATH", untrusted+string(os.PathListSeparator)+trusted)
			t.Setenv("F2B_TRUSTED_BIN_DIR", trusted)
			orig := fail2ban.GetSudoChecker()
			fail2ban.SetSudoChecker(tt.checker)
			t.Cleanup(func() { fail2ban.SetSudoChecker(orig) })

			_, err := (&fail2ban.OSRunner{}).CombinedOutputWithSudoContext(
				context.Background(),
				"fail2ban-regex",
				"log",
				"filter",
			)

			require.Error(t, err)
			assert.NoFileExists(t, marker, "a binary from an untrusted PATH entry was executed")
		})
	}
}

// TestOSRunnerSudoDecisionRunsDirectly pins the cases that skip sudo: root, a
// user without sudo rights, and a version query that needs no privileges.
func TestOSRunnerSudoDecisionRunsDirectly(t *testing.T) {
	useSudoStubs(t)

	tests := []struct {
		name    string
		checker *fail2bantest.MockSudoChecker
		args    []string
		want    string
	}{
		{
			name: "root",
			checker: &fail2bantest.MockSudoChecker{
				MockIsRoot:            true,
				MockHasPrivileges:     true,
				ExplicitPrivilegesSet: true,
			},
			args: []string{"status"},
			want: "PLAIN status",
		},
		{
			name:    "unprivileged user",
			checker: &fail2bantest.MockSudoChecker{ExplicitPrivilegesSet: true},
			args:    []string{"status"},
			want:    "PLAIN status",
		},
		{
			name:    "version query",
			checker: &fail2bantest.MockSudoChecker{MockHasPrivileges: true, ExplicitPrivilegesSet: true},
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
