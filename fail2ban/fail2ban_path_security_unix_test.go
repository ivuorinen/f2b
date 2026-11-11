//go:build unix

package fail2ban

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pathConfig returns the production-shaped config for base.
func pathConfig(base string, allowSymlinks bool) PathSecurityConfig {
	return PathSecurityConfig{
		AllowedBasePaths: []string{base},
		MaxPathLength:    4096,
		AllowSymlinks:    allowSymlinks,
	}
}

// TestValidatePathRejectsAncestorSymlinkEscape pins that a symlinked directory
// above an existing file cannot carry a path out of the allowed base. Only the
// leaf used to be inspected, so <base>/link/secret passed the lexical base
// check while really naming a file elsewhere, which `sudo fail2ban-regex` then
// read as root.
func TestValidatePathRejectsAncestorSymlinkEscape(t *testing.T) {
	base, outside := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.log"), []byte("x"), 0600))
	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(outside, link))

	for name, allowSymlinks := range map[string]bool{"symlinks allowed": true, "symlinks refused": false} {
		t.Run(name, func(t *testing.T) {
			_, err := ValidatePathWithSecurity(filepath.Join(link, "secret.log"), pathConfig(base, allowSymlinks))
			require.Error(t, err, "a path leaving the base through a symlinked ancestor was accepted")
		})
	}
}

// TestValidatePathResolvesAncestorSymlinkInsideBase pins that the returned
// path is the real one, so the caller hands the resolved location to sudo
// rather than a name a later symlink swap could redirect.
func TestValidatePathResolvesAncestorSymlinkInsideBase(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	realDir := filepath.Join(base, "real")
	require.NoError(t, os.Mkdir(realDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(realDir, "app.log"), []byte("x"), 0600))
	alias := filepath.Join(base, "alias")
	require.NoError(t, os.Symlink(realDir, alias))

	got, err := ValidatePathWithSecurity(filepath.Join(alias, "app.log"), pathConfig(base, true))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(realDir, "app.log"), got)

	_, err = ValidatePathWithSecurity(filepath.Join(alias, "app.log"), pathConfig(base, false))
	require.Error(t, err, "AllowSymlinks=false accepted a symlink below the base")
}

// TestValidatePathAcceptsBaseBehindSymlink pins that a symlink above the
// allowed base is not treated as an escape: /var is a symlink on macOS, and a
// strict resolved-equals-input check would reject every log there.
func TestValidatePathAcceptsBaseBehindSymlink(t *testing.T) {
	parent := t.TempDir()
	realBase := filepath.Join(parent, "real")
	require.NoError(t, os.Mkdir(realBase, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(realBase, "fail2ban.log"), []byte("x"), 0600))
	linkBase := filepath.Join(parent, "linked")
	require.NoError(t, os.Symlink(realBase, linkBase))

	_, err := ValidatePathWithSecurity(filepath.Join(linkBase, "fail2ban.log"), CreateSingleDirPathConfig(linkBase))
	require.NoError(t, err)
}

// TestFileTypeValidationFifo verifies special files are rejected. It lives in
// a unix-only file because syscall.Mkfifo does not exist on Windows.
func TestFileTypeValidationFifo(t *testing.T) {
	pipePath := filepath.Join(t.TempDir(), "test.pipe")
	if err := syscall.Mkfifo(pipePath, 0600); err != nil {
		// Hard-fail rather than skip: this file is unix-only (//go:build unix)
		// and mkfifo in a tempdir always succeeds there. A silent skip would let
		// the FIFO-rejection security assertion vanish from a green run.
		t.Fatalf("mkfifo failed for this FIFO-rejection security test: %v", err)
	}
	if err := validateFileType(pipePath); err == nil {
		t.Error("named pipe should fail validation")
	}
}
