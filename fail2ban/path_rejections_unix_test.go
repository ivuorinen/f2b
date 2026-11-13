//go:build unix

package fail2ban

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolvedTempDir returns a temp directory with symlinks resolved, so expected
// paths do not depend on the host's temp prefix (a symlink on macOS).
func resolvedTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return dir
}

// allowOnly returns the strict configuration production uses, over bases.
func allowOnly(bases ...string) PathSecurityConfig {
	return PathSecurityConfig{AllowedBasePaths: bases, MaxPathLength: 4096}
}

// TestEmptyAllowlistRefusesEveryPath pins that an allowlist with no entries
// allows nothing. An empty log directory produces one, and reading that as "no
// restrictions" let a zero-value RealClient read any file.
func TestEmptyAllowlistRefusesEveryPath(t *testing.T) {
	file := filepath.Join(resolvedTempDir(t), "secret.log")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	configs := map[string]PathSecurityConfig{
		"empty log directory": CreateSingleDirPathConfig(""),
		"no bases at all":     allowOnly(),
	}
	for name, config := range configs {
		t.Run(name, func(t *testing.T) {
			_, err := ValidatePathWithSecurity(file, config)
			require.ErrorContains(t, err, "outside allowed")
		})
	}
}

// TestPathValidationRequiresAPath allows the working directory, which is where
// an empty path would otherwise resolve.
func TestPathValidationRequiresAPath(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	_, err = ValidatePathWithSecurity("", allowOnly(cwd))

	require.ErrorContains(t, err, "empty path")
}

// TestPathValidationRefusesSpecialFiles pins that only regular files and
// directories pass: reading a device or a socket as a log can block or have
// side effects, and the process may be running as root.
func TestPathValidationRefusesSpecialFiles(t *testing.T) {
	dir := resolvedTempDir(t)
	t.Chdir(dir) // keeps the socket name under the platform's 104-byte limit
	listener, err := net.Listen("unix", "f2b.sock")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, listener.Close()) })

	tests := map[string]struct{ path, base string }{
		"character device": {"/dev/null", "/dev"},
		"socket":           {filepath.Join(dir, "f2b.sock"), dir},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ValidatePathWithSecurity(tt.path, allowOnly(tt.base))
			require.ErrorContains(t, err, "only regular files and directories")
		})
	}
}

// TestPathValidationReportsASymlinkLoop allows symlinks so the loop reaches
// resolution, which has to fail rather than yield an unresolved path.
func TestPathValidationReportsASymlinkLoop(t *testing.T) {
	base := resolvedTempDir(t)
	first, second := filepath.Join(base, "first"), filepath.Join(base, "second")
	require.NoError(t, os.Symlink(second, first))
	require.NoError(t, os.Symlink(first, second))
	config := allowOnly(base)
	config.AllowSymlinks = true

	_, err := ValidatePathWithSecurity(first, config)

	require.ErrorContains(t, err, "resolve symlink")
}

func TestPathValidationRefusesAPathThroughAFile(t *testing.T) {
	base := resolvedTempDir(t)
	file := filepath.Join(base, "fail2ban.log")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	_, err := ValidatePathWithSecurity(filepath.Join(file, "child"), allowOnly(base))

	require.Error(t, err)
}

// TestBaseSymlinkIsRecognisedUnderAnyAllowedBase pins that a base which does
// not contain the path is skipped rather than ending the search: the symlink
// here sits at the second base, which is the host's layout and not an escape.
func TestBaseSymlinkIsRecognisedUnderAnyAllowedBase(t *testing.T) {
	root := resolvedTempDir(t)
	target, link, other := filepath.Join(root, "target"), filepath.Join(root, "link"), filepath.Join(root, "other")
	require.NoError(t, os.Mkdir(target, 0o750))
	require.NoError(t, os.Mkdir(other, 0o750))
	require.NoError(t, os.Symlink(target, link))
	file := filepath.Join(target, "fail2ban.log")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	got, err := ValidatePathWithSecurity(filepath.Join(link, "fail2ban.log"), allowOnly(other, link, target))

	require.NoError(t, err)
	assert.Equal(t, file, got)
}

func TestExpandAllowedPathsKeepsEachDirectoryOnce(t *testing.T) {
	root := resolvedTempDir(t)
	target, link := filepath.Join(root, "target"), filepath.Join(root, "link")
	require.NoError(t, os.Mkdir(target, 0o750))
	require.NoError(t, os.Symlink(target, link))

	tests := map[string]struct{ input, want []string }{
		// An empty entry would resolve to the working directory and allow it.
		"empty entry":                   {[]string{"", target}, []string{target}},
		"repeated entry":                {[]string{target, target}, []string{target}},
		"symlink to a listed directory": {[]string{target, link}, []string{target, link}},
		"symlink adds its target":       {[]string{link}, []string{link, target}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, expandAllowedPaths(tt.input))
		})
	}
}
