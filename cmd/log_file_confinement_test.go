package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpenLogFileRefusesADirectorySwappedForASymlink pins that every
// --log-file component is confined, not only the leaf: a directory replaced by
// a symlink after resolveLogFilePath must not lead the open elsewhere. Opening
// a Root on the file's own directory followed the swapped link, so `sudo f2b`
// created the log file in the link's target.
func TestOpenLogFileRefusesADirectorySwappedForASymlink(t *testing.T) {
	t.Setenv("ALLOW_DEV_PATHS", "1") // temp dirs live under /tmp
	dir, outside := t.TempDir(), t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o750))

	path, err := resolveLogFilePath(filepath.Join(sub, "f2b.log"))
	require.NoError(t, err)

	require.NoError(t, os.Remove(sub))
	require.NoError(t, os.Symlink(outside, sub))

	f, err := openLogFile(path)
	if err == nil {
		require.NoError(t, f.Close())
		t.Error("openLogFile followed a directory swapped for a symlink")
	}
	_, statErr := os.Stat(filepath.Join(outside, "f2b.log"))
	assert.True(t, os.IsNotExist(statErr), "log file created through the swapped directory: stat error = %v", statErr)
}

// TestOpenLogFileFollowsAnAbsoluteSymlinkInsideTheAllowlist pins that a leaf
// symlink staying inside the allowlist opens, absolute target included: an
// os.Root refuses absolute links, so `ln -s /var/log/f2b/f2b.log
// /var/log/f2b.log` made every f2b invocation fail.
func TestOpenLogFileFollowsAnAbsoluteSymlinkInsideTheAllowlist(t *testing.T) {
	t.Setenv("ALLOW_DEV_PATHS", "1") // temp dirs live under /tmp
	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	require.NoError(t, os.WriteFile(target, nil, 0o600))
	link := filepath.Join(dir, "link.log")
	require.NoError(t, os.Symlink(target, link))

	path, err := resolveLogFilePath(link)
	require.NoError(t, err)
	f, err := openLogFile(path)
	require.NoError(t, err)
	_, err = f.WriteString("line\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	data, err := os.ReadFile(target) // #nosec G304 -- test temp file
	require.NoError(t, err)
	assert.Equal(t, "line\n", string(data))
}
