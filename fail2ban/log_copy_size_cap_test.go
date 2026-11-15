package fail2ban

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogCopyRefusesALogOverTheCap pins that a log larger than the cap is an
// error, not a silently truncated copy, and that a log at the cap is copied
// whole.
func TestLogCopyRefusesALogOverTheCap(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "app.log")
	require.NoError(t, os.WriteFile(path, []byte("12345"), 0600))

	_, _, err := copyLogForRegex(path, []string{base}, 4)
	require.ErrorContains(t, err, "larger than 4 bytes")

	copyPath, remove, err := copyLogForRegex(path, []string{base}, 5)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, remove()) })
	data, err := os.ReadFile(copyPath) // #nosec G304 -- test temp file
	require.NoError(t, err)
	assert.Equal(t, "12345", string(data))
}

// TestLogCopyRefusesALogOutsideTheBases pins that the copy is only ever opened
// through an allowlisted directory.
func TestLogCopyRefusesALogOutsideTheBases(t *testing.T) {
	base, outside := t.TempDir(), t.TempDir()
	path := filepath.Join(outside, "app.log")
	require.NoError(t, os.WriteFile(path, []byte("secret\n"), 0600))

	copyPath, _, err := copyLogForRegex(path, []string{base}, 1024)

	require.ErrorContains(t, err, "not under an allowed log directory")
	assert.Empty(t, copyPath)
}

// TestLogCopyReportsAMissingBase pins that an allowlisted directory that does
// not exist is an error, not a copy from elsewhere.
func TestLogCopyReportsAMissingBase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "missing")

	copyPath, _, err := copyLogForRegex(filepath.Join(base, "app.log"), []string{base}, 1024)

	require.Error(t, err)
	assert.Empty(t, copyPath)
}
