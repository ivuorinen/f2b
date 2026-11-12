//go:build unix

package fail2ban

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogCopyIsNotRedirectedBySwapAfterValidation pins that swapping the log,
// or a directory above it, for a symlink after validation does not get the
// outside file read: the log is opened through the allowlisted base, which no
// component may leave.
func TestLogCopyIsNotRedirectedBySwapAfterValidation(t *testing.T) {
	swaps := map[string]func(t *testing.T, dir, outside string){
		"file": func(t *testing.T, dir, outside string) {
			t.Helper()
			log := filepath.Join(dir, "app.log")
			require.NoError(t, os.Remove(log))
			require.NoError(t, os.Symlink(filepath.Join(outside, "app.log"), log))
		},
		"directory": func(t *testing.T, dir, outside string) {
			t.Helper()
			require.NoError(t, os.Rename(dir, dir+".old"))
			require.NoError(t, os.Symlink(outside, dir))
		},
	}
	for name, swap := range swaps {
		t.Run(name, func(t *testing.T) {
			base, outside := resolvedTempDir(t), t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(outside, "app.log"), []byte("secret\n"), 0600))
			dir := filepath.Join(base, "d")
			require.NoError(t, os.Mkdir(dir, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "app.log"), []byte("log line\n"), 0600))
			validated, err := ValidatePathWithSecurity(filepath.Join(dir, "app.log"), pathConfig(base, true))
			require.NoError(t, err)

			swap(t, dir, outside)
			copyPath, _, err := copyLogForRegex(validated, []string{base}, 1024)

			require.Error(t, err, "the read followed a symlink out of the allowlisted base")
			assert.Empty(t, copyPath)
		})
	}
}

// TestLogCopyRefusesANamedPipeWithoutBlocking pins that a log swapped for a
// named pipe is refused at once: opening a pipe for reading otherwise blocks
// until a writer appears, before the file type can be checked.
func TestLogCopyRefusesANamedPipeWithoutBlocking(t *testing.T) {
	base := resolvedTempDir(t)
	pipe := filepath.Join(base, "app.log")
	require.NoError(t, syscall.Mkfifo(pipe, 0600))

	done := make(chan error, 1)
	go func() {
		_, _, err := copyLogForRegex(pipe, []string{base}, 1024)
		done <- err
	}()

	select {
	case err := <-done:
		require.ErrorContains(t, err, "not a regular file")
	case <-time.After(5 * time.Second):
		t.Fatal("opening a named pipe blocked")
	}
}

// TestLogCopyDirectoryIsPrivateAndRemoved pins that the copy lives in a
// directory only its owner can enter, that the remover deletes it, and that a
// refused copy leaves nothing behind.
func TestLogCopyDirectoryIsPrivateAndRemoved(t *testing.T) {
	base, tmp := resolvedTempDir(t), t.TempDir()
	t.Setenv("TMPDIR", tmp)
	path := filepath.Join(base, "app.log")
	require.NoError(t, os.WriteFile(path, []byte("12345"), 0600))

	_, _, err := copyLogForRegex(path, []string{base}, 4)
	require.Error(t, err)
	entries, err := os.ReadDir(tmp)
	require.NoError(t, err)
	assert.Empty(t, entries, "a refused copy left its directory behind")

	copyPath, remove, err := copyLogForRegex(path, []string{base}, 1024)
	require.NoError(t, err)
	copyDir := filepath.Dir(copyPath)
	assert.Equal(t, tmp, filepath.Dir(copyDir))
	info, err := os.Stat(copyDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	require.NoError(t, remove())
	assert.NoDirExists(t, copyDir)
}

// TestLogCopyReportsAnUnusableTempDirectory pins that a temp directory the
// copy cannot be created in is an error before fail2ban-regex could run.
func TestLogCopyReportsAnUnusableTempDirectory(t *testing.T) {
	base := resolvedTempDir(t)
	t.Setenv("TMPDIR", filepath.Join(base, "missing"))
	path := filepath.Join(base, "app.log")
	require.NoError(t, os.WriteFile(path, []byte("x\n"), 0600))

	copyPath, _, err := copyLogForRegex(path, []string{base}, 1024)

	require.Error(t, err)
	assert.Empty(t, copyPath)
}
