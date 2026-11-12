//go:build unix

package fail2ban

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunCombinedBoundsOrphanedChild pins that a canceled command returns
// within its context plus WaitDelay even when a grandchild keeps the output
// pipe open. This is the sudo case: the context kill reaches only sudo, the
// command it started survives, and without WaitDelay CombinedOutput blocks
// until that orphan exits.
func TestRunCombinedBoundsOrphanedChild(t *testing.T) {
	orig := commandWaitDelay
	commandWaitDelay = 200 * time.Millisecond
	t.Cleanup(func() { commandWaitDelay = orig })

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	// sh forks sleep, which inherits stdout/stderr; killing sh leaves sleep
	// holding the pipe, exactly like sudo's child.
	_, err := runCombined(ctx, "sh", "-c", "sleep 30; :")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("runCombined returned nil error for a canceled command")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("runCombined blocked %v after cancellation; WaitDelay did not bound it", elapsed)
	}
}

// TestRunCombinedFoldsDiagnosticIntoExitError pins that a failing command's
// own message reaches the error: callers drop the output bytes on the error
// path, so a bare "exit status N" hid e.g. "jail 'x' does not exist".
func TestRunCombinedFoldsDiagnosticIntoExitError(t *testing.T) {
	_, err := runCombined(
		context.Background(),
		"sh",
		"-c",
		"echo \"Sorry but the jail 'sshdx' does not exist\" >&2; exit 255",
	)
	if err == nil {
		t.Fatal("runCombined returned nil error for a failing command")
	}
	if !strings.Contains(err.Error(), "exit status 255") ||
		!strings.Contains(err.Error(), "Sorry but the jail 'sshdx' does not exist") {
		t.Fatalf("error %q lacks the exit status or the command's diagnostic", err)
	}
	if _, ok := errors.AsType[*exec.ExitError](err); !ok {
		t.Fatalf("error %q no longer unwraps to *exec.ExitError", err)
	}

	// No output: the error stays the bare exit error.
	_, err = runCombined(context.Background(), "sh", "-c", "exit 3")
	if err == nil || err.Error() != "exit status 3" {
		t.Fatalf("silent failure error = %v, want exactly \"exit status 3\"", err)
	}
}

// TestRunCombinedDeliversSIGTERMOnCancel pins that cancellation sends SIGTERM.
// sudo relays SIGTERM to its command but cannot relay SIGKILL, the default
// cancel, which left the command running as an orphan. Only a signal the
// script can trap creates the marker.
func TestRunCombinedDeliversSIGTERMOnCancel(t *testing.T) {
	dir := t.TempDir()
	ready, marker := filepath.Join(dir, "ready"), filepath.Join(dir, "terminated")
	script := `trap ': > "` + marker + `"; kill "$pid"; exit 0' TERM; sleep 30 & pid=$!; : > "` + ready + `"; wait`

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := runCombined(ctx, "sh", "-c", script); err != nil {
			t.Logf("runCombined returned after cancellation: %v", err)
		}
	}()

	require.Eventually(t, func() bool {
		_, err := os.Stat(ready)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond, "the script never started")
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runCombined did not return after cancellation")
	}
	assert.FileExists(t, marker, "the command was not given SIGTERM")
}
