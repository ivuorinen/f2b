//go:build unix

package fail2ban

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
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
