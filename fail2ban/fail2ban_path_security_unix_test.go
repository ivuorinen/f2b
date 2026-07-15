//go:build unix

package fail2ban

import (
	"path/filepath"
	"syscall"
	"testing"
)

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
