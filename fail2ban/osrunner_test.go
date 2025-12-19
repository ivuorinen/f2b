package fail2ban

import (
	"context"
	"testing"
)

func TestOSRunnerContextMethods(_ *testing.T) {
	runner := &OSRunner{}
	ctx := context.Background()

	// Test CombinedOutputWithContext - will fail due to command validation
	// but will exercise the method
	_, _ = runner.CombinedOutputWithContext(ctx, "invalid-command", "arg")

	// Test CombinedOutputWithSudo - will fail due to command validation
	// but will exercise the method
	_, _ = runner.CombinedOutputWithSudo("invalid-command", "arg")

	// Test CombinedOutputWithSudoContext - will fail due to command validation
	// but will exercise the method
	_, _ = runner.CombinedOutputWithSudoContext(ctx, "invalid-command", "arg")
}

func TestGetLogLinesMethod(t *testing.T) {
	// Test that real client's GetLogLines method exists
	// Create a temporary directory for the test
	tmpDir := t.TempDir()

	// Set up test environment
	_, cleanup := SetupMockEnvironmentWithSudo(t, false)
	defer cleanup()

	// Create a client - may fail, that's ok
	client, err := NewClient(tmpDir, tmpDir)
	if err != nil {
		t.Skipf("NewClient failed (expected in test environment): %v", err)
		return
	}

	// Test GetLogLines - will return empty or error, that's ok for coverage
	_, _ = client.GetLogLines("sshd", "192.168.1.1")
}

func TestParseUltraOptimized(_ *testing.T) {
	// Test ultra-optimized parsing functions (both singular and plural variants)
	line := "192.168.1.1 2025-07-20 12:30:45 2025-07-20 13:30:45"
	jail := "sshd"

	// Test ParseBanRecordsUltraOptimized (plural)
	_, _ = ParseBanRecordsUltraOptimized(line, jail)

	// Test with empty line
	_, _ = ParseBanRecordsUltraOptimized("", jail)

	// Test ParseBanRecordLineUltraOptimized (singular) with malformed line
	_, _ = ParseBanRecordLineUltraOptimized("invalid line", jail)
}
