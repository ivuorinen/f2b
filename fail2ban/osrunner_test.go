package fail2ban

import (
	"context"
	"testing"
)

func TestOSRunnerContextMethods(t *testing.T) {
	runner := &OSRunner{}
	ctx := context.Background()

	// "invalid-command" is not on the allowlist, so every entry point must
	// reject it via command validation before executing anything.
	if _, err := runner.CombinedOutputWithContext(ctx, "invalid-command", "arg"); err == nil {
		t.Error("CombinedOutputWithContext accepted a non-allowlisted command")
	}
	if _, err := runner.CombinedOutputWithSudo("invalid-command", "arg"); err == nil {
		t.Error("CombinedOutputWithSudo accepted a non-allowlisted command")
	}
	if _, err := runner.CombinedOutputWithSudoContext(ctx, "invalid-command", "arg"); err == nil {
		t.Error("CombinedOutputWithSudoContext accepted a non-allowlisted command")
	}
}

func TestGetLogLinesMethod(t *testing.T) {
	// Test that real client's GetLogLines method exists
	// Create a temporary directory for the test
	t.Setenv("ALLOW_DEV_PATHS", "1") // temp dirs live under /tmp
	tmpDir := t.TempDir()

	// Set up test environment
	_, cleanup := SetupMockEnvironmentWithSudo(t, false)
	defer cleanup()
	StandardMockSetup(MustMockRunner(t)) // NewClient's version check needs a response

	// NewClient with valid temp dirs must succeed in the test environment;
	// a skip here would hide a real NewClient regression.
	client, err := NewClient(tmpDir, tmpDir)
	if err != nil {
		t.Fatalf("NewClient with valid temp dirs failed: %v", err)
	}

	// Empty log dir: no lines, no error.
	lines, err := client.GetLogLines("sshd", "192.168.1.1")
	if err != nil || len(lines) != 0 {
		t.Fatalf("GetLogLines on empty dir: lines=%v err=%v", lines, err)
	}
}

func TestParseUltraOptimized(t *testing.T) {
	// Test ultra-optimized parsing functions (both singular and plural variants)
	line := "192.168.1.1 2025-07-20 12:30:45 2025-07-20 13:30:45"
	jail := "sshd"

	// Plural: a single well-formed line yields exactly one record for that IP/jail.
	records, err := ParseBanRecordsUltraOptimized(line, jail)
	if err != nil {
		t.Fatalf("ParseBanRecordsUltraOptimized returned error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].IP != "192.168.1.1" {
		t.Errorf("record IP = %q, want 192.168.1.1", records[0].IP)
	}
	if records[0].Jail != jail {
		t.Errorf("record Jail = %q, want %q", records[0].Jail, jail)
	}

	// Empty input yields no records and no error.
	empty, err := ParseBanRecordsUltraOptimized("", jail)
	if err != nil {
		t.Fatalf("ParseBanRecordsUltraOptimized(\"\") returned error: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("expected 0 records for empty input, got %d", len(empty))
	}

	// Singular: a line whose first field is not an IP must be rejected.
	if _, err := ParseBanRecordLineUltraOptimized("invalid line", jail); err == nil {
		t.Error("ParseBanRecordLineUltraOptimized accepted a line with a non-IP first field")
	}
}
