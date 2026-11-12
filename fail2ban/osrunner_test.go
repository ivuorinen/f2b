package fail2ban

import (
	"context"
	"testing"
)

func TestOSRunnerContextMethods(t *testing.T) {
	runner := &OSRunner{}
	ctx := context.Background()

	// "invalid-command" is not on the allowlist, so the runner must reject it
	// via command validation before executing anything.
	if _, err := runner.CombinedOutputWithSudoContext(ctx, "invalid-command", "arg"); err == nil {
		t.Error("CombinedOutputWithSudoContext accepted a non-allowlisted command")
	}
}

func TestParseBanRecordsDefaultParser(t *testing.T) {
	// The package entry point and the single-line parser.
	line := "192.168.1.1 2025-07-20 12:30:45 2025-07-20 13:30:45"
	jail := "sshd"

	// Plural: a single well-formed line yields exactly one record for that IP/jail.
	records, err := ParseBanRecords(line, jail)
	if err != nil {
		t.Fatalf("ParseBanRecords returned error: %v", err)
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
	empty, err := ParseBanRecords("", jail)
	if err != nil {
		t.Fatalf("ParseBanRecords(\"\") returned error: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("expected 0 records for empty input, got %d", len(empty))
	}

	// Singular: a line whose first field is not an IP must be rejected.
	if _, err := parseBanRecordLine("invalid line", jail); err == nil {
		t.Error("ParseBanRecordLine accepted a line with a non-IP first field")
	}
}
