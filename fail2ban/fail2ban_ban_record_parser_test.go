package fail2ban

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ivuorinen/f2b/constants"
)

// A 6/7-field line whose fields aren't timestamps is an exotic variant, not
// garbage: it must produce a simple-format fallback record, not an error.
func TestParseBanRecordSixFieldNonTimestampFallback(t *testing.T) {
	parser, err := NewBanRecordParser()
	if err != nil {
		t.Fatal(err)
	}

	record, err := parser.ParseBanRecordLine("192.168.1.100 foo bar + baz qux", "sshd")
	if err != nil {
		t.Fatalf("expected fallback record, got error: %v", err)
	}
	if record == nil {
		t.Fatal("expected fallback record, got nil")
		return
	}
	if record.IP != "192.168.1.100" {
		t.Errorf("IP = %q, want 192.168.1.100", record.IP)
	}
	if record.Remaining != constants.UnknownValue {
		t.Errorf("Remaining = %q, want %q", record.Remaining, constants.UnknownValue)
	}
}

func TestBanRecordParser(t *testing.T) {
	parser, err := NewBanRecordParser()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		line    string
		jail    string
		wantIP  string
		wantNil bool
	}{
		{
			name:    "valid full format",
			line:    "192.168.1.100 2023-12-01 14:30:45 + 2023-12-02 14:30:45 remaining",
			jail:    "sshd",
			wantIP:  "192.168.1.100",
			wantNil: false,
		},
		{
			name:    "real production format - current ban",
			line:    "192.168.1.100 2025-07-20 14:30:39 + 2025-07-20 14:40:39 remaining",
			jail:    "sshd",
			wantIP:  "192.168.1.100",
			wantNil: false,
		},
		{
			name:    "real production format - longer ban",
			line:    "10.0.0.50 2025-07-20 02:54:28 + 2025-07-20 03:04:28 remaining",
			jail:    "nginx",
			wantIP:  "10.0.0.50",
			wantNil: false,
		},
		{
			name:    "simple format",
			line:    "192.168.1.101 banned",
			jail:    "sshd",
			wantIP:  "192.168.1.101",
			wantNil: false,
		},
		{
			name:    "empty line",
			line:    "",
			jail:    "sshd",
			wantNil: true,
		},
		{
			name:    "single IP field",
			line:    "192.168.1.102",
			jail:    "sshd",
			wantIP:  "192.168.1.102",
			wantNil: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, err := parser.ParseBanRecordLine(tt.line, tt.jail)

			if tt.wantNil {
				if record != nil {
					t.Errorf("Expected nil record, got %+v", record)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if record == nil {
				t.Fatal("Expected record, got nil")
			} else if record.IP != tt.wantIP {
				t.Errorf("IP mismatch: got %s, want %s", record.IP, tt.wantIP)
			}

			if record.Jail != tt.jail {
				t.Errorf("Jail mismatch: got %s, want %s", record.Jail, tt.jail)
			}

			// Full-format rows carry a known ban timestamp; assert it exactly
			// (simple-format rows are skipped inside the helper).
			validateTimeParsing(t, record, tt.line)
		})
	}
}

// TestParseBanRecordLineRejectsUnsafeJail exercises the jail-safety guard in
// ParseBanRecordLine (empty / path-separator / traversal jail names). Without
// this, the guard is mutation-blind: no test ever passed it an unsafe jail.
func TestParseBanRecordLineRejectsUnsafeJail(t *testing.T) {
	parser, err := NewBanRecordParser()
	if err != nil {
		t.Fatal(err)
	}
	line := "192.168.1.100 2023-12-01 14:30:45 + 2023-12-02 14:30:45 remaining"
	unsafeJails := []string{"", "..", "../etc", "a/b", `a\b`, "foo/../bar"}
	for _, jail := range unsafeJails {
		if _, err := parser.ParseBanRecordLine(line, jail); err == nil {
			t.Errorf("ParseBanRecordLine accepted unsafe jail %q, want error", jail)
		}
	}
	// A safe jail on the same line must still succeed, so the guard is not
	// simply rejecting everything.
	if _, err := parser.ParseBanRecordLine(line, "sshd"); err != nil {
		t.Errorf("ParseBanRecordLine rejected safe jail %q: %v", "sshd", err)
	}
}

func TestParseBanRecords(t *testing.T) {
	parser, err := NewBanRecordParser()
	if err != nil {
		t.Fatal(err)
	}

	output := strings.Join([]string{
		"192.168.1.100 2023-12-01 14:30:45 + 2023-12-02 14:30:45 remaining",
		"192.168.1.101 2023-12-01 15:00:00 + 2023-12-02 15:00:00 remaining",
		"",                            // empty line should be skipped
		"invalid",                     // invalid line should be skipped
		"192.168.1.102 banned simple", // simple format
	}, "\n")

	records, err := parser.ParseBanRecords(output, "sshd")
	if err != nil {
		t.Fatalf("ParseBanRecords failed: %v", err)
	}

	expectedIPs := []string{"192.168.1.100", "192.168.1.101", "192.168.1.102"}
	// Note: empty line and invalid IP are both skipped due to validation
	if len(records) != 3 {
		t.Fatalf("Expected 3 records (empty line and invalid IP skipped), got %d", len(records))
	}

	for i, record := range records {
		if record.IP != expectedIPs[i] {
			t.Errorf("Record %d IP mismatch: got %s, want %s", i, record.IP, expectedIPs[i])
		}
		if record.Jail != "sshd" {
			t.Errorf("Record %d jail mismatch: got %s, want sshd", i, record.Jail)
		}
	}
}

func TestParseBanRecordLineOptimized(t *testing.T) {
	line := "192.168.1.100 2023-12-01 14:30:45 + 2023-12-02 14:30:45 remaining"
	record, err := ParseBanRecordLineOptimized(line, "sshd")

	if err != nil {
		t.Fatalf("ParseBanRecordLineOptimized failed: %v", err)
	}

	if record == nil {
		t.Fatal("Expected record, got nil")
	} else if record.IP != "192.168.1.100" {
		t.Errorf("IP mismatch: got %s, want 192.168.1.100", record.IP)
	}

	if record.Jail != "sshd" {
		t.Errorf("Jail mismatch: got %s, want sshd", record.Jail)
	}

	// Assert the parsed ban timestamp, not just IP/jail.
	validateTimeParsing(t, record, line)
}

func TestParseBanRecordsOptimized(t *testing.T) {
	lines := []string{
		"192.168.1.100 2023-12-01 14:30:45 + 2023-12-02 14:30:45 remaining",
		"192.168.1.101 2023-12-01 15:00:00 + 2023-12-02 15:00:00 remaining",
	}
	records, err := ParseBanRecordsOptimized(strings.Join(lines, "\n"), "sshd")

	if err != nil {
		t.Fatalf("ParseBanRecordsOptimized failed: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("Expected 2 records, got %d", len(records))
	}

	// Assert each record's IP and parsed ban timestamp, not just the count.
	wantIPs := []string{"192.168.1.100", "192.168.1.101"}
	for i := range records {
		if records[i].IP != wantIPs[i] {
			t.Errorf("record %d IP = %q, want %q", i, records[i].IP, wantIPs[i])
		}
		validateTimeParsing(t, &records[i], lines[i])
	}
}

func BenchmarkParseBanRecordLine(b *testing.B) {
	parser, err := NewBanRecordParser()
	if err != nil {
		b.Fatal(err)
	}
	line := "192.168.1.100 2023-12-01 14:30:45 + 2023-12-02 14:30:45 remaining"

	b.ResetTimer()
	for b.Loop() {
		_, _ = parser.ParseBanRecordLine(line, "sshd")
	}
}

func BenchmarkParseBanRecords(b *testing.B) {
	parser, err := NewBanRecordParser()
	if err != nil {
		b.Fatal(err)
	}
	output := strings.Repeat("192.168.1.100 2023-12-01 14:30:45 + 2023-12-02 14:30:45 remaining\n", 100)

	b.ResetTimer()
	for b.Loop() {
		_, _ = parser.ParseBanRecords(output, "sshd")
	}
}

// Test error handling for invalid time formats
func TestParseBanRecordInvalidTime(t *testing.T) {
	parser, err := NewBanRecordParser()
	if err != nil {
		t.Fatal(err)
	}

	// Invalid ban time should be skipped (original behavior) - must have 8+ fields
	line := "192.168.1.100 invalid-date 14:30:45 + 2023-12-02 14:30:45 remaining extra"
	record, err := parser.ParseBanRecordLine(line, "sshd")

	if err == nil {
		t.Errorf("Expected error for invalid ban time, but got none")
	}

	if record != nil {
		t.Errorf("Expected nil record for invalid ban time, got %+v", record)
	}

	// Verify it's the correct error type
	if !errors.Is(err, ErrInvalidBanTime) {
		t.Errorf("Expected ErrInvalidBanTime, got %v", err)
	}
}

// Test concurrent access to parser
func TestBanRecordParserConcurrent(t *testing.T) {
	parser, err := NewBanRecordParser()
	if err != nil {
		t.Fatal(err)
	}
	line := "192.168.1.100 2023-12-01 14:30:45 + 2023-12-02 14:30:45 remaining"

	const numGoroutines = 10
	const numOperations = 100

	results := make(chan error, numGoroutines)

	for range numGoroutines {
		go func() {
			var err error
			for range numOperations {
				_, err = parser.ParseBanRecordLine(line, "sshd")
				if err != nil {
					break
				}
			}
			results <- err
		}()
	}

	for range numGoroutines {
		if err := <-results; err != nil {
			t.Errorf("Concurrent parsing failed: %v", err)
		}
	}
}

// TestRealWorldBanRecordPatterns tests with actual patterns from production logs
func TestRealWorldBanRecordPatterns(t *testing.T) {
	parser, err := NewBanRecordParser()
	if err != nil {
		t.Fatal(err)
	}

	// Real patterns observed in production fail2ban
	realWorldPatterns := []struct {
		name        string
		output      string
		jail        string
		wantRecords int
		checkIPs    []string
	}{
		{
			name: "mixed active bans from production",
			output: `192.168.1.100 2025-07-20 00:02:41 + 2025-07-20 00:12:41 remaining
10.0.0.50 2025-07-20 02:37:27 + 2025-07-20 02:47:27 remaining
172.16.0.100 2025-07-20 00:24:53 + 2025-07-20 00:34:53 remaining
192.168.2.100 2025-07-20 16:04:33 + 2025-07-20 16:14:33 remaining`,
			jail:        "sshd",
			wantRecords: 4,
			checkIPs:    []string{"192.168.1.100", "10.0.0.50", "172.16.0.100", "192.168.2.100"},
		},
		{
			name: "repeated offender patterns",
			output: `192.168.1.100 2025-07-20 00:02:41 + 2025-07-20 00:12:41 remaining
192.168.1.100 2025-07-20 00:52:16 + 2025-07-20 01:02:16 remaining
192.168.1.100 2025-07-20 01:41:47 + 2025-07-20 01:51:47 remaining`,
			jail:        "sshd",
			wantRecords: 3,
			checkIPs:    []string{"192.168.1.100"},
		},
		{
			name: "ban cycle timing from real data",
			output: `10.0.0.50 2025-07-20 02:37:27 + 2025-07-20 02:47:27 remaining
10.0.0.50 2025-07-20 02:54:28 + 2025-07-20 03:04:28 remaining
10.0.0.51 2025-07-20 08:59:23 + 2025-07-20 09:09:23 remaining`,
			jail:        "sshd",
			wantRecords: 3,
			checkIPs:    []string{"10.0.0.50", "10.0.0.51"},
		},
	}

	for _, tt := range realWorldPatterns {
		t.Run(tt.name, func(t *testing.T) {
			records, err := parser.ParseBanRecords(tt.output, tt.jail)
			if err != nil {
				t.Fatalf("ParseBanRecords failed: %v", err)
			}

			if len(records) != tt.wantRecords {
				t.Errorf("Expected %d records, got %d", tt.wantRecords, len(records))
			}

			// Check all expected IPs are present
			ipMap := make(map[string]bool)
			for _, record := range records {
				ipMap[record.IP] = true

				// Verify jail
				if record.Jail != tt.jail {
					t.Errorf("Record has wrong jail: got %s, want %s", record.Jail, tt.jail)
				}

				// Verify ban time is parsed
				if record.BannedAt.IsZero() {
					t.Errorf("Record for %s has zero ban time", record.IP)
				}
			}

			for _, checkIP := range tt.checkIPs {
				if !ipMap[checkIP] {
					t.Errorf("Expected IP %s not found in records", checkIP)
				}
			}
		})
	}
}

// TestProductionLogTimingPatterns verifies timing patterns from real logs
func TestProductionLogTimingPatterns(t *testing.T) {
	parser, err := NewBanRecordParser()
	if err != nil {
		t.Fatal(err)
	}

	// Test various real production patterns
	tests := []struct {
		name       string
		line       string
		wantIP     string
		checkTime  bool // Whether to check specific time (only for full format)
		wantParsed bool
	}{
		{
			name:       "10 minute ban (default)",
			line:       "192.168.1.100 2025-07-20 02:37:27 + 2025-07-20 02:47:27 remaining",
			wantIP:     "192.168.1.100",
			checkTime:  true,
			wantParsed: true,
		},
		{
			name:       "early morning attack",
			line:       "192.168.1.101 2025-07-20 00:11:41 + 2025-07-20 00:21:41 remaining",
			wantIP:     "192.168.1.101",
			checkTime:  true,
			wantParsed: true,
		},
		{
			name:       "late night ban",
			line:       "172.16.0.100 2025-07-20 18:23:55 + 2025-07-20 18:33:55 remaining",
			wantIP:     "172.16.0.100",
			checkTime:  true,
			wantParsed: true,
		},
		{
			name:       "simple format from production",
			line:       "192.168.2.100 banned",
			wantIP:     "192.168.2.100",
			checkTime:  false, // Simple format uses current time
			wantParsed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testSingleProductionPattern(t, parser, tt)
		})
	}
}

// testSingleProductionPattern tests a single production log pattern
func testSingleProductionPattern(t *testing.T, parser *BanRecordParser, tt struct {
	name       string
	line       string
	wantIP     string
	checkTime  bool
	wantParsed bool
}) {
	t.Helper()
	record, err := parser.ParseBanRecordLine(tt.line, "sshd")

	if !tt.wantParsed {
		if record != nil || err == nil {
			t.Error("Expected no record or error")
		}
		return
	}

	if !isExpectedError(err) {
		t.Fatalf("Unexpected error: %v", err)
	}

	if record == nil {
		t.Fatal("Expected record, got nil")
	}

	validateParsedRecord(t, record, tt)
}

// isExpectedError checks if the error is one of the expected error types
func isExpectedError(err error) bool {
	if err == nil {
		return true
	}
	return errors.Is(err, ErrEmptyLine) ||
		errors.Is(err, ErrInsufficientFields) ||
		errors.Is(err, ErrInvalidBanTime)
}

// validateParsedRecord validates the parsed ban record
func validateParsedRecord(t *testing.T, record *BanRecord, tt struct {
	name       string
	line       string
	wantIP     string
	checkTime  bool
	wantParsed bool
}) {
	t.Helper()
	// Verify IP
	if record.IP != tt.wantIP {
		t.Errorf("IP mismatch: got %s, want %s", record.IP, tt.wantIP)
	}

	// Verify ban time is set
	if record.BannedAt.IsZero() {
		t.Error("Ban time should not be zero")
	}

	// For full format, verify time parsing
	if tt.checkTime {
		validateTimeParsing(t, record, tt.line)
	}
}

// validateTimeParsing asserts that BannedAt was parsed exactly from the line's
// ban timestamp. Full format is "IP date time + date time [remaining]" (>= 6
// fields); the ban timestamp is always parts[1] (date) and parts[2] (time).
func validateTimeParsing(t *testing.T, record *BanRecord, line string) {
	t.Helper()
	parts := strings.Fields(line)
	if len(parts) < 6 {
		return // simple format: BannedAt is time.Now(), no exact value to assert
	}

	wantStr := parts[1] + " " + parts[2]
	want, err := time.ParseInLocation(constants.TimeFormat, wantStr, time.Local)
	if err != nil {
		t.Fatalf("test setup: cannot parse expected ban time %q: %v", wantStr, err)
	}
	if !record.BannedAt.Equal(want) {
		t.Errorf("BannedAt = %v, want %v (parsed from %q)", record.BannedAt, want, wantStr)
	}
}
