package fail2ban

import (
	"errors"
	"strings"
	"testing"
)

func TestBanRecordParser(t *testing.T) {
	parser := NewBanRecordParser()

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
			}

			if record.IP != tt.wantIP {
				t.Errorf("IP mismatch: got %s, want %s", record.IP, tt.wantIP)
			}

			if record.Jail != tt.jail {
				t.Errorf("Jail mismatch: got %s, want %s", record.Jail, tt.jail)
			}
		})
	}
}

func TestParseBanRecords(t *testing.T) {
	parser := NewBanRecordParser()

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

	expectedIPs := []string{"192.168.1.100", "192.168.1.101", "invalid", "192.168.1.102"}
	// Note: empty line is skipped, but "invalid" is treated as simple format
	if len(records) != 4 {
		t.Fatalf("Expected 4 records (empty line skipped), got %d", len(records))
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
	}

	if record.IP != "192.168.1.100" {
		t.Errorf("IP mismatch: got %s, want 192.168.1.100", record.IP)
	}

	if record.Jail != "sshd" {
		t.Errorf("Jail mismatch: got %s, want sshd", record.Jail)
	}
}

func TestParseBanRecordsOptimized(t *testing.T) {
	output := "192.168.1.100 2023-12-01 14:30:45 + 2023-12-02 14:30:45 remaining\n" +
		"192.168.1.101 2023-12-01 15:00:00 + 2023-12-02 15:00:00 remaining"
	records, err := ParseBanRecordsOptimized(output, "sshd")

	if err != nil {
		t.Fatalf("ParseBanRecordsOptimized failed: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("Expected 2 records, got %d", len(records))
	}
}

func BenchmarkParseBanRecordLine(b *testing.B) {
	parser := NewBanRecordParser()
	line := "192.168.1.100 2023-12-01 14:30:45 + 2023-12-02 14:30:45 remaining"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.ParseBanRecordLine(line, "sshd")
	}
}

func BenchmarkParseBanRecords(b *testing.B) {
	parser := NewBanRecordParser()
	output := strings.Repeat("192.168.1.100 2023-12-01 14:30:45 + 2023-12-02 14:30:45 remaining\n", 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.ParseBanRecords(output, "sshd")
	}
}

// Test error handling for invalid time formats
func TestParseBanRecordInvalidTime(t *testing.T) {
	parser := NewBanRecordParser()

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
	parser := NewBanRecordParser()
	line := "192.168.1.100 2023-12-01 14:30:45 + 2023-12-02 14:30:45 remaining"

	const numGoroutines = 10
	const numOperations = 100

	results := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			var err error
			for j := 0; j < numOperations; j++ {
				_, err = parser.ParseBanRecordLine(line, "sshd")
				if err != nil {
					break
				}
			}
			results <- err
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		if err := <-results; err != nil {
			t.Errorf("Concurrent parsing failed: %v", err)
		}
	}
}
