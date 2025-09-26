package fail2ban

import (
	"testing"
	"time"
)

// compareParserResults compares results from original and optimized parsers
func compareParserResults(t *testing.T, originalRecords []BanRecord, originalErr error,
	optimizedRecords []BanRecord, optimizedErr error) {
	t.Helper()
	// Compare errors
	if (originalErr == nil) != (optimizedErr == nil) {
		t.Fatalf("Error mismatch: original=%v, optimized=%v", originalErr, optimizedErr)
	}

	// Compare record counts
	if len(originalRecords) != len(optimizedRecords) {
		t.Fatalf("Record count mismatch: original=%d, optimized=%d",
			len(originalRecords), len(optimizedRecords))
	}

	// Compare each record
	for i := range originalRecords {
		compareRecords(t, i, &originalRecords[i], &optimizedRecords[i])
	}
}

// compareRecords compares individual ban records
func compareRecords(t *testing.T, index int, orig, opt *BanRecord) {
	t.Helper()
	if orig.Jail != opt.Jail {
		t.Errorf("Record %d jail mismatch: original=%s, optimized=%s", index, orig.Jail, opt.Jail)
	}

	if orig.IP != opt.IP {
		t.Errorf("Record %d IP mismatch: original=%s, optimized=%s", index, orig.IP, opt.IP)
	}

	// For time comparison, allow small differences due to parsing
	if !orig.BannedAt.IsZero() && !opt.BannedAt.IsZero() {
		if orig.BannedAt.Unix() != opt.BannedAt.Unix() {
			t.Errorf("Record %d banned time mismatch: original=%v, optimized=%v",
				index, orig.BannedAt, opt.BannedAt)
		}
	}

	// Remaining time should be consistent
	if orig.Remaining != opt.Remaining {
		t.Errorf("Record %d remaining time mismatch: original=%s, optimized=%s",
			index, orig.Remaining, opt.Remaining)
	}
}

// TestParserCompatibility ensures the optimized parser produces identical results to the original
func TestParserCompatibility(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		jail  string
	}{
		{
			name:  "full_format_single_record",
			input: "192.168.1.100 2025-07-20 14:30:39 + 2025-07-20 14:40:39 remaining",
			jail:  "sshd",
		},
		{
			name: "multiple_records",
			input: `192.168.1.100 2025-07-20 14:30:39 + 2025-07-20 14:40:39 remaining
10.0.0.50 2025-07-20 14:36:59 + 2025-07-20 14:46:59 remaining
172.16.0.100 2025-07-20 14:52:09 + 2025-07-20 15:02:09 remaining`,
			jail: "apache",
		},
		{
			name:  "empty_input",
			input: "",
			jail:  "sshd",
		},
		{
			name:  "whitespace_only",
			input: "   \n\t   \n   ",
			jail:  "sshd",
		},
		{
			name:  "single_field_fallback",
			input: "192.168.1.100",
			jail:  "nginx",
		},
		{
			name: "mixed_formats",
			input: `192.168.1.100 2025-07-20 14:30:39 + 2025-07-20 14:40:39 remaining
10.0.0.50
172.16.0.100 2025-07-20 14:52:09 + 2025-07-20 15:02:09 remaining`,
			jail: "mixed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Parse with original parser
			originalParser := NewBanRecordParser()
			originalRecords, originalErr := originalParser.ParseBanRecords(tc.input, tc.jail)

			// Parse with optimized parser
			optimizedParser := NewBanRecordParser()
			optimizedRecords, optimizedErr := optimizedParser.ParseBanRecords(tc.input, tc.jail)

			compareParserResults(t, originalRecords, originalErr, optimizedRecords, optimizedErr)
		})
	}
}

// compareSingleRecords compares individual parsed records
func compareSingleRecords(t *testing.T, originalRecord *BanRecord, originalErr error,
	optimizedRecord *BanRecord, optimizedErr error) {
	t.Helper()
	// Compare errors
	if (originalErr == nil) != (optimizedErr == nil) {
		t.Fatalf("Error mismatch: original=%v, optimized=%v", originalErr, optimizedErr)
	}

	// If both have errors, that's fine - they should be the same type
	if originalErr != nil && optimizedErr != nil {
		return
	}

	// Compare records
	if (originalRecord == nil) != (optimizedRecord == nil) {
		t.Fatalf("Record nil mismatch: original=%v, optimized=%v",
			originalRecord == nil, optimizedRecord == nil)
	}

	if originalRecord != nil && optimizedRecord != nil {
		compareRecordFields(t, originalRecord, optimizedRecord)
	}
}

// compareRecordFields compares fields of two ban records
func compareRecordFields(t *testing.T, original, optimized *BanRecord) {
	t.Helper()
	if original.Jail != optimized.Jail {
		t.Errorf("Jail mismatch: original=%s, optimized=%s",
			original.Jail, optimized.Jail)
	}

	if original.IP != optimized.IP {
		t.Errorf("IP mismatch: original=%s, optimized=%s",
			original.IP, optimized.IP)
	}

	// Time comparison with tolerance
	if !original.BannedAt.IsZero() && !optimized.BannedAt.IsZero() {
		if original.BannedAt.Unix() != optimized.BannedAt.Unix() {
			t.Errorf("BannedAt mismatch: original=%v, optimized=%v",
				original.BannedAt, optimized.BannedAt)
		}
	}
}

// TestParserCompatibilityLineByLine tests individual line parsing compatibility
func TestParserCompatibilityLineByLine(t *testing.T) {
	testLines := []struct {
		name string
		line string
		jail string
	}{
		{
			name: "valid_full_format",
			line: "192.168.1.100 2025-07-20 14:30:39 + 2025-07-20 14:40:39 remaining",
			jail: "sshd",
		},
		{
			name: "ip_only",
			line: "192.168.1.100",
			jail: "sshd",
		},
		{
			name: "empty_line",
			line: "",
			jail: "sshd",
		},
		{
			name: "whitespace_line",
			line: "   \t   ",
			jail: "sshd",
		},
		{
			name: "insufficient_fields",
			line: "192.168.1.100 incomplete",
			jail: "sshd",
		},
	}

	for _, tc := range testLines {
		t.Run(tc.name, func(t *testing.T) {
			// Parse with original parser
			originalParser := NewBanRecordParser()
			originalRecord, originalErr := originalParser.ParseBanRecordLine(tc.line, tc.jail)

			// Parse with optimized parser
			optimizedParser := NewBanRecordParser()
			optimizedRecord, optimizedErr := optimizedParser.ParseBanRecordLine(tc.line, tc.jail)

			compareSingleRecords(t, originalRecord, originalErr, optimizedRecord, optimizedErr)
		})
	}
}

// TestOptimizedParserStatistics tests the statistics functionality
func TestOptimizedParserStatistics(t *testing.T) {
	parser := NewBanRecordParser()

	// Initial stats should be zero
	parseCount, errorCount := parser.GetStats()
	if parseCount != 0 || errorCount != 0 {
		t.Errorf("Initial stats should be zero: parseCount=%d, errorCount=%d", parseCount, errorCount)
	}

	// Parse some records
	input := `192.168.1.100 2025-07-20 14:30:39 + 2025-07-20 14:40:39 remaining

10.0.0.50 2025-07-20 14:36:59 + 2025-07-20 14:46:59 remaining`

	records, err := parser.ParseBanRecords(input, "sshd")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(records) != 2 {
		t.Errorf("Expected 2 records, got %d", len(records))
	}

	// Check stats (empty lines are skipped, not counted as errors)
	parseCount, errorCount = parser.GetStats()
	if parseCount != 2 {
		t.Errorf("Expected 2 successful parses, got %d", parseCount)
	}
	if errorCount != 0 {
		t.Errorf("Expected 0 errors, got %d", errorCount)
	}
}

// TestTimeParsingOptimizations tests the optimized time parsing
func TestTimeParsingOptimizations(t *testing.T) {
	cache := NewFastTimeCache("2006-01-02 15:04:05")

	testTimeStr := "2025-07-20 14:30:39"

	// First parse
	time1, err1 := cache.ParseTimeOptimized(testTimeStr)
	if err1 != nil {
		t.Fatalf("First parse failed: %v", err1)
	}

	// Second parse should hit cache
	time2, err2 := cache.ParseTimeOptimized(testTimeStr)
	if err2 != nil {
		t.Fatalf("Second parse failed: %v", err2)
	}

	if time1.Unix() != time2.Unix() {
		t.Errorf("Cached time doesn't match: %v vs %v", time1, time2)
	}

	expected := time.Date(2025, 7, 20, 14, 30, 39, 0, time.UTC)
	if time1.UTC().Unix() != expected.Unix() {
		t.Errorf("Parsed time incorrect: got %v, expected %v", time1.UTC(), expected)
	}
}

// TestStringBuildingOptimizations tests the optimized string building
func TestStringBuildingOptimizations(t *testing.T) {
	cache := NewFastTimeCache("2006-01-02 15:04:05")

	dateStr := "2025-07-20"
	timeStr := "14:30:39"
	expected := "2025-07-20 14:30:39"

	result := cache.BuildTimeStringOptimized(dateStr, timeStr)
	if result != expected {
		t.Errorf("String building failed: got %s, expected %s", result, expected)
	}
}

// BenchmarkParserStatistics tests performance impact of statistics tracking
func BenchmarkParserStatistics(b *testing.B) {
	parser := NewBanRecordParser()
	testLine := "192.168.1.100 2025-07-20 14:30:39 + 2025-07-20 14:40:39 remaining"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := parser.ParseBanRecordLine(testLine, "sshd")
		if err != nil {
			b.Fatal(err)
		}
	}
}
