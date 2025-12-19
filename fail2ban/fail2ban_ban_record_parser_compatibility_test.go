package fail2ban

import (
	"testing"
	"time"
)

// compareParserResults compares results from two consecutive parser runs
func compareParserResults(t *testing.T, firstRecords []BanRecord, firstErr error,
	secondRecords []BanRecord, secondErr error) {
	t.Helper()
	// Compare errors
	if (firstErr == nil) != (secondErr == nil) {
		t.Fatalf("Error mismatch: first=%v, second=%v", firstErr, secondErr)
	}

	// Compare record counts
	if len(firstRecords) != len(secondRecords) {
		t.Fatalf("Record count mismatch: first=%d, second=%d",
			len(firstRecords), len(secondRecords))
	}

	// Compare each record
	for i := range firstRecords {
		compareRecords(t, i, &firstRecords[i], &secondRecords[i])
	}
}

// compareRecords compares individual ban records
func compareRecords(t *testing.T, index int, first, second *BanRecord) {
	t.Helper()
	if first.Jail != second.Jail {
		t.Errorf("Record %d jail mismatch: first=%s, second=%s", index, first.Jail, second.Jail)
	}

	if first.IP != second.IP {
		t.Errorf("Record %d IP mismatch: first=%s, second=%s", index, first.IP, second.IP)
	}

	// For time comparison, allow small differences due to parsing
	if !first.BannedAt.IsZero() && !second.BannedAt.IsZero() {
		if first.BannedAt.Unix() != second.BannedAt.Unix() {
			t.Errorf("Record %d banned time mismatch: first=%v, second=%v",
				index, first.BannedAt, second.BannedAt)
		}
	}

	// Remaining time should be consistent
	if first.Remaining != second.Remaining {
		t.Errorf("Record %d remaining time mismatch: first=%s, second=%s",
			index, first.Remaining, second.Remaining)
	}
}

// TestParserDeterminism ensures the parser produces identical results across consecutive runs
func TestParserDeterminism(t *testing.T) {
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
			// Validates parser determinism by running twice with identical input
			parser1, err := NewBanRecordParser()
			if err != nil {
				t.Fatal(err)
			}

			// First parse
			firstRecords, firstErr := parser1.ParseBanRecords(tc.input, tc.jail)

			// Second parse with fresh parser (should produce identical results)
			parser2, err := NewBanRecordParser()
			if err != nil {
				t.Fatal(err)
			}
			secondRecords, secondErr := parser2.ParseBanRecords(tc.input, tc.jail)

			compareParserResults(t, firstRecords, firstErr, secondRecords, secondErr)
		})
	}
}

// compareSingleRecords compares individual parsed records
func compareSingleRecords(t *testing.T, firstRecord *BanRecord, firstErr error,
	secondRecord *BanRecord, secondErr error) {
	t.Helper()
	// Compare errors
	if (firstErr == nil) != (secondErr == nil) {
		t.Fatalf("Error mismatch: first=%v, second=%v", firstErr, secondErr)
	}

	// If both have errors, that's fine - they should be the same type
	if firstErr != nil && secondErr != nil {
		return
	}

	// Compare records
	if (firstRecord == nil) != (secondRecord == nil) {
		t.Fatalf("Record nil mismatch: first=%v, second=%v",
			firstRecord == nil, secondRecord == nil)
	}

	if firstRecord != nil && secondRecord != nil {
		compareRecordFields(t, firstRecord, secondRecord)
	}
}

// compareRecordFields compares fields of two ban records
func compareRecordFields(t *testing.T, first, second *BanRecord) {
	t.Helper()
	if first.Jail != second.Jail {
		t.Errorf("Jail mismatch: first=%s, second=%s",
			first.Jail, second.Jail)
	}

	if first.IP != second.IP {
		t.Errorf("IP mismatch: first=%s, second=%s",
			first.IP, second.IP)
	}

	// Time comparison with tolerance
	if !first.BannedAt.IsZero() && !second.BannedAt.IsZero() {
		if first.BannedAt.Unix() != second.BannedAt.Unix() {
			t.Errorf("BannedAt mismatch: first=%v, second=%v",
				first.BannedAt, second.BannedAt)
		}
	}
}

// TestParserDeterminismLineByLine tests individual line parsing determinism
func TestParserDeterminismLineByLine(t *testing.T) {
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
			// Validates parser determinism by running twice with identical input
			parser1, err := NewBanRecordParser()
			if err != nil {
				t.Fatal(err)
			}

			// First parse
			firstRecord, firstErr := parser1.ParseBanRecordLine(tc.line, tc.jail)

			// Second parse with fresh parser (should produce identical results)
			parser2, err := NewBanRecordParser()
			if err != nil {
				t.Fatal(err)
			}
			secondRecord, secondErr := parser2.ParseBanRecordLine(tc.line, tc.jail)

			compareSingleRecords(t, firstRecord, firstErr, secondRecord, secondErr)
		})
	}
}

// TestParserStatistics tests the statistics functionality
func TestParserStatistics(t *testing.T) {
	parser, err := NewBanRecordParser()
	if err != nil {
		t.Fatal(err)
	}

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
	cache, err := NewFastTimeCache("2006-01-02 15:04:05")
	if err != nil {
		t.Fatal(err)
	}

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
	cache, err := NewFastTimeCache("2006-01-02 15:04:05")
	if err != nil {
		t.Fatal(err)
	}

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
	parser, err := NewBanRecordParser()
	if err != nil {
		b.Fatal(err)
	}
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
