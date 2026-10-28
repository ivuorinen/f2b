package fail2ban

import (
	"bytes"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			parser1 := NewBanRecordParser()

			// First parse
			firstRecords, firstErr := parser1.ParseBanRecords(tc.input, tc.jail)

			// Second parse with fresh parser (should produce identical results)
			parser2 := NewBanRecordParser()
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
			parser1 := NewBanRecordParser()

			// First parse
			firstRecord, firstErr := parser1.ParseBanRecordLine(tc.line, tc.jail)

			// Second parse with fresh parser (should produce identical results)
			parser2 := NewBanRecordParser()
			secondRecord, secondErr := parser2.ParseBanRecordLine(tc.line, tc.jail)

			compareSingleRecords(t, firstRecord, firstErr, secondRecord, secondErr)
		})
	}
}

// captureFail2banLog routes the package logger to a buffer for the test.
func captureFail2banLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	l := NewSlogLogger(SlogText)
	l.SetOutput(&buf)
	l.SetLevel(slog.LevelDebug)
	previous := getLogger()
	SetLogger(l)
	t.Cleanup(func() { SetLogger(previous) })
	return &buf
}

// TestParseBanRecordsWarnsOnSkippedLines pins that unparseable lines are
// reported: a jail whose every record is rejected (e.g. ticket IDs instead of
// IPs) must not look like a jail with no bans. Blank lines are not counted.
func TestParseBanRecordsWarnsOnSkippedLines(t *testing.T) {
	input := "192.168.1.100 2025-07-20 14:30:39 + 2025-07-20 14:40:39 remaining\n" +
		"\n" +
		"ticket-42 2025-07-20 14:36:59 + 2025-07-20 14:46:59 remaining\n" +
		"not-an-ip\n"

	t.Run("skipped lines are counted and logged", func(t *testing.T) {
		buf := captureFail2banLog(t)
		records, err := NewBanRecordParser().ParseBanRecords(input, "sshd")
		require.NoError(t, err)
		require.Len(t, records, 1)
		assert.Contains(t, buf.String(), "Skipped unparseable ban record lines")
		assert.Contains(t, buf.String(), "skipped=2")
		assert.Contains(t, buf.String(), "jail=sshd")
	})

	t.Run("clean input logs no warning", func(t *testing.T) {
		buf := captureFail2banLog(t)
		records, err := NewBanRecordParser().ParseBanRecords(benchmarkBanRecordOutput, "sshd")
		require.NoError(t, err)
		require.Len(t, records, len(benchmarkBanRecordData))
		assert.NotContains(t, buf.String(), "Skipped unparseable")
	})
}

// TestParseWithLayoutKeysCacheByLayout pins that the time cache key includes
// the layout: keyed by the string alone, a day-first parse returned the cached
// month-first result.
func TestParseWithLayoutKeysCacheByLayout(t *testing.T) {
	cache, err := NewBoundedTimeCache(10)
	require.NoError(t, err)

	monthFirst, err := cache.ParseWithLayout("01/02/2026 10:00", "01/02/2006 15:04")
	require.NoError(t, err)
	dayFirst, err := cache.ParseWithLayout("01/02/2026 10:00", "02/01/2006 15:04")
	require.NoError(t, err)

	assert.Equal(t, time.January, monthFirst.Month())
	assert.Equal(t, 2, monthFirst.Day())
	assert.Equal(t, time.February, dayFirst.Month())
	assert.Equal(t, 1, dayFirst.Day())
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

	// fail2ban emits zone-less local timestamps, parsed in the local zone.
	expected := time.Date(2025, 7, 20, 14, 30, 39, 0, time.Local)
	if time1.Unix() != expected.Unix() {
		t.Errorf("Parsed time incorrect: got %v, expected %v", time1, expected)
	}
}
