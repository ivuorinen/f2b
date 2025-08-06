package fail2ban

import (
	"testing"
	"time"
)

func TestTimeParsingCache(t *testing.T) {
	cache := NewTimeParsingCache("2006-01-02 15:04:05")

	// Test basic parsing
	testTime := "2023-12-01 14:30:45"
	parsed1, err := cache.ParseTime(testTime)
	if err != nil {
		t.Fatalf("Failed to parse time: %v", err)
	}

	// Test cache hit
	parsed2, err := cache.ParseTime(testTime)
	if err != nil {
		t.Fatalf("Failed to parse cached time: %v", err)
	}

	if !parsed1.Equal(parsed2) {
		t.Errorf("Cached time doesn't match original: %v vs %v", parsed1, parsed2)
	}

	// Verify the parsed time
	expected := time.Date(2023, 12, 1, 14, 30, 45, 0, time.UTC)
	if !parsed1.Equal(expected) {
		t.Errorf("Parsed time incorrect: got %v, want %v", parsed1, expected)
	}
}

func TestBuildTimeString(t *testing.T) {
	cache := NewTimeParsingCache("2006-01-02 15:04:05")

	result := cache.BuildTimeString("2023-12-01", "14:30:45")
	expected := "2023-12-01 14:30:45"

	if result != expected {
		t.Errorf("BuildTimeString failed: got %s, want %s", result, expected)
	}
}

func TestParseBanTime(t *testing.T) {
	testTime := "2023-12-01 14:30:45"
	parsed, err := ParseBanTime(testTime)
	if err != nil {
		t.Fatalf("ParseBanTime failed: %v", err)
	}

	expected := time.Date(2023, 12, 1, 14, 30, 45, 0, time.UTC)
	if !parsed.Equal(expected) {
		t.Errorf("ParseBanTime incorrect: got %v, want %v", parsed, expected)
	}
}

func TestBuildBanTimeString(t *testing.T) {
	result := BuildBanTimeString("2023-12-01", "14:30:45")
	expected := "2023-12-01 14:30:45"

	if result != expected {
		t.Errorf("BuildBanTimeString failed: got %s, want %s", result, expected)
	}
}

func BenchmarkTimeParsingWithCache(b *testing.B) {
	cache := NewTimeParsingCache("2006-01-02 15:04:05")
	testTime := "2023-12-01 14:30:45"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.ParseTime(testTime)
	}
}

func BenchmarkTimeParsingWithoutCache(b *testing.B) {
	testTime := "2023-12-01 14:30:45"
	layout := "2006-01-02 15:04:05"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = time.Parse(layout, testTime)
	}
}

func BenchmarkBuildTimeString(b *testing.B) {
	cache := NewTimeParsingCache("2006-01-02 15:04:05")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.BuildTimeString("2023-12-01", "14:30:45")
	}
}

func BenchmarkBuildTimeStringNaive(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = "2023-12-01" + " " + "14:30:45"
	}
}
