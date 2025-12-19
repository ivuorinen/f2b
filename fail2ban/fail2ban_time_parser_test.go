package fail2ban

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/shared"
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

// TestTimeParsingCache_BoundedEviction verifies that the cache doesn't grow unbounded
func TestTimeParsingCache_BoundedEviction(t *testing.T) {
	cache := NewTimeParsingCache("2006-01-02 15:04:05")

	// Fill cache beyond threshold to trigger eviction
	maxSize := int(float64(shared.CacheMaxSize)*shared.CacheEvictionThreshold) + 100

	for i := 0; i < maxSize; i++ {
		// Generate unique time strings
		timeStr := fmt.Sprintf("2024-01-01 %02d:%02d:%02d",
			i%24, (i/24)%60, (i/1440)%60)
		_, err := cache.ParseTime(timeStr)
		require.NoError(t, err)
	}

	// Verify cache was evicted and didn't grow unbounded
	size := cache.parseCache.Size()
	assert.Less(t, size, shared.CacheMaxSize,
		"Cache should have evicted entries to stay under max size")
	assert.Greater(t, size, 0,
		"Cache should still contain entries after eviction")

	t.Logf("Cache size after filling with %d entries: %d (max: %d)",
		maxSize, size, shared.CacheMaxSize)
}
