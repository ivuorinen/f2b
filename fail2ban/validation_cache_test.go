package fail2ban

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// MockMetricsRecorder for testing cache metrics
type MockMetricsRecorder struct {
	mu        sync.Mutex
	cacheHits int
	cacheMiss int
}

func (m *MockMetricsRecorder) RecordValidationCacheHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheHits++
}

func (m *MockMetricsRecorder) RecordValidationCacheMiss() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheMiss++
}

func (m *MockMetricsRecorder) getCounts() (hits, miss int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cacheHits, m.cacheMiss
}

func TestValidationCaching(t *testing.T) {
	// Set up mock metrics recorder
	mockRecorder := &MockMetricsRecorder{}
	SetMetricsRecorder(mockRecorder)

	// Clear caches to start fresh
	ClearValidationCaches()

	tests := []struct {
		name           string
		validator      func(context.Context, string) error
		validInput     string
		expectedHits   int
		expectedMisses int
	}{
		{
			name:           "IP validation caching",
			validator:      CachedValidateIP,
			validInput:     "192.168.1.1",
			expectedHits:   1, // Second call should be a cache hit
			expectedMisses: 1, // First call should be a cache miss
		},
		{
			name:           "Jail validation caching",
			validator:      CachedValidateJail,
			validInput:     "sshd",
			expectedHits:   1,
			expectedMisses: 1,
		},
		{
			name:           "Filter validation caching",
			validator:      CachedValidateFilter,
			validInput:     "sshd",
			expectedHits:   1,
			expectedMisses: 1,
		},
		{
			name:           "Command validation caching",
			validator:      CachedValidateCommand,
			validInput:     "fail2ban-client",
			expectedHits:   1,
			expectedMisses: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset metrics
			mockRecorder.mu.Lock()
			mockRecorder.cacheHits = 0
			mockRecorder.cacheMiss = 0
			mockRecorder.mu.Unlock()

			// Clear caches for this test
			ClearValidationCaches()

			// First call - should be a cache miss
			err := tt.validator(context.Background(), tt.validInput)
			if err != nil {
				t.Fatalf("First validation call failed: %v", err)
			}

			// Second call - should be a cache hit
			err = tt.validator(context.Background(), tt.validInput)
			if err != nil {
				t.Fatalf("Second validation call failed: %v", err)
			}

			// Check metrics
			hits, miss := mockRecorder.getCounts()
			if hits != tt.expectedHits {
				t.Errorf("Expected %d cache hits, got %d", tt.expectedHits, hits)
			}
			if miss != tt.expectedMisses {
				t.Errorf("Expected %d cache misses, got %d", tt.expectedMisses, miss)
			}
		})
	}
}

func TestValidationCacheConcurrency(t *testing.T) {
	// Set up mock metrics recorder
	mockRecorder := &MockMetricsRecorder{}
	SetMetricsRecorder(mockRecorder)
	ClearValidationCaches()

	const numGoroutines = 100
	const numCallsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Launch multiple goroutines to test concurrent access
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numCallsPerGoroutine; j++ {
				// Use the same IP to test caching
				err := CachedValidateIP(context.Background(), "192.168.1.1")
				if err != nil {
					t.Errorf("Concurrent validation failed: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()

	hits, miss := mockRecorder.getCounts()
	totalCalls := numGoroutines * numCallsPerGoroutine

	// Due to concurrency, we might have a few cache misses if multiple goroutines
	// try to validate the same IP before the first result is cached
	// The important thing is that most calls should be cache hits
	if miss == 0 {
		t.Errorf("Expected at least 1 cache miss, got %d", miss)
	}
	if miss > 10 { // Allow up to 10 misses due to race conditions
		t.Errorf("Too many cache misses: got %d, expected <= 10", miss)
	}
	if hits+miss != totalCalls {
		t.Errorf("Cache hits (%d) + misses (%d) != total calls (%d)", hits, miss, totalCalls)
	}

	// Most calls should be hits
	hitRate := float64(hits) / float64(totalCalls)
	if hitRate < 0.9 { // Expect at least 90% hit rate
		t.Errorf("Cache hit rate too low: %.2f%%, expected >= 90%%", hitRate*100)
	}
}

func TestValidationCacheInvalidInput(t *testing.T) {
	// Set up mock metrics recorder
	mockRecorder := &MockMetricsRecorder{}
	SetMetricsRecorder(mockRecorder)
	ClearValidationCaches()

	// Test that errors are also cached
	invalidIP := "invalid.ip.address"

	// First call - should be a cache miss and return error
	err1 := CachedValidateIP(context.Background(), invalidIP)
	if err1 == nil {
		t.Fatal("Expected error for invalid IP, got none")
	}

	// Second call - should be a cache hit and return the same error
	err2 := CachedValidateIP(context.Background(), invalidIP)
	if err2 == nil {
		t.Fatal("Expected error for invalid IP on second call, got none")
	}

	// Both errors should be the same (cached)
	if err1.Error() != err2.Error() {
		t.Errorf("Expected same error message, got %q and %q", err1.Error(), err2.Error())
	}

	hits, miss := mockRecorder.getCounts()
	if miss != 1 {
		t.Errorf("Expected 1 cache miss, got %d", miss)
	}
	if hits != 1 {
		t.Errorf("Expected 1 cache hit, got %d", hits)
	}
}

func BenchmarkValidationCaching(b *testing.B) {
	// Set up mock metrics recorder
	mockRecorder := &MockMetricsRecorder{}
	SetMetricsRecorder(mockRecorder)
	ClearValidationCaches()

	validIP := "192.168.1.1"

	// Warm up the cache
	_ = CachedValidateIP(context.Background(), validIP)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// All calls should hit the cache
			_ = CachedValidateIP(context.Background(), validIP)
		}
	})
}

func BenchmarkValidationNoCaching(b *testing.B) {
	validIP := "192.168.1.1"

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Direct validation without caching
			_ = ValidateIP(validIP)
		}
	})
}

// TestValidationCacheEviction tests that cache eviction works correctly
func TestValidationCacheEviction(t *testing.T) {
	cache := NewValidationCache()

	// Fill cache to trigger eviction (using CacheMaxSize from shared package)
	// Add significantly more than maxSize to guarantee eviction
	entriesToAdd := 11000 // CacheMaxSize is 10000
	for i := 0; i < entriesToAdd; i++ {
		// Add unique keys to cache
		key := fmt.Sprintf("test-key-%d", i)
		cache.Set(key, nil) // nil means valid
	}

	// Verify cache was evicted and didn't grow unbounded
	sizeAfter := cache.Size()
	if sizeAfter > 10000 {
		t.Errorf("Cache should have evicted entries to stay under 10000, got: %d", sizeAfter)
	}
	if sizeAfter == 0 {
		t.Errorf("Cache should not be empty after eviction, got size: %d", sizeAfter)
	}

	t.Logf("Cache evicted successfully after adding %d entries: final size %d", entriesToAdd, sizeAfter)
}
