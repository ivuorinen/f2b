package fail2ban

import (
	"sync"
	"testing"
)

func TestOptimizedLogProcessor_ConcurrentCacheAccess(t *testing.T) {
	processor := NewOptimizedLogProcessor()

	// Number of goroutines and operations per goroutine
	numGoroutines := 100
	opsPerGoroutine := 100

	var wg sync.WaitGroup

	// Start multiple goroutines that increment cache statistics
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for j := 0; j < opsPerGoroutine; j++ {
				// Simulate cache hits and misses
				processor.cacheHits.Add(1)
				processor.cacheMisses.Add(1)

				// Also read the stats
				hits, misses := processor.GetCacheStats()

				// Ensure values are monotonically increasing
				if hits < 0 || misses < 0 {
					t.Errorf("Cache stats should not be negative: hits=%d, misses=%d", hits, misses)
				}
			}
		}()
	}

	wg.Wait()

	// Verify final counts
	finalHits, finalMisses := processor.GetCacheStats()
	expectedCount := int64(numGoroutines * opsPerGoroutine)

	if finalHits != expectedCount {
		t.Errorf("Expected %d cache hits, got %d", expectedCount, finalHits)
	}

	if finalMisses != expectedCount {
		t.Errorf("Expected %d cache misses, got %d", expectedCount, finalMisses)
	}
}

func TestOptimizedLogProcessor_ConcurrentCacheClear(t *testing.T) {
	processor := NewOptimizedLogProcessor()

	// Number of goroutines
	numGoroutines := 50

	var wg sync.WaitGroup

	// Start goroutines that increment stats and clear caches concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Half increment, half clear
			if id%2 == 0 {
				// Incrementer goroutines
				for j := 0; j < 100; j++ {
					processor.cacheHits.Add(1)
					processor.cacheMisses.Add(1)
				}
			} else {
				// Clearer goroutines
				for j := 0; j < 10; j++ {
					processor.ClearCaches()
				}
			}
		}(i)
	}

	wg.Wait()

	// Test should complete without races - exact final values don't matter
	// since clears can happen at any time
	hits, misses := processor.GetCacheStats()

	// Values should be non-negative
	if hits < 0 || misses < 0 {
		t.Errorf("Cache stats should not be negative after concurrent operations: hits=%d, misses=%d", hits, misses)
	}
}

func TestOptimizedLogProcessor_CacheStatsConsistency(t *testing.T) {
	processor := NewOptimizedLogProcessor()

	// Test initial state
	hits, misses := processor.GetCacheStats()
	if hits != 0 || misses != 0 {
		t.Errorf("Initial cache stats should be zero: hits=%d, misses=%d", hits, misses)
	}

	// Test increment operations
	processor.cacheHits.Add(5)
	processor.cacheMisses.Add(3)

	hits, misses = processor.GetCacheStats()
	if hits != 5 || misses != 3 {
		t.Errorf("Cache stats after increment: expected hits=5, misses=3; got hits=%d, misses=%d", hits, misses)
	}

	// Test clear operation
	processor.ClearCaches()

	hits, misses = processor.GetCacheStats()
	if hits != 0 || misses != 0 {
		t.Errorf("Cache stats after clear should be zero: hits=%d, misses=%d", hits, misses)
	}
}

func BenchmarkOptimizedLogProcessor_ConcurrentCacheStats(b *testing.B) {
	processor := NewOptimizedLogProcessor()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Simulate cache operations
			processor.cacheHits.Add(1)
			processor.cacheMisses.Add(1)

			// Read stats
			processor.GetCacheStats()
		}
	})
}
