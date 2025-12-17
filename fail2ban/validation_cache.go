// Package fail2ban provides validation caching utilities for performance optimization.
// This module handles caching of validation results to avoid repeated expensive validation
// operations, with metrics support and thread-safe cache management.
package fail2ban

import "sync"

const (
	// maxCacheSize limits the number of entries in each validation cache.
	// When the cache reaches this size, older entries are evicted to prevent
	// unbounded memory growth in long-running processes.
	maxCacheSize = 10000

	// evictionThreshold determines when to trigger eviction.
	// When cache size reaches this percentage of maxCacheSize, we evict entries.
	evictionThreshold = 0.9 // 90% full

	// evictionRate determines how much of the cache to clear during eviction.
	// We evict this percentage of entries to avoid frequent evictions.
	evictionRate = 0.25 // Remove 25% of entries
)

// ValidationCache provides thread-safe caching for validation results with bounded size.
// The cache automatically evicts entries when it reaches capacity to prevent memory exhaustion.
type ValidationCache struct {
	mu    sync.RWMutex
	cache map[string]error
}

// NewValidationCache creates a new bounded validation cache.
// The cache will automatically evict 25% of entries when it reaches 90% of maxCacheSize (10000).
// This prevents unbounded memory growth in long-running processes.
func NewValidationCache() *ValidationCache {
	return &ValidationCache{
		cache: make(map[string]error),
	}
}

// Get retrieves a cached validation result
func (vc *ValidationCache) Get(key string) (bool, error) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	result, exists := vc.cache[key]
	return exists, result
}

// Set stores a validation result in the cache.
// If the cache is at capacity, it automatically evicts a portion of entries.
func (vc *ValidationCache) Set(key string, err error) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	// Check if eviction is needed (at 90% capacity)
	if len(vc.cache) >= int(float64(maxCacheSize)*evictionThreshold) {
		vc.evictEntries()
	}

	vc.cache[key] = err
}

// evictEntries removes a portion of cache entries to free up space.
// Must be called with vc.mu held (Lock, not RLock).
// Evicts approximately evictionRate (25%) of entries using random iteration.
func (vc *ValidationCache) evictEntries() {
	targetSize := int(float64(len(vc.cache)) * (1.0 - evictionRate))
	count := 0

	// Go map iteration is random, so this effectively evicts random entries
	for key := range vc.cache {
		if len(vc.cache) <= targetSize {
			break
		}
		delete(vc.cache, key)
		count++
	}

	// Log eviction for observability (optional, could use metrics)
	if count > 0 {
		getLogger().WithField("evicted", count).WithField("remaining", len(vc.cache)).
			Debug("Validation cache evicted entries")
	}
}

// Clear removes all entries from the cache
func (vc *ValidationCache) Clear() {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	// Create a new map instead of deleting entries for better performance
	vc.cache = make(map[string]error)
}

// Size returns the number of entries in the cache
func (vc *ValidationCache) Size() int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	return len(vc.cache)
}

// Global validation caches for frequently used validators
var (
	ipValidationCache      = NewValidationCache()
	jailValidationCache    = NewValidationCache()
	filterValidationCache  = NewValidationCache()
	commandValidationCache = NewValidationCache()

	// metricsRecorder is set by the cmd package to avoid circular dependencies
	metricsRecorder   MetricsRecorder
	metricsRecorderMu sync.RWMutex
)

// SetMetricsRecorder sets the metrics recorder (called by cmd package)
func SetMetricsRecorder(recorder MetricsRecorder) {
	metricsRecorderMu.Lock()
	defer metricsRecorderMu.Unlock()
	metricsRecorder = recorder
}

// getMetricsRecorder returns the current metrics recorder
func getMetricsRecorder() MetricsRecorder {
	metricsRecorderMu.RLock()
	defer metricsRecorderMu.RUnlock()
	return metricsRecorder
}

// CachedValidateIP validates an IP address with caching
func CachedValidateIP(ip string) error {
	cacheKey := "ip:" + ip
	if exists, result := ipValidationCache.Get(cacheKey); exists {
		// Record cache hit in metrics
		if recorder := getMetricsRecorder(); recorder != nil {
			recorder.RecordValidationCacheHit()
		}
		return result
	}

	// Record cache miss in metrics
	if recorder := getMetricsRecorder(); recorder != nil {
		recorder.RecordValidationCacheMiss()
	}

	err := ValidateIP(ip)
	ipValidationCache.Set(cacheKey, err)
	return err
}

// CachedValidateJail validates a jail name with caching
func CachedValidateJail(jail string) error {
	cacheKey := "jail:" + jail
	if exists, result := jailValidationCache.Get(cacheKey); exists {
		// Record cache hit in metrics
		if recorder := getMetricsRecorder(); recorder != nil {
			recorder.RecordValidationCacheHit()
		}
		return result
	}

	// Record cache miss in metrics
	if recorder := getMetricsRecorder(); recorder != nil {
		recorder.RecordValidationCacheMiss()
	}

	err := ValidateJail(jail)
	jailValidationCache.Set(cacheKey, err)
	return err
}

// CachedValidateFilter validates a filter name with caching
func CachedValidateFilter(filter string) error {
	cacheKey := "filter:" + filter
	if exists, result := filterValidationCache.Get(cacheKey); exists {
		// Record cache hit in metrics
		if recorder := getMetricsRecorder(); recorder != nil {
			recorder.RecordValidationCacheHit()
		}
		return result
	}

	// Record cache miss in metrics
	if recorder := getMetricsRecorder(); recorder != nil {
		recorder.RecordValidationCacheMiss()
	}

	err := ValidateFilter(filter)
	filterValidationCache.Set(cacheKey, err)
	return err
}

// CachedValidateCommand validates a command with caching
func CachedValidateCommand(command string) error {
	cacheKey := "command:" + command
	if exists, result := commandValidationCache.Get(cacheKey); exists {
		// Record cache hit in metrics
		if recorder := getMetricsRecorder(); recorder != nil {
			recorder.RecordValidationCacheHit()
		}
		return result
	}

	// Record cache miss in metrics
	if recorder := getMetricsRecorder(); recorder != nil {
		recorder.RecordValidationCacheMiss()
	}

	err := ValidateCommand(command)
	commandValidationCache.Set(cacheKey, err)
	return err
}

// ClearValidationCaches clears all validation caches
func ClearValidationCaches() {
	ipValidationCache.Clear()
	jailValidationCache.Clear()
	filterValidationCache.Clear()
	commandValidationCache.Clear()
}

// GetValidationCacheStats returns statistics for all validation caches
func GetValidationCacheStats() map[string]int {
	return map[string]int{
		"ip_cache_size":      ipValidationCache.Size(),
		"jail_cache_size":    jailValidationCache.Size(),
		"filter_cache_size":  filterValidationCache.Size(),
		"command_cache_size": commandValidationCache.Size(),
	}
}
