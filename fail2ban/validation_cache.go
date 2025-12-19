// Package fail2ban provides validation caching utilities for performance optimization.
// This module handles caching of validation results to avoid repeated expensive validation
// operations, with metrics support and thread-safe cache management.
package fail2ban

import (
	"sync"

	"github.com/ivuorinen/f2b/shared"
)

// ValidationCache provides thread-safe caching for validation results with bounded size.
// The cache automatically evicts entries when it reaches capacity to prevent memory exhaustion.
type ValidationCache struct {
	mu    sync.RWMutex
	cache map[string]error
}

// NewValidationCache creates a new bounded validation cache.
// The cache will automatically evict entries when it reaches capacity to prevent
// unbounded memory growth in long-running processes. See constants.go for cache limits.
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

	// Check if eviction is needed (at configured threshold)
	if len(vc.cache) >= int(float64(shared.CacheMaxSize)*shared.CacheEvictionThreshold) {
		vc.evictEntries()
	}

	vc.cache[key] = err
}

// evictEntries removes a portion of cache entries to free up space.
// Must be called with vc.mu held (Lock, not RLock).
// Evicts entries based on shared.CacheEvictionRate using random iteration.
func (vc *ValidationCache) evictEntries() {
	targetSize := int(float64(len(vc.cache)) * (1.0 - shared.CacheEvictionRate))
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

// cachedValidate provides a generic caching wrapper for validation functions
func cachedValidate(
	cache *ValidationCache,
	keyPrefix string,
	value string,
	validator func(string) error,
) error {
	cacheKey := keyPrefix + ":" + value
	if exists, result := cache.Get(cacheKey); exists {
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

	err := validator(value)
	cache.Set(cacheKey, err)
	return err
}

// CachedValidateIP validates an IP address with caching
func CachedValidateIP(ip string) error {
	return cachedValidate(ipValidationCache, "ip", ip, ValidateIP)
}

// CachedValidateJail validates a jail name with caching
func CachedValidateJail(jail string) error {
	return cachedValidate(jailValidationCache, string(shared.ContextKeyJail), jail, ValidateJail)
}

// CachedValidateFilter validates a filter name with caching
func CachedValidateFilter(filter string) error {
	return cachedValidate(filterValidationCache, "filter", filter, ValidateFilter)
}

// CachedValidateCommand validates a command with caching
func CachedValidateCommand(command string) error {
	return cachedValidate(commandValidationCache, string(shared.ContextKeyCommand), command, ValidateCommand)
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
