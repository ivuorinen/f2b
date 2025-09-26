// Package fail2ban provides validation caching utilities for performance optimization.
// This module handles caching of validation results to avoid repeated expensive validation
// operations, with metrics support and thread-safe cache management.
package fail2ban

import "sync"

// ValidationCache provides thread-safe caching for validation results
type ValidationCache struct {
	mu    sync.RWMutex
	cache map[string]error
}

// NewValidationCache creates a new validation cache
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

// Set stores a validation result in the cache
func (vc *ValidationCache) Set(key string, err error) {
	vc.mu.Lock()
	defer vc.mu.Unlock()

	vc.cache[key] = err
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
