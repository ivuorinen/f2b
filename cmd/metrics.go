package cmd

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics collector for performance monitoring and observability
type Metrics struct {
	// Command execution metrics
	CommandExecutions    int64
	CommandFailures      int64
	CommandTotalDuration int64 // in milliseconds

	// Ban/Unban operation metrics
	BanOperations   int64
	UnbanOperations int64
	BanFailures     int64
	UnbanFailures   int64

	// Client operation metrics
	ClientOperations    int64
	ClientFailures      int64
	ClientTotalDuration int64 // in milliseconds

	// Validation metrics
	ValidationCacheHits int64
	ValidationCacheMiss int64
	ValidationFailures  int64

	// System resource metrics
	MaxMemoryUsage int64 // in bytes
	GoroutineCount int64

	// Timing histograms (buckets for latency distribution)
	commandLatencyBuckets map[string]*LatencyBucket
	clientLatencyBuckets  map[string]*LatencyBucket
	mu                    sync.RWMutex

	startTime time.Time
}

// LatencyBucket represents latency distribution buckets
type LatencyBucket struct {
	Under1ms   int64
	Under10ms  int64
	Under100ms int64
	Under1s    int64
	Under10s   int64
	Over10s    int64
	Total      int64
	TotalTime  int64 // in milliseconds
}

// NewMetrics creates a new metrics collector
func NewMetrics() *Metrics {
	return &Metrics{
		commandLatencyBuckets: make(map[string]*LatencyBucket),
		clientLatencyBuckets:  make(map[string]*LatencyBucket),
		startTime:             time.Now(),
	}
}

// RecordCommandExecution records metrics for command execution
func (m *Metrics) RecordCommandExecution(command string, duration time.Duration, success bool) {
	atomic.AddInt64(&m.CommandExecutions, 1)
	atomic.AddInt64(&m.CommandTotalDuration, duration.Milliseconds())

	if !success {
		atomic.AddInt64(&m.CommandFailures, 1)
	}

	// Record latency bucket
	m.recordLatencyBucket(m.commandLatencyBuckets, command, duration)
}

// RecordBanOperation records metrics for ban operations
func (m *Metrics) RecordBanOperation(operation string, _ time.Duration, success bool) {
	switch operation {
	case "ban":
		atomic.AddInt64(&m.BanOperations, 1)
		if !success {
			atomic.AddInt64(&m.BanFailures, 1)
		}
	case "unban":
		atomic.AddInt64(&m.UnbanOperations, 1)
		if !success {
			atomic.AddInt64(&m.UnbanFailures, 1)
		}
	}
}

// RecordClientOperation records metrics for client operations
func (m *Metrics) RecordClientOperation(operation string, duration time.Duration, success bool) {
	atomic.AddInt64(&m.ClientOperations, 1)
	atomic.AddInt64(&m.ClientTotalDuration, duration.Milliseconds())

	if !success {
		atomic.AddInt64(&m.ClientFailures, 1)
	}

	// Record latency bucket
	m.recordLatencyBucket(m.clientLatencyBuckets, operation, duration)
}

// RecordValidationCacheHit records validation cache hits
func (m *Metrics) RecordValidationCacheHit() {
	atomic.AddInt64(&m.ValidationCacheHits, 1)
}

// RecordValidationCacheMiss records validation cache misses
func (m *Metrics) RecordValidationCacheMiss() {
	atomic.AddInt64(&m.ValidationCacheMiss, 1)
}

// RecordValidationFailure records validation failures
func (m *Metrics) RecordValidationFailure() {
	atomic.AddInt64(&m.ValidationFailures, 1)
}

// UpdateMemoryUsage updates the maximum memory usage
func (m *Metrics) UpdateMemoryUsage(bytes int64) {
	for {
		current := atomic.LoadInt64(&m.MaxMemoryUsage)
		if bytes <= current {
			break
		}
		if atomic.CompareAndSwapInt64(&m.MaxMemoryUsage, current, bytes) {
			break
		}
	}
}

// UpdateGoroutineCount updates the goroutine count
func (m *Metrics) UpdateGoroutineCount(count int64) {
	atomic.StoreInt64(&m.GoroutineCount, count)
}

// recordLatencyBucket records latency in appropriate bucket
func (m *Metrics) recordLatencyBucket(buckets map[string]*LatencyBucket, operation string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	bucket, exists := buckets[operation]
	if !exists {
		bucket = &LatencyBucket{}
		buckets[operation] = bucket
	}

	ms := duration.Milliseconds()
	atomic.AddInt64(&bucket.Total, 1)
	atomic.AddInt64(&bucket.TotalTime, ms)

	switch {
	case duration < time.Millisecond:
		atomic.AddInt64(&bucket.Under1ms, 1)
	case duration < 10*time.Millisecond:
		atomic.AddInt64(&bucket.Under10ms, 1)
	case duration < 100*time.Millisecond:
		atomic.AddInt64(&bucket.Under100ms, 1)
	case duration < time.Second:
		atomic.AddInt64(&bucket.Under1s, 1)
	case duration < 10*time.Second:
		atomic.AddInt64(&bucket.Under10s, 1)
	default:
		atomic.AddInt64(&bucket.Over10s, 1)
	}
}

// GetSnapshot returns a snapshot of current metrics
func (m *Metrics) GetSnapshot() MetricsSnapshot {
	m.mu.RLock()

	// Copy command latency buckets
	commandBuckets := make(map[string]LatencyBucketSnapshot)
	for op, bucket := range m.commandLatencyBuckets {
		commandBuckets[op] = LatencyBucketSnapshot{
			Under1ms:   atomic.LoadInt64(&bucket.Under1ms),
			Under10ms:  atomic.LoadInt64(&bucket.Under10ms),
			Under100ms: atomic.LoadInt64(&bucket.Under100ms),
			Under1s:    atomic.LoadInt64(&bucket.Under1s),
			Under10s:   atomic.LoadInt64(&bucket.Under10s),
			Over10s:    atomic.LoadInt64(&bucket.Over10s),
			Total:      atomic.LoadInt64(&bucket.Total),
			TotalTime:  atomic.LoadInt64(&bucket.TotalTime),
		}
	}

	// Copy client latency buckets
	clientBuckets := make(map[string]LatencyBucketSnapshot)
	for op, bucket := range m.clientLatencyBuckets {
		clientBuckets[op] = LatencyBucketSnapshot{
			Under1ms:   atomic.LoadInt64(&bucket.Under1ms),
			Under10ms:  atomic.LoadInt64(&bucket.Under10ms),
			Under100ms: atomic.LoadInt64(&bucket.Under100ms),
			Under1s:    atomic.LoadInt64(&bucket.Under1s),
			Under10s:   atomic.LoadInt64(&bucket.Under10s),
			Over10s:    atomic.LoadInt64(&bucket.Over10s),
			Total:      atomic.LoadInt64(&bucket.Total),
			TotalTime:  atomic.LoadInt64(&bucket.TotalTime),
		}
	}

	m.mu.RUnlock()

	return MetricsSnapshot{
		// Command metrics
		CommandExecutions:    atomic.LoadInt64(&m.CommandExecutions),
		CommandFailures:      atomic.LoadInt64(&m.CommandFailures),
		CommandTotalDuration: atomic.LoadInt64(&m.CommandTotalDuration),

		// Ban/Unban metrics
		BanOperations:   atomic.LoadInt64(&m.BanOperations),
		UnbanOperations: atomic.LoadInt64(&m.UnbanOperations),
		BanFailures:     atomic.LoadInt64(&m.BanFailures),
		UnbanFailures:   atomic.LoadInt64(&m.UnbanFailures),

		// Client metrics
		ClientOperations:    atomic.LoadInt64(&m.ClientOperations),
		ClientFailures:      atomic.LoadInt64(&m.ClientFailures),
		ClientTotalDuration: atomic.LoadInt64(&m.ClientTotalDuration),

		// Validation metrics
		ValidationCacheHits: atomic.LoadInt64(&m.ValidationCacheHits),
		ValidationCacheMiss: atomic.LoadInt64(&m.ValidationCacheMiss),
		ValidationFailures:  atomic.LoadInt64(&m.ValidationFailures),

		// System metrics
		MaxMemoryUsage: atomic.LoadInt64(&m.MaxMemoryUsage),
		GoroutineCount: atomic.LoadInt64(&m.GoroutineCount),

		// Latency buckets
		CommandLatencyBuckets: commandBuckets,
		ClientLatencyBuckets:  clientBuckets,

		// Uptime
		UptimeSeconds: int64(time.Since(m.startTime).Seconds()),
	}
}

// MetricsSnapshot represents a point-in-time snapshot of metrics
type MetricsSnapshot struct {
	// Command execution metrics
	CommandExecutions    int64 `json:"command_executions"`
	CommandFailures      int64 `json:"command_failures"`
	CommandTotalDuration int64 `json:"command_total_duration_ms"`

	// Ban/Unban operation metrics
	BanOperations   int64 `json:"ban_operations"`
	UnbanOperations int64 `json:"unban_operations"`
	BanFailures     int64 `json:"ban_failures"`
	UnbanFailures   int64 `json:"unban_failures"`

	// Client operation metrics
	ClientOperations    int64 `json:"client_operations"`
	ClientFailures      int64 `json:"client_failures"`
	ClientTotalDuration int64 `json:"client_total_duration_ms"`

	// Validation metrics
	ValidationCacheHits int64 `json:"validation_cache_hits"`
	ValidationCacheMiss int64 `json:"validation_cache_miss"`
	ValidationFailures  int64 `json:"validation_failures"`

	// System resource metrics
	MaxMemoryUsage int64 `json:"max_memory_usage_bytes"`
	GoroutineCount int64 `json:"goroutine_count"`
	UptimeSeconds  int64 `json:"uptime_seconds"`

	// Latency distribution
	CommandLatencyBuckets map[string]LatencyBucketSnapshot `json:"command_latency_buckets"`
	ClientLatencyBuckets  map[string]LatencyBucketSnapshot `json:"client_latency_buckets"`
}

// LatencyBucketSnapshot represents a snapshot of latency bucket
type LatencyBucketSnapshot struct {
	Under1ms   int64 `json:"under_1ms"`
	Under10ms  int64 `json:"under_10ms"`
	Under100ms int64 `json:"under_100ms"`
	Under1s    int64 `json:"under_1s"`
	Under10s   int64 `json:"under_10s"`
	Over10s    int64 `json:"over_10s"`
	Total      int64 `json:"total"`
	TotalTime  int64 `json:"total_time_ms"`
}

// GetAverageLatency calculates average latency for the bucket
func (l LatencyBucketSnapshot) GetAverageLatency() float64 {
	if l.Total == 0 {
		return 0
	}
	return float64(l.TotalTime) / float64(l.Total)
}

// TimedOperation provides instrumentation for timed operations
type TimedOperation struct {
	metrics   *Metrics
	operation string
	category  string
	startTime time.Time
}

// NewTimedOperation creates a new timed operation
func NewTimedOperation(_ context.Context, metrics *Metrics, category, operation string) *TimedOperation {
	return &TimedOperation{
		metrics:   metrics,
		operation: operation,
		category:  category,
		startTime: time.Now(),
	}
}

// Finish completes the timed operation and records metrics
func (t *TimedOperation) Finish(success bool) {
	duration := time.Since(t.startTime)

	switch t.category {
	case "command":
		t.metrics.RecordCommandExecution(t.operation, duration, success)
	case "client":
		t.metrics.RecordClientOperation(t.operation, duration, success)
	case "ban":
		t.metrics.RecordBanOperation(t.operation, duration, success)
	}

	// Note: Additional context logging could be added here if needed
}

// Global metrics instance
var globalMetrics = NewMetrics()

// GetGlobalMetrics returns the global metrics instance
func GetGlobalMetrics() *Metrics {
	return globalMetrics
}

// SetGlobalMetrics sets a new global metrics instance
func SetGlobalMetrics(metrics *Metrics) {
	globalMetrics = metrics
}
