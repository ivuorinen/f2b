package fail2ban

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ivuorinen/f2b/shared"
)

// Sentinel errors for parser
var (
	ErrEmptyLine          = errors.New("empty line")
	ErrInsufficientFields = errors.New("insufficient fields")
	ErrInvalidBanTime     = errors.New("invalid ban time")
)

// Buffer pool for duration formatting to reduce allocations
var durationBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 11)
		return &b
	},
}

// BoundedTimeCache provides a concurrent-safe bounded cache for parsed times
type BoundedTimeCache struct {
	mu      sync.RWMutex
	cache   map[string]time.Time
	maxSize int
}

// NewBoundedTimeCache creates a new bounded time cache
func NewBoundedTimeCache(maxSize int) (*BoundedTimeCache, error) {
	if maxSize <= 0 {
		return nil, fmt.Errorf("BoundedTimeCache maxSize must be positive, got %d", maxSize)
	}
	return &BoundedTimeCache{
		cache:   make(map[string]time.Time),
		maxSize: maxSize,
	}, nil
}

// Load retrieves a cached time value
func (btc *BoundedTimeCache) Load(key string) (time.Time, bool) {
	btc.mu.RLock()
	t, ok := btc.cache[key]
	btc.mu.RUnlock()
	return t, ok
}

// Store caches a time value with automatic eviction when threshold is reached
func (btc *BoundedTimeCache) Store(key string, value time.Time) {
	btc.mu.Lock()
	defer btc.mu.Unlock()

	// Check if we need to evict before adding
	if len(btc.cache) >= int(float64(btc.maxSize)*shared.CacheEvictionThreshold) {
		btc.evictEntries()
	}

	btc.cache[key] = value
}

// evictEntries removes entries to bring cache back to target size
// Caller must hold btc.mu lock
func (btc *BoundedTimeCache) evictEntries() {
	targetSize := int(float64(len(btc.cache)) * (1.0 - shared.CacheEvictionRate))
	count := 0

	for key := range btc.cache {
		if len(btc.cache) <= targetSize {
			break
		}
		delete(btc.cache, key)
		count++
	}

	getLogger().WithFields(Fields{
		"evicted":   count,
		"remaining": len(btc.cache),
		"max_size":  btc.maxSize,
	}).Debug("Evicted time cache entries")
}

// Size returns the current number of entries in the cache
func (btc *BoundedTimeCache) Size() int {
	btc.mu.RLock()
	defer btc.mu.RUnlock()
	return len(btc.cache)
}

// ParseWithLayout parses a time string using the specified layout with caching.
// This method consolidates the cache-lookup-parse-store pattern used across
// different time parsing caches in the codebase.
func (btc *BoundedTimeCache) ParseWithLayout(timeStr, layout string) (time.Time, error) {
	// Fast path: check cache
	if cached, ok := btc.Load(timeStr); ok {
		return cached, nil
	}

	// Parse and cache - only cache successful parses
	t, err := time.Parse(layout, timeStr)
	if err == nil {
		btc.Store(timeStr, t)
	}
	return t, err
}

// BanRecordParser provides high-performance parsing of ban records
type BanRecordParser struct {
	// Pools for zero-allocation parsing (goroutine-safe)
	stringPool sync.Pool
	recordPool sync.Pool
	timeCache  *FastTimeCache

	// Statistics for monitoring
	parseCount int64
	errorCount int64
}

// FastTimeCache provides ultra-fast time parsing with minimal allocations
type FastTimeCache struct {
	layout     string
	parseCache *BoundedTimeCache // Bounded cache with max 10k entries
	stringPool sync.Pool
}

// NewBanRecordParser creates a new high-performance ban record parser
func NewBanRecordParser() (*BanRecordParser, error) {
	timeCache, err := NewFastTimeCache(shared.TimeFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to create parser: %w", err)
	}

	parser := &BanRecordParser{
		timeCache: timeCache,
	}

	// String pool for reusing field slices
	parser.stringPool = sync.Pool{
		New: func() interface{} {
			s := make([]string, 0, 16)
			return &s
		},
	}

	// Record pool for reusing BanRecord objects
	parser.recordPool = sync.Pool{
		New: func() interface{} {
			return &BanRecord{}
		},
	}

	return parser, nil
}

// NewFastTimeCache creates an optimized time cache
func NewFastTimeCache(layout string) (*FastTimeCache, error) {
	parseCache, err := NewBoundedTimeCache(shared.CacheMaxSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create time cache: %w", err)
	}

	cache := &FastTimeCache{
		layout:     layout,
		parseCache: parseCache,
	}

	cache.stringPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 32)
			return &b
		},
	}

	return cache, nil
}

// ParseTimeOptimized parses time with minimal allocations
func (ftc *FastTimeCache) ParseTimeOptimized(timeStr string) (time.Time, error) {
	return ftc.parseCache.ParseWithLayout(timeStr, ftc.layout)
}

// BuildTimeStringOptimized builds time string with zero allocations using byte buffer
func (ftc *FastTimeCache) BuildTimeStringOptimized(dateStr, timeStr string) string {
	bufPtr := ftc.stringPool.Get().(*[]byte)
	buf := *bufPtr
	defer func() {
		buf = buf[:0] // Reset buffer
		*bufPtr = buf
		ftc.stringPool.Put(bufPtr)
	}()

	// Calculate required capacity
	totalLen := len(dateStr) + 1 + len(timeStr)
	if cap(buf) < totalLen {
		buf = make([]byte, 0, totalLen)
		*bufPtr = buf
	}

	// Build string using byte operations
	buf = append(buf, dateStr...)
	buf = append(buf, ' ')
	buf = append(buf, timeStr...)

	// Convert to string - Go compiler will optimize this
	return string(buf)
}

// ParseBanRecordLine parses a single line with maximum performance
func (brp *BanRecordParser) ParseBanRecordLine(line, jail string) (*BanRecord, error) {
	// Fast path: check for empty line
	if len(line) == 0 {
		return nil, ErrEmptyLine
	}

	// Trim whitespace in-place if needed
	line = fastTrimSpace(line)
	if len(line) == 0 {
		return nil, ErrEmptyLine
	}

	// Get pooled field slice
	fieldsPtr := brp.stringPool.Get().(*[]string)
	fields := (*fieldsPtr)[:0] // Reset slice but keep capacity
	defer func() {
		*fieldsPtr = fields[:0]
		brp.stringPool.Put(fieldsPtr)
	}()

	// Fast field parsing - avoid strings.Fields allocation
	fields = fastSplitFields(line, fields)
	if len(fields) < 1 {
		return nil, ErrInsufficientFields
	}

	// Validate jail name for path traversal
	if jail == "" || strings.ContainsAny(jail, "/\\") || strings.Contains(jail, "..") {
		return nil, fmt.Errorf("invalid jail name: contains unsafe characters")
	}

	// Validate IP address format
	if fields[0] != "" && net.ParseIP(fields[0]) == nil {
		return nil, fmt.Errorf(shared.ErrInvalidIPAddress, fields[0])
	}

	// Get pooled record
	record := brp.recordPool.Get().(*BanRecord)
	defer brp.recordPool.Put(record)

	// Reset record fields
	*record = BanRecord{
		Jail: jail,
		IP:   fields[0],
	}

	// Fast path for full format (8+ fields)
	if len(fields) >= 8 {
		return brp.parseFullFormat(fields, record)
	}

	// Fallback for simple format
	record.BannedAt = time.Now()
	record.Remaining = shared.UnknownValue

	// Return a copy since we're pooling the original
	result := &BanRecord{
		Jail:      record.Jail,
		IP:        record.IP,
		BannedAt:  record.BannedAt,
		Remaining: record.Remaining,
	}

	return result, nil
}

// parseFullFormat handles the full 8-field format efficiently
func (brp *BanRecordParser) parseFullFormat(fields []string, record *BanRecord) (*BanRecord, error) {
	// Build time strings efficiently
	bannedStr := brp.timeCache.BuildTimeStringOptimized(fields[1], fields[2])
	unbanStr := brp.timeCache.BuildTimeStringOptimized(fields[4], fields[5])

	// Parse ban time
	tBan, err := brp.timeCache.ParseTimeOptimized(bannedStr)
	if err != nil {
		getLogger().WithFields(Fields{
			"jail":      record.Jail,
			"ip":        record.IP,
			"bannedStr": bannedStr,
		}).Warnf("Failed to parse ban time: %v", err)
		return nil, ErrInvalidBanTime
	}

	// Parse unban time with fallback
	tUnban, err := brp.timeCache.ParseTimeOptimized(unbanStr)
	if err != nil {
		getLogger().WithFields(Fields{
			"jail":     record.Jail,
			"ip":       record.IP,
			"unbanStr": unbanStr,
		}).Warnf("Failed to parse unban time: %v", err)
		tUnban = time.Now().Add(shared.DefaultBanDuration) // 24h fallback
	}

	// Calculate remaining time efficiently
	now := time.Now()
	rem := tUnban.Unix() - now.Unix()
	if rem < 0 {
		rem = 0
	}

	// Set parsed values
	record.BannedAt = tBan
	record.Remaining = formatDurationOptimized(rem)

	// Return a copy since we're pooling the original
	result := &BanRecord{
		Jail:      record.Jail,
		IP:        record.IP,
		BannedAt:  record.BannedAt,
		Remaining: record.Remaining,
	}

	return result, nil
}

// ParseBanRecords parses multiple records with maximum efficiency
func (brp *BanRecordParser) ParseBanRecords(output string, jail string) ([]BanRecord, error) {
	if len(output) == 0 {
		return []BanRecord{}, nil
	}

	// Fast line splitting without allocation where possible
	lines := fastSplitLines(strings.TrimSpace(output))
	records := make([]BanRecord, 0, len(lines))

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		record, err := brp.ParseBanRecordLine(line, jail)
		if err != nil {
			atomic.AddInt64(&brp.errorCount, 1)
			continue // Skip invalid lines
		}

		if record != nil {
			records = append(records, *record)
			atomic.AddInt64(&brp.parseCount, 1)
		}
	}

	return records, nil
}

// GetStats returns parsing statistics
func (brp *BanRecordParser) GetStats() (parseCount, errorCount int64) {
	return atomic.LoadInt64(&brp.parseCount), atomic.LoadInt64(&brp.errorCount)
}

// fastTrimSpace trims whitespace efficiently
func fastTrimSpace(s string) string {
	start := 0
	end := len(s)

	// Trim leading whitespace
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}

	// Trim trailing whitespace
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}

	return s[start:end]
}

// fastSplitFields splits on whitespace efficiently, reusing provided slice
func fastSplitFields(s string, fields []string) []string {
	fields = fields[:0] // Reset but keep capacity

	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if i > start {
				fields = append(fields, s[start:i])
			}
			// Skip consecutive whitespace
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			start = i
			i-- // Compensate for loop increment
		}
	}

	// Add final field if any
	if start < len(s) {
		fields = append(fields, s[start:])
	}

	return fields
}

// fastSplitLines splits on newlines efficiently
func fastSplitLines(s string) []string {
	if len(s) == 0 {
		return nil
	}

	lines := make([]string, 0, strings.Count(s, "\n")+1)
	start := 0

	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}

	// Add final line if any
	if start < len(s) {
		lines = append(lines, s[start:])
	}

	return lines
}

// formatDurationOptimized formats duration efficiently in DD:HH:MM:SS format to match original
func formatDurationOptimized(sec int64) string {
	days := sec / shared.SecondsPerDay
	h := (sec % shared.SecondsPerDay) / shared.SecondsPerHour
	m := (sec % shared.SecondsPerHour) / shared.SecondsPerMinute
	s := sec % shared.SecondsPerMinute

	// Get buffer from pool to reduce allocations
	bufPtr := durationBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:0]
	defer func() {
		*bufPtr = buf[:0]
		durationBufPool.Put(bufPtr)
	}()

	// Format days (2 digits)
	if days < 10 {
		buf = append(buf, '0')
	}
	buf = strconv.AppendInt(buf, days, 10)
	buf = append(buf, ':')

	// Format hours (2 digits)
	if h < 10 {
		buf = append(buf, '0')
	}
	buf = strconv.AppendInt(buf, h, 10)
	buf = append(buf, ':')

	// Format minutes (2 digits)
	if m < 10 {
		buf = append(buf, '0')
	}
	buf = strconv.AppendInt(buf, m, 10)
	buf = append(buf, ':')

	// Format seconds (2 digits)
	if s < 10 {
		buf = append(buf, '0')
	}
	buf = strconv.AppendInt(buf, s, 10)

	return string(buf)
}

// Global parser instance for reuse
var defaultBanRecordParser = mustCreateParser()

// mustCreateParser creates a parser or panics (used for global init only)
func mustCreateParser() *BanRecordParser {
	parser, err := NewBanRecordParser()
	if err != nil {
		panic(fmt.Sprintf("failed to create default ban record parser: %v", err))
	}
	return parser
}

// ParseBanRecordLineOptimized parses a ban record line using the default parser.
func ParseBanRecordLineOptimized(line, jail string) (*BanRecord, error) {
	return defaultBanRecordParser.ParseBanRecordLine(line, jail)
}

// ParseBanRecordsOptimized parses multiple ban records using the default parser.
func ParseBanRecordsOptimized(output, jail string) ([]BanRecord, error) {
	return defaultBanRecordParser.ParseBanRecords(output, jail)
}

// ParseBanRecordsUltraOptimized is an alias for backward compatibility
func ParseBanRecordsUltraOptimized(output, jail string) ([]BanRecord, error) {
	return ParseBanRecordsOptimized(output, jail)
}

// ParseBanRecordLineUltraOptimized is an alias for backward compatibility
func ParseBanRecordLineUltraOptimized(line, jail string) (*BanRecord, error) {
	return ParseBanRecordLineOptimized(line, jail)
}
