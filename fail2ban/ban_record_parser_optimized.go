package fail2ban

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// OptimizedBanRecordParser provides high-performance parsing of ban records
type OptimizedBanRecordParser struct {
	// Pre-allocated buffers for zero-allocation parsing
	fieldBuf   []string
	timeBuf    []byte
	stringPool sync.Pool
	recordPool sync.Pool
	timeCache  *FastTimeCache

	// Statistics for monitoring
	parseCount int64
	errorCount int64
}

// FastTimeCache provides ultra-fast time parsing with minimal allocations
type FastTimeCache struct {
	layout      string
	layoutBytes []byte
	parseCache  sync.Map
	stringPool  sync.Pool
}

// NewOptimizedBanRecordParser creates a new high-performance ban record parser
func NewOptimizedBanRecordParser() *OptimizedBanRecordParser {
	parser := &OptimizedBanRecordParser{
		fieldBuf:  make([]string, 0, 16), // Pre-allocate for max expected fields
		timeBuf:   make([]byte, 0, 32),   // Pre-allocate for time string building
		timeCache: NewFastTimeCache("2006-01-02 15:04:05"),
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

	return parser
}

// NewFastTimeCache creates an optimized time cache
func NewFastTimeCache(layout string) *FastTimeCache {
	cache := &FastTimeCache{
		layout:      layout,
		layoutBytes: []byte(layout),
	}

	cache.stringPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 32)
			return &b
		},
	}

	return cache
}

// ParseTimeOptimized parses time with minimal allocations
func (ftc *FastTimeCache) ParseTimeOptimized(timeStr string) (time.Time, error) {
	// Fast path: check cache
	if cached, ok := ftc.parseCache.Load(timeStr); ok {
		return cached.(time.Time), nil
	}

	// Parse and cache - only cache successful parses
	t, err := time.Parse(ftc.layout, timeStr)
	if err == nil {
		ftc.parseCache.Store(timeStr, t)
	}
	return t, err
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

// ParseBanRecordLineOptimized parses a single line with maximum performance
func (obp *OptimizedBanRecordParser) ParseBanRecordLineOptimized(line, jail string) (*BanRecord, error) {
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
	fieldsPtr := obp.stringPool.Get().(*[]string)
	fields := (*fieldsPtr)[:0] // Reset slice but keep capacity
	defer func() {
		*fieldsPtr = fields[:0]
		obp.stringPool.Put(fieldsPtr)
	}()

	// Fast field parsing - avoid strings.Fields allocation
	fields = fastSplitFields(line, fields)
	if len(fields) < 1 {
		return nil, ErrInsufficientFields
	}

	// Get pooled record
	record := obp.recordPool.Get().(*BanRecord)
	defer obp.recordPool.Put(record)

	// Reset record fields
	*record = BanRecord{
		Jail: jail,
		IP:   fields[0],
	}

	// Fast path for full format (8+ fields)
	if len(fields) >= 8 {
		return obp.parseFullFormat(fields, record)
	}

	// Fallback for simple format
	record.BannedAt = time.Now()
	record.Remaining = "unknown"

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
func (obp *OptimizedBanRecordParser) parseFullFormat(fields []string, record *BanRecord) (*BanRecord, error) {
	// Build time strings efficiently
	bannedStr := obp.timeCache.BuildTimeStringOptimized(fields[1], fields[2])
	unbanStr := obp.timeCache.BuildTimeStringOptimized(fields[4], fields[5])

	// Parse ban time
	tBan, err := obp.timeCache.ParseTimeOptimized(bannedStr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"jail":      record.Jail,
			"ip":        record.IP,
			"bannedStr": bannedStr,
		}).Warnf("Failed to parse ban time: %v", err)
		return nil, ErrInvalidBanTime
	}

	// Parse unban time with fallback
	tUnban, err := obp.timeCache.ParseTimeOptimized(unbanStr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"jail":     record.Jail,
			"ip":       record.IP,
			"unbanStr": unbanStr,
		}).Warnf("Failed to parse unban time: %v", err)
		tUnban = time.Now().Add(24 * time.Hour) // 24h fallback
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

// ParseBanRecordsOptimized parses multiple records with maximum efficiency
func (obp *OptimizedBanRecordParser) ParseBanRecordsOptimized(output string, jail string) ([]BanRecord, error) {
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

		record, err := obp.ParseBanRecordLineOptimized(line, jail)
		if err != nil {
			obp.errorCount++
			continue // Skip invalid lines
		}

		if record != nil {
			records = append(records, *record)
			obp.parseCount++
		}
	}

	return records, nil
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
	days := sec / 86400
	h := (sec % 86400) / 3600
	m := (sec % 3600) / 60
	s := sec % 60

	// Pre-allocate buffer for DD:HH:MM:SS format (11 chars)
	buf := make([]byte, 0, 11)

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

// GetStats returns parsing statistics
func (obp *OptimizedBanRecordParser) GetStats() (parseCount, errorCount int64) {
	return obp.parseCount, obp.errorCount
}

// Global optimized parser instance
var optimizedBanRecordParser = NewOptimizedBanRecordParser()

// ParseBanRecordLineUltraOptimized parses a ban record line using the optimized parser
func ParseBanRecordLineUltraOptimized(line, jail string) (*BanRecord, error) {
	return optimizedBanRecordParser.ParseBanRecordLineOptimized(line, jail)
}

// ParseBanRecordsUltraOptimized parses multiple ban records using the optimized parser
func ParseBanRecordsUltraOptimized(output, jail string) ([]BanRecord, error) {
	return optimizedBanRecordParser.ParseBanRecordsOptimized(output, jail)
}
