package fail2ban

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ivuorinen/f2b/constants"
)

// Sentinel errors for parser
var (
	ErrEmptyLine      = errors.New("empty line")
	ErrInvalidBanTime = errors.New("invalid ban time")
)

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
	if len(btc.cache) >= int(float64(btc.maxSize)*constants.CacheEvictionThreshold) {
		btc.evictEntries()
	}

	btc.cache[key] = value
}

// evictEntries removes entries to bring cache back to target size
// Caller must hold btc.mu lock
func (btc *BoundedTimeCache) evictEntries() {
	targetSize := int(float64(len(btc.cache)) * (1.0 - constants.CacheEvictionRate))
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

// ParseWithLayout parses a time string using the specified layout with caching.
//
// The cache key includes the layout: the parsed time depends on it, and a key
// of timeStr alone returned the first layout's result for every later layout
// (e.g. "01/02/2026" as Jan 2 under both month-first and day-first layouts).
func (btc *BoundedTimeCache) ParseWithLayout(timeStr, layout string) (time.Time, error) {
	key := layout + "\x00" + timeStr
	if cached, ok := btc.Load(key); ok {
		return cached, nil
	}

	// Parse and cache - only cache successful parses.
	// fail2ban-client emits zone-less local timestamps; time.Parse would
	// interpret them as UTC, skewing "remaining" by the host's UTC offset
	// (and clamping fresh bans to 0 east of UTC). Parse in the local zone.
	t, err := time.ParseInLocation(layout, timeStr, time.Local)
	if err == nil {
		btc.Store(key, t)
	}
	return t, err
}

// BanRecordParser parses `fail2ban-client get <jail> banip --with-time`
// output. It is safe for concurrent use: its only state is the
// mutex-guarded time cache.
type BanRecordParser struct {
	timeCache *FastTimeCache
}

// FastTimeCache parses timestamps of one fixed layout through a bounded cache.
type FastTimeCache struct {
	layout     string
	parseCache *BoundedTimeCache
}

// NewBanRecordParser creates a ban record parser. It cannot fail, so it
// returns no error for callers to handle.
func NewBanRecordParser() *BanRecordParser {
	return &BanRecordParser{timeCache: NewFastTimeCache(constants.TimeFormat)}
}

// NewFastTimeCache creates a time cache for layout, bounded to
// constants.CacheMaxSize entries. The size is a positive constant, so unlike
// NewBoundedTimeCache it has no failure to report.
func NewFastTimeCache(layout string) *FastTimeCache {
	return &FastTimeCache{
		layout: layout,
		parseCache: &BoundedTimeCache{
			cache:   make(map[string]time.Time),
			maxSize: constants.CacheMaxSize,
		},
	}
}

// ParseTimeOptimized parses timeStr with the cache's layout, reusing cached results.
func (ftc *FastTimeCache) ParseTimeOptimized(timeStr string) (time.Time, error) {
	return ftc.parseCache.ParseWithLayout(timeStr, ftc.layout)
}

// ParseBanRecordLine parses a single ban record line.
func (brp *BanRecordParser) ParseBanRecordLine(line, jail string) (*BanRecord, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, ErrEmptyLine
	}
	fields := strings.Fields(line)

	// Validate jail name for path traversal
	if jail == "" || strings.ContainsAny(jail, "/\\") || strings.Contains(jail, "..") {
		return nil, fmt.Errorf("invalid jail name: contains unsafe characters")
	}

	// Validate IP address format
	if net.ParseIP(fields[0]) == nil {
		return nil, fmt.Errorf(constants.ErrInvalidIPAddress, fields[0])
	}

	record := &BanRecord{Jail: jail, IP: fields[0]}

	// Full format carries ban and unban timestamps (>= 6 fields).
	// The 8-field upstream variant "IP date time + SECS = date time" and the
	// 7-field "IP date time + date time remaining" both have ban time at
	// fields[1..2]; parseFullFormat locates the unban time for each.
	if len(fields) >= 6 {
		err := brp.parseFullFormat(fields, record)
		if err == nil {
			return record, nil
		}
		if len(fields) >= 8 {
			// 8+ fields is the well-known upstream layout: unparseable
			// timestamps there mean a genuinely malformed record.
			return nil, err
		}
		// A 6/7-field line whose fields aren't timestamps is an exotic
		// variant, not garbage: fall through to the simple-format record
		// instead of dropping the line.
	}

	// Fallback for simple format
	record.BannedAt = time.Now()
	record.Remaining = constants.UnknownValue
	return record, nil
}

// parseFullFormat handles the full ban-record format (ban + unban timestamps),
// filling record's BannedAt and Remaining. Ban date/time is always
// fields[1]/fields[2]. The unban timestamp position depends on the layout
// emitted by fail2ban-client:
//   - 8-field "IP date time + SECS = date time": "=" at index 5, unban at 6/7
//   - 6/7-field "IP date time + date time [remaining]": unban at 4/5
func (brp *BanRecordParser) parseFullFormat(fields []string, record *BanRecord) error {
	bannedStr := fields[1] + " " + fields[2]
	unbanStr := fields[4] + " " + fields[5]
	if len(fields) >= 8 && fields[5] == "=" {
		unbanStr = fields[6] + " " + fields[7]
	}

	// Parse ban time
	tBan, err := brp.timeCache.ParseTimeOptimized(bannedStr)
	if err != nil {
		getLogger().WithFields(Fields{
			"jail":      record.Jail,
			"ip":        record.IP,
			"bannedStr": bannedStr,
		}).Warnf("Failed to parse ban time: %v", err)
		return ErrInvalidBanTime
	}

	// Parse unban time with fallback
	tUnban, err := brp.timeCache.ParseTimeOptimized(unbanStr)
	if err != nil {
		getLogger().WithFields(Fields{
			"jail":     record.Jail,
			"ip":       record.IP,
			"unbanStr": unbanStr,
		}).Warnf("Failed to parse unban time: %v", err)
		tUnban = time.Now().Add(constants.DefaultBanDuration) // 24h fallback
	}

	record.BannedAt = tBan
	record.Remaining = formatDuration(max(tUnban.Unix()-time.Now().Unix(), 0))
	return nil
}

// ParseBanRecords parses multiple records. Lines that fail to parse are
// skipped, and the count of skipped lines is logged as a warning: dropping
// them silently made a jail whose bans fail2ban reports in an unexpected
// shape (e.g. ticket IDs instead of IPs) look like a jail with no bans.
func (brp *BanRecordParser) ParseBanRecords(output string, jail string) ([]BanRecord, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	records := make([]BanRecord, 0, len(lines))
	skipped := 0

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		record, err := brp.ParseBanRecordLine(line, jail)
		if err != nil {
			skipped++
			continue
		}
		records = append(records, *record)
	}

	if skipped > 0 {
		getLogger().WithField("jail", jail).WithField("skipped", skipped).
			Warn("Skipped unparseable ban record lines")
	}
	return records, nil
}

// formatDuration formats seconds as DD:HH:MM:SS, the shape fail2ban users expect.
func formatDuration(sec int64) string {
	days := sec / constants.SecondsPerDay
	h := (sec % constants.SecondsPerDay) / constants.SecondsPerHour
	m := (sec % constants.SecondsPerHour) / constants.SecondsPerMinute
	s := sec % constants.SecondsPerMinute
	return fmt.Sprintf("%02d:%02d:%02d:%02d", days, h, m, s)
}

// defaultBanRecordParser is shared so every caller reuses one time cache.
var defaultBanRecordParser = NewBanRecordParser()

// ParseBanRecords parses multiple ban records using the shared default parser.
func ParseBanRecords(output, jail string) ([]BanRecord, error) {
	return defaultBanRecordParser.ParseBanRecords(output, jail)
}
