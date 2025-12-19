package fail2ban

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ivuorinen/f2b/shared"
)

// TimeParsingCache provides cached and optimized time parsing functionality with bounded cache
type TimeParsingCache struct {
	layout        string
	parseCache    *BoundedTimeCache // Bounded cache prevents unbounded memory growth
	stringBuilder sync.Pool
}

// NewTimeParsingCache creates a new time parsing cache with the specified layout
func NewTimeParsingCache(layout string) (*TimeParsingCache, error) {
	parseCache, err := NewBoundedTimeCache(shared.CacheMaxSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create time parsing cache: %w", err)
	}

	return &TimeParsingCache{
		layout:     layout,
		parseCache: parseCache, // Bounded at 10k entries
		stringBuilder: sync.Pool{
			New: func() interface{} {
				return &strings.Builder{}
			},
		},
	}, nil
}

// ParseTime parses a time string with bounded caching for performance
func (tpc *TimeParsingCache) ParseTime(timeStr string) (time.Time, error) {
	// Check cache first
	if cached, ok := tpc.parseCache.Load(timeStr); ok {
		return cached, nil
	}

	// Parse and cache
	t, err := time.Parse(tpc.layout, timeStr)
	if err == nil {
		tpc.parseCache.Store(timeStr, t)
	}
	return t, err
}

// BuildTimeString efficiently builds a time string from date and time components
func (tpc *TimeParsingCache) BuildTimeString(dateStr, timeStr string) string {
	sb := tpc.stringBuilder.Get().(*strings.Builder)
	defer tpc.stringBuilder.Put(sb)

	sb.Reset()
	sb.WriteString(dateStr)
	sb.WriteByte(' ')
	sb.WriteString(timeStr)
	return sb.String()
}

// Global cache instances for common time formats
var (
	defaultTimeCache = mustCreateTimeCache()
)

// mustCreateTimeCache creates the default time cache or panics (init time only)
func mustCreateTimeCache() *TimeParsingCache {
	cache, err := NewTimeParsingCache("2006-01-02 15:04:05")
	if err != nil {
		panic(fmt.Sprintf("failed to create default time cache: %v", err))
	}
	return cache
}

// ParseBanTime parses ban time using the default bounded cache
func ParseBanTime(timeStr string) (time.Time, error) {
	return defaultTimeCache.ParseTime(timeStr)
}

// BuildBanTimeString efficiently builds a ban time string
func BuildBanTimeString(dateStr, timeStr string) string {
	return defaultTimeCache.BuildTimeString(dateStr, timeStr)
}
