package fail2ban

import (
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
func NewTimeParsingCache(layout string) *TimeParsingCache {
	return &TimeParsingCache{
		layout:     layout,
		parseCache: NewBoundedTimeCache(shared.CacheMaxSize), // Bounded at 10k entries
		stringBuilder: sync.Pool{
			New: func() interface{} {
				return &strings.Builder{}
			},
		},
	}
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
	defaultTimeCache = NewTimeParsingCache("2006-01-02 15:04:05")
)

// ParseBanTime parses ban time using the default bounded cache
func ParseBanTime(timeStr string) (time.Time, error) {
	return defaultTimeCache.ParseTime(timeStr)
}

// BuildBanTimeString efficiently builds a ban time string
func BuildBanTimeString(dateStr, timeStr string) string {
	return defaultTimeCache.BuildTimeString(dateStr, timeStr)
}
