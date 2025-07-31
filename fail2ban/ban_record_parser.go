package fail2ban

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Sentinel errors for parser
var (
	ErrEmptyLine          = errors.New("empty line")
	ErrInsufficientFields = errors.New("insufficient fields")
	ErrInvalidBanTime     = errors.New("invalid ban time")
)

// BanRecordParser provides optimized parsing of ban records
type BanRecordParser struct {
	stringPool sync.Pool
	timeCache  *TimeParsingCache
}

// NewBanRecordParser creates a new optimized ban record parser
func NewBanRecordParser() *BanRecordParser {
	return &BanRecordParser{
		stringPool: sync.Pool{
			New: func() interface{} {
				s := make([]string, 0, 8) // Pre-allocate for typical field count
				return &s
			},
		},
		timeCache: defaultTimeCache,
	}
}

// ParseBanRecordLine efficiently parses a single ban record line
func (brp *BanRecordParser) ParseBanRecordLine(line, jail string) (*BanRecord, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, ErrEmptyLine
	}

	// Get pooled slice for fields
	fieldsPtr := brp.stringPool.Get().(*[]string)
	fields := *fieldsPtr
	defer func() {
		if len(fields) > 0 {
			resetFields := fields[:0]
			*fieldsPtr = resetFields
			brp.stringPool.Put(fieldsPtr) // Reset slice and return to pool
		}
	}()

	// Parse fields more efficiently
	fields = strings.Fields(line)
	if len(fields) < 1 {
		return nil, ErrInsufficientFields
	}

	ip := fields[0]

	if len(fields) >= 8 {
		// Format: IP BANNED_DATE BANNED_TIME + UNBAN_DATE UNBAN_TIME
		bannedStr := brp.timeCache.BuildTimeString(fields[1], fields[2])
		unbanStr := brp.timeCache.BuildTimeString(fields[4], fields[5])

		tBan, err := brp.timeCache.ParseTime(bannedStr)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"jail":      jail,
				"ip":        ip,
				"bannedStr": bannedStr,
			}).Warnf("Failed to parse ban time: %v", err)
			// Skip this entry if we can't parse the ban time (original behavior)
			return nil, ErrInvalidBanTime
		}

		tUnban, err := brp.timeCache.ParseTime(unbanStr)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"jail":     jail,
				"ip":       ip,
				"unbanStr": unbanStr,
			}).Warnf("Failed to parse unban time: %v", err)
			// Use current time as fallback for unban time calculation
			tUnban = time.Now().Add(DefaultBanDuration) // Assume 24h remaining
		}

		rem := tUnban.Unix() - time.Now().Unix()
		if rem < 0 {
			rem = 0
		}

		return &BanRecord{
			Jail:      jail,
			IP:        ip,
			BannedAt:  tBan,
			Remaining: FormatDuration(rem),
		}, nil
	}

	// Fallback for simpler format
	return &BanRecord{
		Jail:      jail,
		IP:        ip,
		BannedAt:  time.Now(),
		Remaining: "unknown",
	}, nil
}

// ParseBanRecords parses multiple ban record lines efficiently
func (brp *BanRecordParser) ParseBanRecords(output string, jail string) ([]BanRecord, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	records := make([]BanRecord, 0, len(lines)) // Pre-allocate based on line count

	for _, line := range lines {
		record, err := brp.ParseBanRecordLine(line, jail)
		if err != nil {
			// Skip lines with parsing errors (empty lines, insufficient fields, invalid times)
			continue
		}
		if record != nil {
			records = append(records, *record)
		}
	}

	return records, nil
}

// Global parser instance for reuse
var defaultBanRecordParser = NewBanRecordParser()

// ParseBanRecordLineOptimized parses a ban record line using the default parser
func ParseBanRecordLineOptimized(line, jail string) (*BanRecord, error) {
	return defaultBanRecordParser.ParseBanRecordLine(line, jail)
}

// ParseBanRecordsOptimized parses multiple ban records using the default parser
func ParseBanRecordsOptimized(output, jail string) ([]BanRecord, error) {
	return defaultBanRecordParser.ParseBanRecords(output, jail)
}
