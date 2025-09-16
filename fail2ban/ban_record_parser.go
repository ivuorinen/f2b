package fail2ban

import (
	"errors"
)

// Sentinel errors for parser
var (
	ErrEmptyLine          = errors.New("empty line")
	ErrInsufficientFields = errors.New("insufficient fields")
	ErrInvalidBanTime     = errors.New("invalid ban time")
)

// BanRecordParser provides ban record parsing backed by the optimized implementation.
type BanRecordParser struct {
	optimized *OptimizedBanRecordParser
}

// NewBanRecordParser creates a parser that delegates to the optimized ban record parser.
func NewBanRecordParser() *BanRecordParser {
	return &BanRecordParser{optimized: NewOptimizedBanRecordParser()}
}

// ParseBanRecordLine parses a single line using the optimized parser while preserving legacy API.
func (brp *BanRecordParser) ParseBanRecordLine(line, jail string) (*BanRecord, error) {
	if brp == nil || brp.optimized == nil {
		return optimizedBanRecordParser.ParseBanRecordLineOptimized(line, jail)
	}
	return brp.optimized.ParseBanRecordLineOptimized(line, jail)
}

// ParseBanRecords parses multiple ban record lines using the optimized parser while preserving legacy API.
func (brp *BanRecordParser) ParseBanRecords(output string, jail string) ([]BanRecord, error) {
	if brp == nil || brp.optimized == nil {
		return optimizedBanRecordParser.ParseBanRecordsOptimized(output, jail)
	}
	return brp.optimized.ParseBanRecordsOptimized(output, jail)
}

// Global parser instance for reuse
var defaultBanRecordParser = NewBanRecordParser()

// ParseBanRecordLineOptimized parses a ban record line using the default parser.
func ParseBanRecordLineOptimized(line, jail string) (*BanRecord, error) {
	return defaultBanRecordParser.ParseBanRecordLine(line, jail)
}

// ParseBanRecordsOptimized parses multiple ban records using the default parser.
func ParseBanRecordsOptimized(output, jail string) ([]BanRecord, error) {
	return defaultBanRecordParser.ParseBanRecords(output, jail)
}
