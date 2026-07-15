package fail2ban

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivuorinen/f2b/constants"
)

/*
Package fail2ban provides log reading and filtering utilities for Fail2Ban logs.
This file contains logic for reading, parsing, and filtering Fail2Ban log files,
including support for rotated and compressed logs.
*/

// GetLogLines reads Fail2Ban log files (current and rotated) and filters lines by jail and/or IP.
//
// jailFilter: jail name to filter by (empty or "all" for all jails)
// ipFilter: IP address to filter by (empty or "all" for all IPs)
//
// Returns a slice of matching log lines, or an error.
// This function uses streaming to limit memory usage.
// Context parameter supports timeout and cancellation of file I/O operations.
func GetLogLines(ctx context.Context, jailFilter string, ipFilter string) ([]string, error) {
	return GetLogLinesWithLimit(ctx, jailFilter, ipFilter, constants.DefaultLogLinesLimit) // Default limit for safety
}

// GetLogLinesWithLimit returns log lines with configurable limits for memory management.
// Context parameter supports timeout and cancellation of file I/O operations.
func GetLogLinesWithLimit(ctx context.Context, jailFilter string, ipFilter string, maxLines int) ([]string, error) {
	// Validate maxLines parameter
	if maxLines < 0 {
		return nil, fmt.Errorf(constants.ErrMaxLinesNegative, maxLines)
	}

	if maxLines > constants.MaxLogLinesLimit {
		return nil, fmt.Errorf(constants.ErrMaxLinesExceedsLimit, constants.MaxLogLinesLimit)
	}

	if maxLines == 0 {
		return []string{}, nil
	}

	jailFilter, ipFilter, err := validateLogFilters(jailFilter, ipFilter)
	if err != nil {
		return nil, err
	}

	config := LogReadConfig{
		MaxLines:    maxLines,
		MaxFileSize: constants.DefaultMaxFileSize,
		JailFilter:  jailFilter,
		IPFilter:    ipFilter,
		BaseDir:     GetLogDir(),
	}

	return collectLogLines(ctx, GetLogDir(), config)
}

// validateLogFilters trims and validates the jail/IP filter values shared by
// every log-read entry point (package-level and RealClient), so an invalid
// filter errors instead of silently matching nothing.
func validateLogFilters(jailFilter, ipFilter string) (string, string, error) {
	jailFilter = strings.TrimSpace(jailFilter)
	ipFilter = strings.TrimSpace(ipFilter)

	if jailFilter != "" {
		if err := ValidateJail(jailFilter); err != nil {
			return "", "", fmt.Errorf("invalid jail filter: %w", err)
		}
	}

	if ipFilter != "" && ipFilter != constants.AllFilter {
		if net.ParseIP(ipFilter) == nil {
			return "", "", fmt.Errorf(constants.ErrInvalidIPAddress, ipFilter)
		}
	}

	return jailFilter, ipFilter, nil
}

// canonicalizeIPFilter normalizes an IP filter via net.ParseIP so that e.g.
// the IPv6 query "2001:DB8::1" matches the lowercase canonical form fail2ban
// writes to its logs. Non-IP values pass through untouched (they are rejected
// by validation upstream).
func canonicalizeIPFilter(ip string) string {
	if ip == "" || ip == constants.AllFilter {
		return ip
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	return ip
}

// collectLogLines reads log files under the provided directory using the supplied configuration.
func collectLogLines(ctx context.Context, logDir string, baseConfig LogReadConfig) ([]string, error) {
	if baseConfig.MaxLines == 0 {
		return []string{}, nil
	}

	baseConfig.IPFilter = canonicalizeIPFilter(baseConfig.IPFilter)

	pattern := filepath.Join(logDir, "fail2ban.log*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("error listing log files: %w", err)
	}

	if len(files) == 0 {
		return []string{}, nil
	}

	currentLog, rotated := parseLogFiles(files)

	var allLines []string

	appendAndTrim := func(lines []string) {
		if len(lines) == 0 {
			return
		}
		allLines = append(allLines, lines...)
		if baseConfig.MaxLines > 0 && len(allLines) > baseConfig.MaxLines {
			allLines = allLines[len(allLines)-baseConfig.MaxLines:]
		}
	}

	// readAndAppend reads one log file and appends its lines. A context
	// cancellation is fatal (returned); any other read error is logged and the
	// file skipped.
	readAndAppend := func(path string, isCurrent bool) error {
		fileLines, err := readLogLinesFromFile(ctx, path, baseConfig, isCurrent)
		if err != nil {
			if ctx != nil && errors.Is(err, ctx.Err()) {
				return err
			}
			getLogger().WithError(err).WithField(constants.LogFieldFile, path).Error("Failed to read log file")
			return nil
		}
		appendAndTrim(fileLines)
		return nil
	}

	// Rotated logs are read oldest-first, then the current log last.
	for _, rotatedFile := range rotated {
		if err := readAndAppend(rotatedFile.path, false); err != nil {
			return nil, err
		}
	}
	if currentLog != "" {
		if err := readAndAppend(currentLog, true); err != nil {
			return nil, err
		}
	}

	return allLines, nil
}

func readLogLinesFromFile(
	ctx context.Context, path string, baseConfig LogReadConfig, isCurrent bool,
) ([]string, error) {
	fileConfig := baseConfig
	// ponytail: unbounded per-file line buffer (MaxFileSize caps it at 100MB
	// of input); switch to a per-file ring of MaxLines if transient RSS on
	// large all-matching logs ever matters.
	fileConfig.MaxLines = 0
	fileConfig.TailOversized = isCurrent

	if ctx != nil {
		return streamLogFileWithContext(ctx, path, fileConfig)
	}
	return streamLogFile(path, fileConfig)
}

// parseLogFiles parses log file names and returns the current log and a slice of rotated logs
// (sorted oldest to newest).
func parseLogFiles(files []string) (string, []rotatedLog) {
	var currentLog string
	var rotated []rotatedLog

	for _, path := range files {
		base := filepath.Base(path)
		if base == constants.LogFileName {
			currentLog = path
			continue
		}
		if num, ok := extractLogNumber(base); ok {
			rotated = append(rotated, rotatedLog{num: num, path: path})
		}
	}

	// Sort rotated logs by key descending (highest key = oldest log)
	sort.Slice(rotated, func(i, j int) bool {
		return rotated[i].num > rotated[j].num
	})

	return currentLog, rotated
}

// extractLogNumber extracts an ordering key from a rotated log file name,
// where a higher key means an older log (parseLogFiles sorts descending).
// It handles both logrotate schemes:
//   - numbered:  fail2ban.log.<N>[.gz]      -> N        (higher N = older)
//   - dateext:   fail2ban.log-YYYYMMDD[.gz] -> -YYYYMMDD (higher date = newer,
//     so the date is negated to keep the higher-key-is-older invariant)
//
// Returns ok=false for names matching neither scheme (previously such files,
// e.g. RHEL/Fedora dateext logs, were silently dropped from `f2b log` output).
func extractLogNumber(base string) (int, bool) {
	if rest, ok := strings.CutPrefix(base, constants.LogFilePrefix); ok {
		rest = strings.TrimSuffix(rest, constants.GzipExtension)
		if rest == "" || rest == "gz" {
			return 0, true // fail2ban.log.gz (compressed, unnumbered)
		}
		if n, err := strconv.Atoi(rest); err == nil {
			// logrotate `dateformat .%Y%m%d` produces fail2ban.log.20240102:
			// an 8-digit rest that parses as a date is a dateext date, not a
			// rotation number, so negate it (higher date = newer log) to keep
			// the higher-key-is-older invariant.
			if len(rest) == 8 {
				if _, dateErr := time.Parse("20060102", rest); dateErr == nil {
					return -n, true
				}
			}
			return n, true
		}
	}
	if rest, ok := strings.CutPrefix(base, "fail2ban.log-"); ok {
		rest = strings.TrimSuffix(rest, constants.GzipExtension)
		if n, err := strconv.Atoi(rest); err == nil {
			return -n, true
		}
	}
	return 0, false
}

// rotatedLog represents a rotated log file with its rotation number.
type rotatedLog struct {
	num  int
	path string
}

// LogReadConfig holds configuration for streaming log reading
type LogReadConfig struct {
	MaxLines    int    // Maximum number of lines to read (0 = unlimited)
	MaxFileSize int64  // Maximum file size to process in bytes (0 = unlimited)
	JailFilter  string // Filter by jail name (empty = no filter)
	IPFilter    string // Filter by IP address (empty = no filter)
	BaseDir     string // Base directory for log validation
	// TailOversized reads the newest MaxFileSize bytes of an oversized file
	// instead of skipping it. Set only for the active (plain-text) log: it is
	// the file most likely to exceed the cap, and skipping it would drop the
	// newest events; rotated files are still skipped.
	TailOversized bool
}

// resolveBaseDir returns the base directory from config or falls back to GetLogDir()
func resolveBaseDir(config LogReadConfig) string {
	if config.BaseDir != "" {
		return config.BaseDir
	}
	return GetLogDir()
}

// streamLogFile reads a log file line by line with memory limits and filtering
func streamLogFile(path string, config LogReadConfig) ([]string, error) {
	return streamLogFileWithContext(context.Background(), path, config)
}

// streamLogFileWithContext reads a log file line by line with memory limits,
// filtering, and context support for timeouts
func streamLogFileWithContext(ctx context.Context, path string, config LogReadConfig) ([]string, error) {
	// Check context before starting
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	baseDir := resolveBaseDir(config)
	cleanPath, err := validateLogPathForDir(ctx, path, baseDir)
	if err != nil {
		return nil, err
	}

	if config.TailOversized && isOversizedFile(cleanPath, config.MaxFileSize) {
		return scanOversizedTail(ctx, cleanPath, config)
	}
	if shouldSkipFile(cleanPath, config.MaxFileSize) {
		return []string{}, nil
	}

	scanner, cleanup, err := createLogScanner(cleanPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return scanLogLinesWithContext(ctx, scanner, config)
}

// isOversizedFile reports whether path exceeds maxFileSize (0 = no limit).
func isOversizedFile(path string, maxFileSize int64) bool {
	if maxFileSize <= 0 {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Size() > maxFileSize
}

// scanOversizedTail reads the newest config.MaxFileSize bytes of an oversized
// plain-text log. The caller only sets TailOversized for the active
// fail2ban.log, which is never gzip-compressed. The first line after the seek
// is discarded as likely partial.
func scanOversizedTail(ctx context.Context, path string, config LogReadConfig) ([]string, error) {
	f, err := os.Open(path) // #nosec G304 -- path validated by the caller
	if err != nil {
		return nil, fmt.Errorf("error opening log file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			getLogger().WithError(cerr).WithField(constants.LogFieldFile, path).
				Debug("closing log file failed")
		}
	}()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("error inspecting log file: %w", err)
	}
	if _, err := f.Seek(info.Size()-config.MaxFileSize, io.SeekStart); err != nil {
		return nil, fmt.Errorf("error seeking log file: %w", err)
	}

	getLogger().WithField(constants.LogFieldFile, path).WithField("size", info.Size()).
		Warn("Active log exceeds size limit; reading only the newest bytes within the limit")

	const maxLineSize = 64 * 1024 // matches createLogScanner
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, bufio.MaxScanTokenSize), maxLineSize)
	scanner.Scan() // discard the first, likely partial, line

	return scanLogLinesWithContext(ctx, scanner, config)
}

func validateLogPathForDir(ctx context.Context, path string, baseDir string) (string, error) {
	return ValidateLogPath(ctx, path, baseDir)
}

// shouldSkipFile checks if a file should be skipped due to size limits
func shouldSkipFile(path string, maxFileSize int64) bool {
	if maxFileSize <= 0 {
		return false
	}

	if info, err := os.Stat(path); err == nil {
		if info.Size() > maxFileSize {
			getLogger().WithField(constants.LogFieldFile, path).WithField("size", info.Size()).
				Warn("Skipping large log file due to size limit")
			return true
		}
	}
	return false
}

// createLogScanner creates a scanner for the log file, handling gzip compression
func createLogScanner(path string) (*bufio.Scanner, func(), error) {
	// #nosec G304 - Path is validated and sanitized above
	const maxLineSize = 64 * 1024 // 64KB per line
	return CreateGzipAwareScannerWithBuffer(path, maxLineSize)
}

// scanLogLines scans lines from the scanner with filtering and limits
func scanLogLines(scanner *bufio.Scanner, config LogReadConfig) ([]string, error) {
	var lines []string
	lineCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if !passesFilters(line, config) {
			continue
		}

		lines = append(lines, line)
		lineCount++

		if config.MaxLines > 0 && lineCount >= config.MaxLines {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return salvageScannedLines(lines, err)
	}

	return lines, nil
}

// salvageScannedLines decides what to keep when a log scan stops with an
// error. Lines already read are valid data: a single oversized line or a
// truncated/corrupt (e.g. mid-logrotate) gzip must not discard every line
// already read from the file — the scanner cannot continue past the defect,
// so the rest of the file is dropped with a warning instead of failing
// silently. Any other error is a real read failure and is returned as-is.
func salvageScannedLines(lines []string, err error) ([]string, error) {
	switch {
	case errors.Is(err, bufio.ErrTooLong):
		getLogger().WithField("lines_read", len(lines)).
			Warn("Log line exceeds scan buffer; returning lines read so far and dropping the rest of this file")
		return lines, nil
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, gzip.ErrHeader), errors.Is(err, gzip.ErrChecksum):
		getLogger().WithField("lines_read", len(lines)).WithField("error", err.Error()).
			Warn("Log file truncated or corrupt; returning lines read so far and dropping the rest of this file")
		return lines, nil
	}
	return nil, fmt.Errorf(constants.ErrScanLogFile, err)
}

// scanLogLinesWithContext scans log lines with context support for timeout handling
func scanLogLinesWithContext(ctx context.Context, scanner *bufio.Scanner, config LogReadConfig) ([]string, error) {
	var lines []string
	lineCount := 0
	linesProcessed := 0

	for scanner.Scan() {
		// Check context periodically (every 100 lines to avoid excessive overhead)
		if linesProcessed%100 == 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}
		linesProcessed++

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if !passesFilters(line, config) {
			continue
		}

		lines = append(lines, line)
		lineCount++

		if config.MaxLines > 0 && lineCount >= config.MaxLines {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return salvageScannedLines(lines, err)
	}

	return lines, nil
}

// passesFilters checks if a log line passes the configured filters
func passesFilters(line string, config LogReadConfig) bool {
	if config.JailFilter != "" && config.JailFilter != constants.AllFilter {
		jailPattern := fmt.Sprintf("[%s]", config.JailFilter)
		if !strings.Contains(line, jailPattern) {
			return false
		}
	}

	if config.IPFilter != "" && config.IPFilter != constants.AllFilter {
		if !containsIPToken(line, config.IPFilter) {
			return false
		}
	}

	return true
}

// containsIPToken reports whether ip appears in line as a whole token, i.e. not
// as a substring of a longer address. A plain substring match for "10.0.0.1"
// wrongly matches "10.0.0.100" (and "110.0.0.1"), attributing other hosts'
// events to the requested IP.
//
// For an IPv4 query, ':' is treated as a separator rather than an address
// byte, so IPv4-mapped IPv6 forms ("::ffff:10.0.0.1") and "IP:port" forms
// still match the plain IPv4 address.
func containsIPToken(line, ip string) bool {
	ipv4 := strings.Contains(ip, ".") && !strings.Contains(ip, ":")
	isIPByte := func(b byte) bool {
		switch {
		case b >= '0' && b <= '9',
			b >= 'a' && b <= 'f',
			b >= 'A' && b <= 'F',
			b == '.':
			return true
		case b == ':':
			return !ipv4
		default:
			return false
		}
	}
	for idx := 0; ; {
		i := strings.Index(line[idx:], ip)
		if i < 0 {
			return false
		}
		start := idx + i
		end := start + len(ip)
		beforeOK := start == 0 || !isIPByte(line[start-1])
		afterOK := end == len(line) || !isIPByte(line[end])
		if beforeOK && afterOK {
			return true
		}
		idx = start + 1
	}
}

// OptimizedLogProcessor is a thin wrapper maintained for backwards compatibility
// with existing benchmarks and tests. Internally it delegates to the shared log collection
// helpers so we have a single codepath to maintain.
type OptimizedLogProcessor struct{}

// NewOptimizedLogProcessor creates a new optimized processor wrapper.
func NewOptimizedLogProcessor() *OptimizedLogProcessor {
	return &OptimizedLogProcessor{}
}

// GetLogLinesOptimized proxies to the shared collector to keep behavior identical
// while allowing benchmarks to exercise this entrypoint.
func (olp *OptimizedLogProcessor) GetLogLinesOptimized(jailFilter, ipFilter string, maxLines int) ([]string, error) {
	// Validate maxLines parameter
	if maxLines < 0 {
		return nil, fmt.Errorf(constants.ErrMaxLinesNegative, maxLines)
	}

	if maxLines > constants.MaxLogLinesLimit {
		return nil, fmt.Errorf(constants.ErrMaxLinesExceedsLimit, constants.MaxLogLinesLimit)
	}

	// Sanitize filter parameters
	jailFilter = strings.TrimSpace(jailFilter)
	ipFilter = strings.TrimSpace(ipFilter)

	config := LogReadConfig{
		MaxLines:    maxLines,
		MaxFileSize: constants.DefaultMaxFileSize,
		JailFilter:  jailFilter,
		IPFilter:    ipFilter,
		BaseDir:     GetLogDir(),
	}

	return collectLogLines(context.Background(), GetLogDir(), config)
}

var optimizedLogProcessor = NewOptimizedLogProcessor()

// GetLogLinesUltraOptimized retains the legacy API that benchmarks expect while now
// sharing the simplified implementation.
func GetLogLinesUltraOptimized(jailFilter, ipFilter string, maxLines int) ([]string, error) {
	return optimizedLogProcessor.GetLogLinesOptimized(jailFilter, ipFilter, maxLines)
}
