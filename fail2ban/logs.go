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
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ivuorinen/f2b/constants"
)

// Log reading and filtering for Fail2Ban logs, including rotated and
// compressed logs.

// validateLogFilters trims and validates the jail/IP filter values of a log
// read, so an invalid filter errors instead of silently matching nothing.
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

// logSource is one log file to read and whether it is the active log.
type logSource struct {
	path    string
	current bool
}

// collectLogLines returns the newest MaxLines lines matching baseConfig from
// the fail2ban logs under logDir, in chronological order. The result is never
// nil, so JSON output prints [] rather than null for "no matches".
//
// Files are read newest first (the current log, then rotated logs from newest
// to oldest) and reading stops once MaxLines matching lines are collected. The
// former oldest-first order read and decompressed every rotated archive on
// each call, and logs-watch repeated that on every poll, even when the current
// log alone held enough lines.
//
// A context cancellation is returned. Any other per-file failure is logged and
// the file skipped; when no file could be read and at least one failed, the
// joined failures are returned, because an unreadable log (e.g. root:adm 0640
// for a non-adm user) must not look like "no matches".
func collectLogLines(ctx context.Context, logDir string, baseConfig LogReadConfig) ([]string, error) {
	if baseConfig.MaxLines <= 0 {
		return []string{}, nil
	}

	sources, err := logSourcesNewestFirst(logDir)
	if err != nil {
		return nil, err
	}

	var chunks [][]string // newest file first
	var failures []error
	total, readOK := 0, 0
	for _, src := range sources {
		if total >= baseConfig.MaxLines {
			break
		}
		lines, err := readLogLinesFromFile(ctx, src.path, baseConfig, src.current)
		if err != nil {
			if errors.Is(err, ctx.Err()) {
				return nil, err
			}
			getLogger().WithError(err).WithField(constants.LogFieldFile, src.path).Error("Failed to read log file")
			failures = append(failures, err)
			continue
		}
		readOK++
		chunks = append(chunks, lines)
		total += len(lines)
	}
	if readOK == 0 && len(failures) > 0 {
		return nil, errors.Join(failures...)
	}
	return newestLines(chunks, total, baseConfig.MaxLines), nil
}

// logSourcesNewestFirst lists the fail2ban logs under logDir newest first:
// the current log, then rotated logs from newest to oldest.
func logSourcesNewestFirst(logDir string) ([]logSource, error) {
	files, err := filepath.Glob(filepath.Join(logDir, "fail2ban.log*"))
	if err != nil {
		return nil, fmt.Errorf("error listing log files: %w", err)
	}
	currentLog, rotated := parseLogFiles(files)
	sources := make([]logSource, 0, len(rotated)+1)
	if currentLog != "" {
		sources = append(sources, logSource{path: currentLog, current: true})
	}
	for _, r := range slices.Backward(rotated) { // rotated is oldest first
		sources = append(sources, logSource{path: r.path})
	}
	return sources, nil
}

// newestLines reassembles per-file chunks (newest file first, total lines in
// all) into chronological order, keeping only the newest maxLines lines.
func newestLines(chunks [][]string, total, maxLines int) []string {
	skip := max(total-maxLines, 0)
	out := make([]string, 0, total-skip)
	for _, chunk := range slices.Backward(chunks) {
		if skip >= len(chunk) {
			skip -= len(chunk)
			continue
		}
		out = append(out, chunk[skip:]...)
		skip = 0
	}
	return out
}

// readLogLinesFromFile returns every matching line of one log file. The line
// limit is applied across files by collectLogLines, so it is lifted here.
func readLogLinesFromFile(
	ctx context.Context, path string, baseConfig LogReadConfig, isCurrent bool,
) ([]string, error) {
	fileConfig := baseConfig
	// ponytail: unbounded per-file line buffer (MaxFileSize caps it at 100MB
	// of input); switch to a per-file ring of MaxLines if transient RSS on
	// large all-matching logs ever matters.
	fileConfig.MaxLines = 0
	fileConfig.TailOversized = isCurrent
	return streamLogFileWithContext(ctx, path, fileConfig)
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
		return numberedLogKey(strings.TrimSuffix(rest, constants.GzipExtension))
	}
	if rest, ok := strings.CutPrefix(base, "fail2ban.log-"); ok {
		if n, err := strconv.Atoi(strings.TrimSuffix(rest, constants.GzipExtension)); err == nil {
			return -n, true
		}
	}
	return 0, false
}

// numberedLogKey resolves the ordering key for a `fail2ban.log.<rest>` name,
// where rest already has the .gz suffix trimmed. An 8-digit rest that parses as
// a date is a `dateformat .%Y%m%d` value, not a rotation number, so it is
// negated (higher date = newer log) to keep the higher-key-is-older invariant.
func numberedLogKey(rest string) (int, bool) {
	if rest == "" || rest == "gz" {
		return 0, true // fail2ban.log.gz (compressed, unnumbered)
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}
	if len(rest) == 8 {
		if _, dateErr := time.Parse("20060102", rest); dateErr == nil {
			return -n, true
		}
	}
	return n, true
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

	// jailPattern is the "[jail]" substring passesFilters looks for, built
	// once per read by prepareLogFilters instead of formatted per line.
	jailPattern string
}

// prepareLogFilters derives the per-read filter state: the bracketed jail
// pattern and the canonical IP. It runs once per file read so the per-line
// filter does no formatting or allocation.
func prepareLogFilters(config LogReadConfig) LogReadConfig {
	config.jailPattern = ""
	if config.JailFilter != "" && config.JailFilter != constants.AllFilter {
		config.jailPattern = "[" + config.JailFilter + "]"
	}
	config.IPFilter = canonicalizeIPFilter(config.IPFilter)
	return config
}

// resolveBaseDir returns the base directory from config or falls back to GetLogDir()
func resolveBaseDir(config LogReadConfig) string {
	if config.BaseDir != "" {
		return config.BaseDir
	}
	return GetLogDir()
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
	config = prepareLogFilters(config)

	cleanPath, err := ValidateLogPath(path, resolveBaseDir(config))
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
	const maxLineSize = 64 * 1024 // 64KB per line
	return createGzipAwareScanner(path, maxLineSize)
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

// passesFilters checks if a log line passes the configured filters. config
// must come from prepareLogFilters, which builds the jail pattern.
func passesFilters(line string, config LogReadConfig) bool {
	if config.jailPattern != "" && !strings.Contains(line, config.jailPattern) {
		return false
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
