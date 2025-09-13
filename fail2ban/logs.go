package fail2ban

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
func GetLogLines(jailFilter string, ipFilter string) ([]string, error) {
	return GetLogLinesWithLimit(jailFilter, ipFilter, 1000) // Default limit for safety
}

// GetLogLinesWithLimit returns log lines with configurable limits for memory management.
func GetLogLinesWithLimit(jailFilter string, ipFilter string, maxLines int) ([]string, error) {
	// Handle zero limit case - return empty slice immediately
	if maxLines == 0 {
		return []string{}, nil
	}

	pattern := filepath.Join(GetLogDir(), "fail2ban.log*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("error listing log files: %w", err)
	}

	if len(files) == 0 {
		return []string{}, nil
	}

	currentLog, rotated := parseLogFiles(files)

	// Use streaming approach with memory limits
	config := LogReadConfig{
		MaxLines:     maxLines,
		MaxFileSize:  100 * 1024 * 1024, // 100MB file size limit
		JailFilter:   jailFilter,
		IPFilter:     ipFilter,
		ReverseOrder: false,
	}

	var allLines []string
	totalLines := 0

	// Read rotated logs first (oldest to newest) - maintains original ordering
	for _, rotatedFile := range rotated {
		if config.MaxLines > 0 && totalLines >= config.MaxLines {
			break
		}

		// Adjust remaining lines limit (skip limit check for negative MaxLines)
		fileConfig := config
		if config.MaxLines > 0 {
			remainingLines := config.MaxLines - totalLines
			if remainingLines <= 0 {
				break
			}
			fileConfig.MaxLines = remainingLines
		}

		lines, err := streamLogFile(rotatedFile.path, fileConfig)
		if err != nil {
			getLogger().WithError(err).WithField("file", rotatedFile.path).Error("Failed to read rotated log file")
			continue
		}

		allLines = append(allLines, lines...)
		totalLines += len(lines)
	}

	// Read current log last (most recent) - maintains original ordering
	if currentLog != "" && (config.MaxLines <= 0 || totalLines < config.MaxLines) {
		fileConfig := config
		if config.MaxLines > 0 {
			remainingLines := config.MaxLines - totalLines
			if remainingLines <= 0 {
				return allLines, nil
			}
			fileConfig.MaxLines = remainingLines
		}

		lines, err := streamLogFile(currentLog, fileConfig)
		if err != nil {
			getLogger().WithError(err).WithField("file", currentLog).Error("Failed to read current log file")
		} else {
			allLines = append(allLines, lines...)
		}
	}

	return allLines, nil
}

// parseLogFiles parses log file names and returns the current log and a slice of rotated logs
// (sorted oldest to newest).
func parseLogFiles(files []string) (string, []rotatedLog) {
	var currentLog string
	var rotated []rotatedLog

	for _, path := range files {
		base := filepath.Base(path)
		if base == "fail2ban.log" {
			currentLog = path
		} else if strings.HasPrefix(base, "fail2ban.log.") {
			if num := extractLogNumber(base); num >= 0 {
				rotated = append(rotated, rotatedLog{num: num, path: path})
			}
		}
	}

	// Sort rotated logs by number descending (highest number = oldest log)
	sort.Slice(rotated, func(i, j int) bool {
		return rotated[i].num > rotated[j].num
	})

	return currentLog, rotated
}

// extractLogNumber extracts the rotation number from a log file name (e.g., "fail2ban.log.2.gz" -> 2).
func extractLogNumber(base string) int {
	numPart := strings.TrimPrefix(base, "fail2ban.log.")
	numPart = strings.TrimSuffix(numPart, ".gz")
	if n, err := strconv.Atoi(numPart); err == nil {
		return n
	}
	return -1
}

// rotatedLog represents a rotated log file with its rotation number.
type rotatedLog struct {
	num  int
	path string
}

// LogReadConfig holds configuration for streaming log reading
type LogReadConfig struct {
	MaxLines     int    // Maximum number of lines to read (0 = unlimited)
	MaxFileSize  int64  // Maximum file size to process in bytes (0 = unlimited)
	JailFilter   string // Filter by jail name (empty = no filter)
	IPFilter     string // Filter by IP address (empty = no filter)
	ReverseOrder bool   // Read from end of file backwards (for recent logs)
}

// streamLogFile reads a log file line by line with memory limits and filtering
func streamLogFile(path string, config LogReadConfig) ([]string, error) {
	cleanPath, err := validateLogPath(path)
	if err != nil {
		return nil, err
	}

	if shouldSkipFile(cleanPath, config.MaxFileSize) {
		return []string{}, nil
	}

	scanner, cleanup, err := createLogScanner(cleanPath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return scanLogLines(scanner, config)
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

	cleanPath, err := validateLogPath(path)
	if err != nil {
		return nil, err
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

// validateLogPath validates and sanitizes the log file path with comprehensive security checks
func validateLogPath(path string) (string, error) {
	return ValidateLogPath(path, GetLogDir())
}

// shouldSkipFile checks if a file should be skipped due to size limits
func shouldSkipFile(path string, maxFileSize int64) bool {
	if maxFileSize <= 0 {
		return false
	}

	if info, err := os.Stat(path); err == nil {
		if info.Size() > maxFileSize {
			getLogger().WithField("file", path).WithField("size", info.Size()).
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
		return nil, fmt.Errorf("error scanning log file: %w", err)
	}

	return lines, nil
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
		return nil, fmt.Errorf("error scanning log file: %w", err)
	}

	return lines, nil
}

// passesFilters checks if a log line passes the configured filters
func passesFilters(line string, config LogReadConfig) bool {
	if config.JailFilter != "" && config.JailFilter != AllFilter {
		jailPattern := fmt.Sprintf("[%s]", config.JailFilter)
		if !strings.Contains(line, jailPattern) {
			return false
		}
	}

	if config.IPFilter != "" && config.IPFilter != AllFilter {
		if !strings.Contains(line, config.IPFilter) {
			return false
		}
	}

	return true
}

// readLogFile reads the contents of a log file, handling gzip compression if necessary.
// DEPRECATED: Use streamLogFile instead for better memory efficiency.
func readLogFile(path string) ([]byte, error) {
	// Validate path for security using comprehensive validation
	cleanPath, err := validateLogPath(path)
	if err != nil {
		return nil, err
	}

	// Use consolidated gzip detection utility
	reader, err := OpenGzipAwareReader(cleanPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := reader.Close(); cerr != nil {
			getLogger().WithError(cerr).Error("failed to close log file")
		}
	}()

	return io.ReadAll(reader)
}
