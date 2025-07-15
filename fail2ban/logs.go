package fail2ban

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
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
func GetLogLines(jailFilter string, ipFilter string) ([]string, error) {
	pattern := filepath.Join(logDir, "fail2ban.log*")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("error listing log files: %w", err)
	}
	if len(files) == 0 {
		return []string{}, nil
	}

	currentLog, rotated := parseLogFiles(files)
	lines := readAllLogFiles(currentLog, rotated)
	lines = applyFilters(lines, jailFilter, ipFilter)

	return lines, nil
}

// parseLogFiles parses log file names and returns the current log and a slice of rotated logs (sorted oldest to newest).
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

// readAllLogFiles reads all log files in chronological order (oldest rotated first, then current).
func readAllLogFiles(currentLog string, rotated []rotatedLog) []string {
	var lines []string

	// Read rotated logs first (oldest to newest)
	for _, entry := range rotated {
		lines = append(lines, readLogFileLines(entry.path)...)
	}

	// Read current log last
	if currentLog != "" {
		lines = append(lines, readLogFileLines(currentLog)...)
	}

	return lines
}

// readLogFileLines reads a single log file and returns non-empty lines.
func readLogFileLines(path string) []string {
	content, err := readLogFile(path)
	if err != nil {
		return []string{}
	}

	var lines []string
	for _, line := range strings.Split(string(content), "\n") {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// readLogFile reads the contents of a log file, handling gzip compression if necessary.
func readLogFile(path string) ([]byte, error) {
	// Validate path for security
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("invalid log file path: %w", err)
	}

	// Additional security check: ensure path doesn't contain dangerous patterns
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid log file path: contains path traversal")
	}

	// #nosec G304 - Path is validated and sanitized above
	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			logrus.WithError(cerr).Error("failed to close log file")
		}
	}()

	// Check if file is gzip compressed by reading magic bytes
	var magic [2]byte
	n, err := f.Read(magic[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	// Seek back to beginning
	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	// Check if we have gzip magic bytes (0x1f, 0x8b)
	if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer func() {
			if cerr := gz.Close(); cerr != nil {
				logrus.WithError(cerr).Error("failed to close gzip reader")
			}
		}()
		return io.ReadAll(gz)
	}

	return io.ReadAll(f)
}

// applyFilters applies jail and IP filters to log lines.
func applyFilters(lines []string, jailFilter, ipFilter string) []string {
	if jailFilter != "" && jailFilter != AllFilter {
		lines = filterByJail(lines, jailFilter)
	}
	if ipFilter != "" && ipFilter != AllFilter {
		lines = filterByIP(lines, ipFilter)
	}
	return lines
}

// filterByJail filters lines by jail name.
func filterByJail(lines []string, jailFilter string) []string {
	identifier := fmt.Sprintf("[%s]", jailFilter)
	var filtered []string
	for _, line := range lines {
		if strings.Contains(line, identifier) {
			filtered = append(filtered, line)
		}
	}
	return filtered
}

// filterByIP filters lines by IP address.
func filterByIP(lines []string, ipFilter string) []string {
	var filtered []string
	for _, line := range lines {
		if strings.Contains(line, ipFilter) {
			filtered = append(filtered, line)
		}
	}
	return filtered
}
