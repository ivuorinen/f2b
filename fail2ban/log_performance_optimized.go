package fail2ban

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"
)

// OptimizedLogProcessor provides high-performance log processing with caching and optimizations
type OptimizedLogProcessor struct {
	// Caches for performance
	gzipCache     sync.Map // string -> bool (path -> isGzip)
	pathCache     sync.Map // string -> string (pattern -> cleanPath)
	fileInfoCache sync.Map // string -> *CachedFileInfo

	// Object pools for reducing allocations
	stringPool  sync.Pool
	linePool    sync.Pool
	scannerPool sync.Pool

	// Statistics (thread-safe atomic counters)
	cacheHits   atomic.Int64
	cacheMisses atomic.Int64
}

// CachedFileInfo holds cached information about a log file
type CachedFileInfo struct {
	Path      string
	IsGzip    bool
	Size      int64
	ModTime   int64
	LogNumber int // For rotated logs: -1 for current, >=0 for rotated
	IsValid   bool
}

// OptimizedRotatedLog represents a rotated log file with cached info
type OptimizedRotatedLog struct {
	Num  int
	Path string
	Info *CachedFileInfo
}

// NewOptimizedLogProcessor creates a new high-performance log processor
func NewOptimizedLogProcessor() *OptimizedLogProcessor {
	processor := &OptimizedLogProcessor{}

	// String slice pool for lines
	processor.stringPool = sync.Pool{
		New: func() interface{} {
			s := make([]string, 0, 1000) // Pre-allocate for typical log sizes
			return &s
		},
	}

	// Line buffer pool for individual lines
	processor.linePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 512) // Pre-allocate for typical line lengths
			return &b
		},
	}

	// Scanner buffer pool
	processor.scannerPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 0, 64*1024) // 64KB scanner buffer
			return &b
		},
	}

	return processor
}

// GetLogLinesOptimized provides optimized log line retrieval with caching
func (olp *OptimizedLogProcessor) GetLogLinesOptimized(jailFilter, ipFilter string, maxLines int) ([]string, error) {
	// Fast path for log directory pattern caching
	pattern := filepath.Join(GetLogDir(), "fail2ban.log*")
	files, err := olp.getCachedGlobResults(pattern)
	if err != nil {
		return nil, fmt.Errorf("error listing log files: %w", err)
	}

	if len(files) == 0 {
		return []string{}, nil
	}

	// Optimized file parsing and sorting
	currentLog, rotated := olp.parseLogFilesOptimized(files)

	// Get pooled string slice
	linesPtr := olp.stringPool.Get().(*[]string)
	lines := (*linesPtr)[:0] // Reset slice but keep capacity
	defer func() {
		*linesPtr = lines[:0]
		olp.stringPool.Put(linesPtr)
	}()

	config := LogReadConfig{
		MaxLines:     maxLines,
		MaxFileSize:  100 * 1024 * 1024, // 100MB file size limit
		JailFilter:   jailFilter,
		IPFilter:     ipFilter,
		ReverseOrder: false,
	}

	totalLines := 0

	// Process rotated logs first (oldest to newest)
	for _, rotatedLog := range rotated {
		if config.MaxLines > 0 && totalLines >= config.MaxLines {
			break
		}

		remainingLines := config.MaxLines - totalLines
		if remainingLines <= 0 {
			break
		}

		fileConfig := config
		fileConfig.MaxLines = remainingLines

		fileLines, err := olp.streamLogFileOptimized(rotatedLog.Path, fileConfig)
		if err != nil {
			logrus.WithError(err).WithField("file", rotatedLog.Path).Error("Failed to read log file")
			continue
		}

		lines = append(lines, fileLines...)
		totalLines += len(fileLines)
	}

	// Process current log last
	if currentLog != "" && (config.MaxLines == 0 || totalLines < config.MaxLines) {
		remainingLines := config.MaxLines - totalLines
		if remainingLines > 0 || config.MaxLines == 0 {
			fileConfig := config
			if config.MaxLines > 0 {
				fileConfig.MaxLines = remainingLines
			}

			fileLines, err := olp.streamLogFileOptimized(currentLog, fileConfig)
			if err != nil {
				logrus.WithError(err).WithField("file", currentLog).Error("Failed to read current log file")
			} else {
				lines = append(lines, fileLines...)
			}
		}
	}

	// Return a copy since we're pooling the original
	result := make([]string, len(lines))
	copy(result, lines)
	return result, nil
}

// getCachedGlobResults caches glob results for performance
func (olp *OptimizedLogProcessor) getCachedGlobResults(pattern string) ([]string, error) {
	// For now, don't cache glob results as file lists change frequently
	// In a production system, you might cache with a TTL
	return filepath.Glob(pattern)
}

// parseLogFilesOptimized optimizes file parsing with caching and better sorting
func (olp *OptimizedLogProcessor) parseLogFilesOptimized(files []string) (string, []OptimizedRotatedLog) {
	var currentLog string
	rotated := make([]OptimizedRotatedLog, 0, len(files))

	for _, path := range files {
		base := filepath.Base(path)

		if base == "fail2ban.log" {
			currentLog = path
		} else if strings.HasPrefix(base, "fail2ban.log.") {
			// Extract number more efficiently
			if num := olp.extractLogNumberOptimized(base); num >= 0 {
				info := olp.getCachedFileInfo(path)
				rotated = append(rotated, OptimizedRotatedLog{
					Num:  num,
					Path: path,
					Info: info,
				})
			}
		}
	}

	// Sort with cached info for better performance
	olp.sortRotatedLogsOptimized(rotated)

	return currentLog, rotated
}

// extractLogNumberOptimized efficiently extracts log numbers from filenames
func (olp *OptimizedLogProcessor) extractLogNumberOptimized(basename string) int {
	// For "fail2ban.log.1" or "fail2ban.log.1.gz"
	parts := strings.Split(basename, ".")
	if len(parts) < 3 {
		return -1
	}

	// parts[2] should be the number
	numStr := parts[2]
	if num, err := strconv.Atoi(numStr); err == nil && num >= 0 {
		return num
	}

	return -1
}

// getCachedFileInfo gets or creates cached file information
func (olp *OptimizedLogProcessor) getCachedFileInfo(path string) *CachedFileInfo {
	if cached, ok := olp.fileInfoCache.Load(path); ok {
		olp.cacheHits.Add(1)
		return cached.(*CachedFileInfo)
	}

	olp.cacheMisses.Add(1)

	// Create new file info
	info := &CachedFileInfo{
		Path:      path,
		LogNumber: olp.extractLogNumberOptimized(filepath.Base(path)),
		IsValid:   true,
	}

	// Check if file is gzip
	info.IsGzip = olp.isGzipFileOptimized(path)

	// Get file size and mod time if needed for sorting
	if stat, err := os.Stat(path); err == nil {
		info.Size = stat.Size()
		info.ModTime = stat.ModTime().Unix()
	}

	olp.fileInfoCache.Store(path, info)
	return info
}

// isGzipFileOptimized provides cached gzip detection
func (olp *OptimizedLogProcessor) isGzipFileOptimized(path string) bool {
	if cached, ok := olp.gzipCache.Load(path); ok {
		return cached.(bool)
	}

	// Use optimized detection
	isGzip := olp.fastGzipDetection(path)
	olp.gzipCache.Store(path, isGzip)
	return isGzip
}

// fastGzipDetection provides faster gzip detection
func (olp *OptimizedLogProcessor) fastGzipDetection(path string) bool {
	// Super fast path: check extension
	if strings.HasSuffix(path, ".gz") {
		return true
	}

	// For fail2ban logs, if it doesn't end in .gz, it's very likely not gzipped
	// We can skip the expensive magic byte check for known patterns
	basename := filepath.Base(path)
	if strings.HasPrefix(basename, "fail2ban.log") && !strings.Contains(basename, ".gz") {
		return false
	}

	// Fallback to default detection only if necessary
	isGzip, err := IsGzipFile(path)
	if err != nil {
		return false
	}
	return isGzip
}

// sortRotatedLogsOptimized provides optimized sorting
func (olp *OptimizedLogProcessor) sortRotatedLogsOptimized(rotated []OptimizedRotatedLog) {
	// Use a more efficient sorting approach
	sort.Slice(rotated, func(i, j int) bool {
		// Primary sort: by log number (higher number = older)
		if rotated[i].Num != rotated[j].Num {
			return rotated[i].Num > rotated[j].Num
		}

		// Secondary sort: by modification time if numbers are equal
		if rotated[i].Info != nil && rotated[j].Info != nil {
			return rotated[i].Info.ModTime > rotated[j].Info.ModTime
		}

		// Fallback: string comparison
		return rotated[i].Path > rotated[j].Path
	})
}

// streamLogFileOptimized provides optimized log file streaming
func (olp *OptimizedLogProcessor) streamLogFileOptimized(path string, config LogReadConfig) ([]string, error) {
	cleanPath, err := validateLogPath(path)
	if err != nil {
		return nil, err
	}

	if shouldSkipFile(cleanPath, config.MaxFileSize) {
		return []string{}, nil
	}

	// Use cached gzip detection
	isGzip := olp.isGzipFileOptimized(cleanPath)

	// Create optimized scanner
	scanner, cleanup, err := olp.createOptimizedScanner(cleanPath, isGzip)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return olp.scanLogLinesOptimized(scanner, config)
}

// createOptimizedScanner creates an optimized scanner with pooled buffers
func (olp *OptimizedLogProcessor) createOptimizedScanner(path string, isGzip bool) (*bufio.Scanner, func(), error) {
	if isGzip {
		// Use existing gzip-aware scanner
		return CreateGzipAwareScannerWithBuffer(path, 64*1024)
	}

	// For regular files, use optimized approach
	// #nosec G304 - path is validated by validateLogPath before this call
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}

	// Get pooled buffer
	bufPtr := olp.scannerPool.Get().(*[]byte)
	buf := (*bufPtr)[:cap(*bufPtr)] // Use full capacity

	scanner := bufio.NewScanner(file)
	scanner.Buffer(buf, 64*1024) // 64KB max line size

	cleanup := func() {
		if err := file.Close(); err != nil {
			logrus.WithError(err).WithField("file", path).Warn("Failed to close file during cleanup")
		}
		*bufPtr = (*bufPtr)[:0] // Reset buffer
		olp.scannerPool.Put(bufPtr)
	}

	return scanner, cleanup, nil
}

// scanLogLinesOptimized provides optimized line scanning with reduced allocations
func (olp *OptimizedLogProcessor) scanLogLinesOptimized(
	scanner *bufio.Scanner,
	config LogReadConfig,
) ([]string, error) {
	// Get pooled string slice
	linesPtr := olp.stringPool.Get().(*[]string)
	lines := (*linesPtr)[:0] // Reset slice but keep capacity
	defer func() {
		*linesPtr = lines[:0]
		olp.stringPool.Put(linesPtr)
	}()

	lineCount := 0
	hasJailFilter := config.JailFilter != "" && config.JailFilter != "all"
	hasIPFilter := config.IPFilter != "" && config.IPFilter != "all"

	for scanner.Scan() {
		if config.MaxLines > 0 && lineCount >= config.MaxLines {
			break
		}

		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		// Fast filtering without trimming unless necessary
		if hasJailFilter || hasIPFilter {
			if !olp.matchesFiltersOptimized(line, config.JailFilter, config.IPFilter, hasJailFilter, hasIPFilter) {
				continue
			}
		}

		lines = append(lines, line)
		lineCount++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Return a copy since we're pooling the original
	result := make([]string, len(lines))
	copy(result, lines)
	return result, nil
}

// matchesFiltersOptimized provides optimized filtering with minimal allocations
func (olp *OptimizedLogProcessor) matchesFiltersOptimized(
	line, jailFilter, ipFilter string,
	hasJailFilter, hasIPFilter bool,
) bool {
	if !hasJailFilter && !hasIPFilter {
		return true
	}

	// Fast byte-level searching to avoid string allocations
	lineBytes := []byte(line)

	jailMatch := !hasJailFilter
	ipMatch := !hasIPFilter

	if hasJailFilter && !jailMatch {
		// Look for jail pattern: [jail-name]
		jailPattern := "[" + jailFilter + "]"
		if olp.fastContains(lineBytes, []byte(jailPattern)) {
			jailMatch = true
		}
	}

	if hasIPFilter && !ipMatch {
		// Look for IP pattern in the line
		if olp.fastContains(lineBytes, []byte(ipFilter)) {
			ipMatch = true
		}
	}

	return jailMatch && ipMatch
}

// fastContains provides fast byte-level substring search
func (olp *OptimizedLogProcessor) fastContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}

	// Use Boyer-Moore-like approach for longer needles
	if len(needle) > 4 {
		return strings.Contains(string(haystack), string(needle))
	}

	// Simple search for short needles
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// GetCacheStats returns cache performance statistics
func (olp *OptimizedLogProcessor) GetCacheStats() (hits, misses int64) {
	return olp.cacheHits.Load(), olp.cacheMisses.Load()
}

// ClearCaches clears all caches (useful for testing or memory management)
func (olp *OptimizedLogProcessor) ClearCaches() {
	// Use sync.Map's Range and Delete methods for thread-safe clearing
	olp.gzipCache.Range(func(key, _ interface{}) bool {
		olp.gzipCache.Delete(key)
		return true
	})

	olp.pathCache.Range(func(key, _ interface{}) bool {
		olp.pathCache.Delete(key)
		return true
	})

	olp.fileInfoCache.Range(func(key, _ interface{}) bool {
		olp.fileInfoCache.Delete(key)
		return true
	})

	olp.cacheHits.Store(0)
	olp.cacheMisses.Store(0)
}

// Global optimized processor instance
var optimizedLogProcessor = NewOptimizedLogProcessor()

// GetLogLinesUltraOptimized provides ultra-optimized log line retrieval
func GetLogLinesUltraOptimized(jailFilter, ipFilter string, maxLines int) ([]string, error) {
	return optimizedLogProcessor.GetLogLinesOptimized(jailFilter, ipFilter, maxLines)
}
