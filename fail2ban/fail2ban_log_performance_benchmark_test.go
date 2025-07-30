package fail2ban

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkOriginalLogParsing benchmarks the current log parsing implementation
func BenchmarkOriginalLogParsing(b *testing.B) {
	// Set up test environment with test data
	testLogFile := filepath.Join("testdata", "fail2ban_full.log")

	// Ensure test file exists
	if _, err := os.Stat(testLogFile); os.IsNotExist(err) {
		b.Skip("Test log file not found:", testLogFile)
	}

	cleanup := setupBenchmarkLogEnvironment(b, testLogFile)
	defer cleanup()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := GetLogLinesWithLimit("sshd", "", 100)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOptimizedLogParsing benchmarks the new optimized implementation
func BenchmarkOptimizedLogParsing(b *testing.B) {
	// Set up test environment with test data
	testLogFile := filepath.Join("testdata", "fail2ban_full.log")

	// Ensure test file exists
	if _, err := os.Stat(testLogFile); os.IsNotExist(err) {
		b.Skip("Test log file not found:", testLogFile)
	}

	cleanup := setupBenchmarkLogEnvironment(b, testLogFile)
	defer cleanup()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := GetLogLinesUltraOptimized("sshd", "", 100)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGzipDetectionComparison compares gzip detection methods
func BenchmarkGzipDetectionComparison(b *testing.B) {
	testFiles := []string{
		filepath.Join("testdata", "fail2ban_full.log"),          // Regular file
		filepath.Join("testdata", "fail2ban_compressed.log.gz"), // Gzip file
	}

	processor := NewOptimizedLogProcessor()

	for _, testFile := range testFiles {
		if _, err := os.Stat(testFile); os.IsNotExist(err) {
			continue // Skip if file doesn't exist
		}

		baseName := filepath.Base(testFile)

		b.Run("original_"+baseName, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := IsGzipFile(testFile)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run("optimized_"+baseName, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_ = processor.isGzipFileOptimized(testFile)
			}
		})
	}
}

// BenchmarkFileNumberExtraction compares log number extraction methods
func BenchmarkFileNumberExtraction(b *testing.B) {
	testFilenames := []string{
		"fail2ban.log.1",
		"fail2ban.log.2.gz",
		"fail2ban.log.10",
		"fail2ban.log.100.gz",
		"fail2ban.log", // No number
	}

	processor := NewOptimizedLogProcessor()

	b.Run("original", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, filename := range testFilenames {
				_ = extractLogNumber(filename)
			}
		}
	})

	b.Run("optimized", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, filename := range testFilenames {
				_ = processor.extractLogNumberOptimized(filename)
			}
		}
	})
}

// BenchmarkLogFiltering compares log filtering performance
func BenchmarkLogFiltering(b *testing.B) {
	// Sample log lines with various patterns
	testLines := []string{
		"2025-07-20 14:30:39,123 fail2ban.actions[1234]: NOTICE [sshd] Ban 192.168.1.100",
		"2025-07-20 14:31:15,456 fail2ban.actions[1234]: NOTICE [apache] Ban 10.0.0.50",
		"2025-07-20 14:32:01,789 fail2ban.filter[5678]: INFO [sshd] Found 192.168.1.100 - 2025-07-20 14:32:01",
		"2025-07-20 14:33:45,012 fail2ban.actions[1234]: NOTICE [nginx] Ban 172.16.0.100",
		"2025-07-20 14:34:22,345 fail2ban.filter[5678]: INFO [apache] Found 10.0.0.50 - 2025-07-20 14:34:22",
	}

	processor := NewOptimizedLogProcessor()

	b.Run("original_jail_filter", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, line := range testLines {
				// Simulate original filtering logic
				_ = strings.Contains(line, "[sshd]")
			}
		}
	})

	b.Run("optimized_jail_filter", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, line := range testLines {
				_ = processor.matchesFiltersOptimized(line, "sshd", "", true, false)
			}
		}
	})

	b.Run("original_ip_filter", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, line := range testLines {
				// Simulate original IP filtering logic
				_ = strings.Contains(line, "192.168.1.100")
			}
		}
	})

	b.Run("optimized_ip_filter", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, line := range testLines {
				_ = processor.matchesFiltersOptimized(line, "", "192.168.1.100", false, true)
			}
		}
	})
}

// BenchmarkCachePerformance tests the effectiveness of caching
func BenchmarkCachePerformance(b *testing.B) {
	processor := NewOptimizedLogProcessor()
	testFile := filepath.Join("testdata", "fail2ban_full.log")

	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		b.Skip("Test file not found:", testFile)
	}

	b.Run("first_access_cache_miss", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			processor.ClearCaches() // Clear cache to force miss
			_ = processor.isGzipFileOptimized(testFile)
		}
	})

	b.Run("repeated_access_cache_hit", func(b *testing.B) {
		// Prime the cache
		_ = processor.isGzipFileOptimized(testFile)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = processor.isGzipFileOptimized(testFile)
		}
	})
}

// BenchmarkStringPooling tests the effectiveness of string pooling
func BenchmarkStringPooling(b *testing.B) {
	processor := NewOptimizedLogProcessor()

	b.Run("with_pooling", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			// Simulate getting and returning pooled slice
			linesPtr := processor.stringPool.Get().(*[]string)
			lines := (*linesPtr)[:0]

			// Simulate adding lines
			for j := 0; j < 100; j++ {
				lines = append(lines, "test line")
			}

			// Return to pool
			*linesPtr = lines[:0]
			processor.stringPool.Put(linesPtr)
		}
	})

	b.Run("without_pooling", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			// Simulate creating new slice each time
			lines := make([]string, 0, 1000)

			// Simulate adding lines
			for j := 0; j < 100; j++ {
				lines = append(lines, "test line")
			}

			// Let it be garbage collected
			_ = lines
		}
	})
}

// BenchmarkLargeLogDataset tests performance with larger datasets
func BenchmarkLargeLogDataset(b *testing.B) {
	testLogFile := filepath.Join("testdata", "fail2ban_full.log")

	if _, err := os.Stat(testLogFile); os.IsNotExist(err) {
		b.Skip("Test log file not found:", testLogFile)
	}

	cleanup := setupBenchmarkLogEnvironment(b, testLogFile)
	defer cleanup()

	// Test with different line limits
	limits := []int{100, 500, 1000, 5000}

	for _, limit := range limits {
		b.Run(fmt.Sprintf("original_lines_%d", limit), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := GetLogLinesWithLimit("", "", limit)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		b.Run(fmt.Sprintf("optimized_lines_%d", limit), func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := GetLogLinesUltraOptimized("", "", limit)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkMemoryPoolEfficiency tests memory pool efficiency
func BenchmarkMemoryPoolEfficiency(b *testing.B) {
	processor := NewOptimizedLogProcessor()

	// Test scanner buffer pooling
	b.Run("scanner_buffer_pooling", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			bufPtr := processor.scannerPool.Get().(*[]byte)
			buf := (*bufPtr)[:cap(*bufPtr)]

			// Simulate using buffer
			for j := 0; j < 1000; j++ {
				if j < len(buf) {
					buf[j] = byte(j % 256)
				}
			}

			*bufPtr = (*bufPtr)[:0]
			processor.scannerPool.Put(bufPtr)
		}
	})

	// Test line buffer pooling
	b.Run("line_buffer_pooling", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			bufPtr := processor.linePool.Get().(*[]byte)
			buf := (*bufPtr)[:0]

			// Simulate building a line
			testLine := "test log line with some content"
			buf = append(buf, testLine...)

			*bufPtr = buf[:0]
			processor.linePool.Put(bufPtr)
		}
	})
}

// Helper function to set up test environment (reuse from existing tests)
func setupBenchmarkLogEnvironment(tb testing.TB, testLogFile string) func() {
	tb.Helper()
	// Create temporary directory
	tempDir := tb.TempDir()

	// Copy test file to temp directory as fail2ban.log
	mainLog := filepath.Join(tempDir, "fail2ban.log")

	// Read and copy file
	// #nosec G304 - testLogFile is a controlled test data file path
	data, err := os.ReadFile(testLogFile)
	if err != nil {
		tb.Fatalf("Failed to read test file: %v", err)
	}

	if err := os.WriteFile(mainLog, data, 0600); err != nil {
		tb.Fatalf("Failed to create test log: %v", err)
	}

	// Set log directory
	origLogDir := GetLogDir()
	SetLogDir(tempDir)

	return func() {
		SetLogDir(origLogDir)
	}
}
