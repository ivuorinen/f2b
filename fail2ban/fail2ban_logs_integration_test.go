package fail2ban

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIntegrationFullLogProcessing(t *testing.T) {
	// Use full anonymized log for integration testing
	testLogFile := filepath.Join("testdata", "fail2ban_full.log")

	// Set up test environment with test data
	cleanup := setupTestLogEnvironment(t, testLogFile)
	defer cleanup()

	t.Run("process_full_log", testProcessFullLog)
	t.Run("extract_ban_events", testExtractBanEvents)
	t.Run("track_persistent_attacker", testTrackPersistentAttacker)
}

// testProcessFullLog tests processing of the entire log file
func testProcessFullLog(t *testing.T) {
	start := time.Now()
	lines, err := GetLogLines(context.Background(), "", "")
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to process full log: %v", err)
	}

	// Should process 481 lines
	if len(lines) < 480 {
		t.Errorf("Expected ~481 lines, got %d", len(lines))
	}

	// Performance check - should be fast
	if duration > 100*time.Millisecond {
		t.Logf("Warning: Processing took %v, might need optimization", duration)
	}

	t.Logf("Processed %d lines in %v", len(lines), duration)
}

// testExtractBanEvents tests extraction of ban/unban events
func testExtractBanEvents(t *testing.T) {
	lines, err := GetLogLines(context.Background(), "sshd", "")
	if err != nil {
		t.Fatalf("Failed to get log lines: %v", err)
	}

	banCount, unbanCount, foundCount := countEventTypes(lines)

	t.Logf("Statistics: %d found events, %d bans, %d unbans", foundCount, banCount, unbanCount)

	// Verify we found real events
	if banCount == 0 {
		t.Error("No ban events found in full log")
	}
	if unbanCount == 0 {
		t.Error("No unban events found in full log")
	}
	if foundCount == 0 {
		t.Error("No found events in full log")
	}
}

// testTrackPersistentAttacker tests tracking a specific attacker across the log
func testTrackPersistentAttacker(t *testing.T) {
	// Track 192.168.1.100 (most frequent attacker)
	lines, err := GetLogLines(context.Background(), "", "192.168.1.100")
	if err != nil {
		t.Fatalf("Failed to filter by IP: %v", err)
	}

	// Should have multiple entries
	if len(lines) < 10 {
		t.Errorf("Expected multiple entries for persistent attacker, got %d", len(lines))
	}

	// Verify chronological order
	if err := verifyChronologicalOrder(lines); err != nil {
		t.Error(err)
	}
}

// countEventTypes counts ban, unban, and found events in log lines
func countEventTypes(lines []string) (banCount, unbanCount, foundCount int) {
	for _, line := range lines {
		if strings.Contains(line, "Ban ") {
			banCount++
		} else if strings.Contains(line, "Unban ") {
			unbanCount++
		} else if strings.Contains(line, "Found ") {
			foundCount++
		}
	}
	return
}

// verifyChronologicalOrder verifies that log lines are in chronological order
func verifyChronologicalOrder(lines []string) error {
	var lastTime time.Time
	for _, line := range lines {
		// Parse timestamp from line
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			dateStr := parts[0]
			timeStr := strings.TrimSuffix(parts[1], ",")
			timeStr = strings.Replace(timeStr, ",", ".", 1)
			fullTime := dateStr + " " + timeStr

			parsedTime, err := time.Parse("2006-01-02 15:04:05.000", fullTime)
			if err == nil {
				if !lastTime.IsZero() && parsedTime.Before(lastTime) {
					return fmt.Errorf("log entries not in chronological order")
				}
				lastTime = parsedTime
			}
		}
	}
	return nil
}

func TestIntegrationConcurrentLogReading(t *testing.T) {
	// Test concurrent access to log files
	testLogFile := filepath.Join("testdata", "fail2ban_sample.log")

	// Set up test environment with test data
	cleanup := setupTestLogEnvironment(t, testLogFile)
	defer cleanup()

	// Run multiple concurrent readers
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Each goroutine reads with different filters
			var jail, ip string
			switch id % 3 {
			case 0:
				jail = "sshd"
			case 1:
				ip = "192.168.1.100"
			case 2:
				jail = "sshd"
				ip = "10.0.0.50"
			}

			lines, err := GetLogLines(context.Background(), jail, ip)
			if err != nil {
				errors <- err
				return
			}

			if len(lines) == 0 && jail == "sshd" {
				errors <- fmt.Errorf("expected log lines for sshd jail but got empty result")
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		if err != nil {
			t.Errorf("Concurrent read error: %v", err)
		}
	}
}

func TestIntegrationBanRecordParsing(t *testing.T) {
	// Test parsing ban records with real patterns
	parser, err := NewBanRecordParser()
	if err != nil {
		t.Fatal(err)
	}

	// Use dynamic dates relative to current time
	now := time.Now()
	future10min := now.Add(10 * time.Minute)
	past1hour := now.Add(-1 * time.Hour)
	past50min := now.Add(-50 * time.Minute)

	// Date format used by fail2ban
	dateFmt := "2006-01-02 15:04:05"

	// Simulate output from fail2ban-client
	realPatterns := []string{
		// Current bans with different time formats
		fmt.Sprintf("192.168.1.100 %s + %s remaining", now.Format(dateFmt), future10min.Format(dateFmt)),
		fmt.Sprintf(
			"10.0.0.50 %s + %s remaining",
			now.Add(6*time.Minute).Format(dateFmt),
			now.Add(16*time.Minute).Format(dateFmt),
		),
		fmt.Sprintf(
			"172.16.0.100 %s + %s remaining",
			now.Add(22*time.Minute).Format(dateFmt),
			now.Add(32*time.Minute).Format(dateFmt),
		),
		// Already expired
		fmt.Sprintf("192.168.2.100 %s + %s remaining", past1hour.Format(dateFmt), past50min.Format(dateFmt)),
	}

	output := strings.Join(realPatterns, "\n")
	records, err := parser.ParseBanRecords(output, "sshd")
	if err != nil {
		t.Fatalf("Failed to parse ban records: %v", err)
	}

	// Should parse all records
	if len(records) != 4 {
		t.Errorf("Expected 4 records, got %d", len(records))
	}

	// Verify record details
	for i, record := range records {
		if record.Jail != "sshd" {
			t.Errorf("Record %d: wrong jail %s", i, record.Jail)
		}

		if record.IP == "" {
			t.Errorf("Record %d: empty IP", i)
		}

		if record.BannedAt.IsZero() {
			t.Errorf("Record %d: zero ban time", i)
		}

		// Check remaining time format
		if record.Remaining == "" {
			t.Errorf("Record %d: empty remaining time", i)
		}
	}
}

func TestIntegrationCompressedLogReading(t *testing.T) {
	// Test reading compressed log files
	compressedLog := filepath.Join("testdata", "fail2ban_compressed.log.gz")

	if _, err := os.Stat(compressedLog); os.IsNotExist(err) {
		t.Skip("Compressed test data file not found:", compressedLog)
	}

	detector := NewGzipDetector()

	// Test 1: Detect gzip file
	isGzip, err := detector.IsGzipFile(compressedLog)
	if err != nil {
		t.Fatalf("Failed to detect gzip: %v", err)
	}
	if !isGzip {
		t.Error("Failed to detect compressed file")
	}

	// Test 2: Read compressed content
	scanner, cleanup, err := detector.CreateGzipAwareScanner(compressedLog)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer cleanup()

	lineCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lineCount++
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("Scanner error: %v", err)
	}

	// Should read all lines from compressed file
	if lineCount < 50 {
		t.Errorf("Expected at least 50 lines from compressed file, got %d", lineCount)
	}
}

func TestIntegrationParallelLogProcessing(t *testing.T) {
	// Test parallel processing of multiple jails
	testLogFile := filepath.Join("testdata", "fail2ban_multi_jail.log")

	// Set up test environment using secure helper
	cleanup := setupTestLogEnvironment(t, testLogFile)
	defer cleanup()

	// Process multiple jails in parallel
	jails := []string{"sshd", "nginx", "postfix", "dovecot"}
	ctx := context.Background()

	// Use parallel processing to read logs for each jail
	pool := NewWorkerPool[string, []string](4)

	start := time.Now()
	results, err := pool.Process(ctx, jails, func(_ context.Context, jail string) ([]string, error) {
		return GetLogLines(context.Background(), jail, "")
	})
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Parallel processing failed: %v", err)
	}

	// Verify results
	totalLines := 0
	for i, result := range results {
		if result.Error != nil {
			t.Errorf("Error processing jail %s: %v", jails[i], result.Error)
			continue
		}
		totalLines += len(result.Value)
	}

	t.Logf("Processed %d jails in %v, total lines: %d", len(jails), duration, totalLines)

	// Should be faster than sequential
	if duration > 50*time.Millisecond {
		t.Logf("Warning: Parallel processing took %v", duration)
	}
}

func TestIntegrationMemoryUsage(t *testing.T) {
	// Test memory usage with large log processing
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	testLogFile := filepath.Join("testdata", "fail2ban_full.log")

	// Set up test environment using secure helper
	cleanup := setupTestLogEnvironment(t, testLogFile)
	defer cleanup()

	// Record initial memory stats
	runtime.GC() // Force GC to get baseline
	var initialStats runtime.MemStats
	runtime.ReadMemStats(&initialStats)

	// Process log multiple times to check for leaks
	for i := 0; i < 10; i++ {
		lines, err := GetLogLines(context.Background(), "", "")
		if err != nil {
			t.Fatalf("Iteration %d failed: %v", i, err)
		}

		// Verify consistent results
		if len(lines) < 480 {
			t.Errorf("Iteration %d: unexpected line count %d", i, len(lines))
		}

		// Clear to help GC
		runtime.GC()
	}

	// Record final memory stats and check for leaks
	runtime.GC() // Force final GC
	var finalStats runtime.MemStats
	runtime.ReadMemStats(&finalStats)

	// Calculate memory growth (handle potential negative values from GC)
	var memoryGrowth uint64
	if finalStats.Alloc >= initialStats.Alloc {
		memoryGrowth = finalStats.Alloc - initialStats.Alloc
	} else {
		// Memory decreased due to GC - this is good, no leak detected
		memoryGrowth = 0
	}
	const memoryThreshold = 10 * 1024 * 1024 // 10MB threshold

	if memoryGrowth > memoryThreshold {
		t.Errorf("Memory leak detected: memory grew by %d bytes (threshold: %d bytes)",
			memoryGrowth, memoryThreshold)
	}

	t.Logf("Memory usage test passed - memory growth: %d bytes (threshold: %d bytes)",
		memoryGrowth, memoryThreshold)
}

func BenchmarkLogParsing(b *testing.B) {
	testLogFile := filepath.Join("testdata", "fail2ban_full.log")

	// Ensure test file exists and get absolute path
	absTestLogFile, err := filepath.Abs(testLogFile)
	if err != nil {
		b.Fatalf("Failed to get absolute path: %v", err)
	}
	if _, err := os.Stat(absTestLogFile); os.IsNotExist(err) {
		b.Skip("Full test data file not found:", absTestLogFile)
	}

	// Ensure the file is within testdata directory for security
	if !strings.Contains(absTestLogFile, "testdata") {
		b.Fatalf("Test file must be in testdata directory: %s", absTestLogFile)
	}

	// Copy the test file to make it look like the main log
	// (symlinks are not allowed by the security validation)
	tempDir := b.TempDir()
	mainLog := filepath.Join(tempDir, "fail2ban.log")

	// Copy the file (don't use symlinks due to security restrictions)
	// #nosec G304 - This is benchmark code reading controlled test data files
	data, err := os.ReadFile(absTestLogFile)
	if err != nil {
		b.Fatalf("Failed to read test file: %v", err)
	}
	if err := os.WriteFile(mainLog, data, 0600); err != nil {
		b.Fatalf("Failed to create test log: %v", err)
	}

	origLogDir := GetLogDir()
	SetLogDir(tempDir)
	defer SetLogDir(origLogDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GetLogLines(context.Background(), "sshd", "")
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

func BenchmarkBanRecordParsing(b *testing.B) {
	parser, err := NewBanRecordParser()
	if err != nil {
		b.Fatal(err)
	}

	// Use dynamic dates for benchmark
	now := time.Now()
	future := now.Add(10 * time.Minute)
	dateFmt := "2006-01-02 15:04:05"

	// Realistic output with 20 ban records
	var records []string
	for i := 0; i < 20; i++ {
		records = append(records,
			fmt.Sprintf("192.168.1.%d %s + %s remaining", i+100, now.Format(dateFmt), future.Format(dateFmt)))
	}
	output := strings.Join(records, "\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.ParseBanRecords(output, "sshd")
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}
