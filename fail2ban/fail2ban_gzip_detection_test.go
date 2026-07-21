package fail2ban

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGzipDetector(t *testing.T) {
	detector := NewGzipDetector()

	// Create temp directory with test files
	files := map[string][]byte{
		"regular.log": []byte("test log line\n"),
	}
	tempDir := setupTempDirWithFiles(t, files)

	// Test gzip file
	regularFile := filepath.Join(tempDir, "regular.log")
	gzipFile := filepath.Join(tempDir, "compressed.log.gz")
	createTestGzipFile(t, gzipFile, []byte("compressed log line\n"))

	tests := []struct {
		name   string
		file   string
		isGzip bool
	}{
		{
			name:   "regular file",
			file:   regularFile,
			isGzip: false,
		},
		{
			name:   "gzip file with .gz extension",
			file:   gzipFile,
			isGzip: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isGzip, err := detector.IsGzipFile(tt.file)
			if err != nil {
				t.Fatalf("IsGzipFile failed: %v", err)
			}
			if isGzip != tt.isGzip {
				t.Errorf("IsGzipFile = %v, want %v", isGzip, tt.isGzip)
			}
		})
	}
}

func TestOpenGzipAwareReader(t *testing.T) {
	detector := NewGzipDetector()

	// Create temp directory with test files
	testContent := "test log line\nsecond line\n"
	files := map[string][]byte{
		"regular.log": []byte(testContent),
	}
	tempDir := setupTempDirWithFiles(t, files)
	regularFile := filepath.Join(tempDir, "regular.log")

	// Test gzip file
	gzipFile := filepath.Join(tempDir, "compressed.log.gz")
	gzipContent := "compressed log line\ncompressed second line\n"
	createTestGzipFile(t, gzipFile, []byte(gzipContent))

	tests := []struct {
		name     string
		file     string
		expected string
	}{
		{
			name:     "regular file",
			file:     regularFile,
			expected: testContent,
		},
		{
			name:     "gzip file",
			file:     gzipFile,
			expected: gzipContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader, err := detector.OpenGzipAwareReader(tt.file)
			if err != nil {
				t.Fatalf("OpenGzipAwareReader failed: %v", err)
			}
			defer func() { _ = reader.Close() }()

			content, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll failed: %v", err)
			}

			if string(content) != tt.expected {
				t.Errorf("Content = %q, want %q", string(content), tt.expected)
			}
		})
	}
}

func TestCreateGzipAwareScanner(t *testing.T) {
	detector := NewGzipDetector()

	// Create temp directory with test files
	testLines := []string{"line1", "line2", "line3"}
	testContent := strings.Join(testLines, "\n")
	files := map[string][]byte{
		"regular.log": []byte(testContent),
	}
	tempDir := setupTempDirWithFiles(t, files)
	regularFile := filepath.Join(tempDir, "regular.log")

	// Test gzip file
	gzipFile := filepath.Join(tempDir, "compressed.log.gz")
	gzipLines := []string{"gzip1", "gzip2", "gzip3"}
	gzipContent := strings.Join(gzipLines, "\n")
	createTestGzipFile(t, gzipFile, []byte(gzipContent))

	tests := []struct {
		name          string
		file          string
		expectedLines []string
	}{
		{
			name:          "regular file",
			file:          regularFile,
			expectedLines: testLines,
		},
		{
			name:          "gzip file",
			file:          gzipFile,
			expectedLines: gzipLines,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertGzipScanner(t, detector, tt.file, tt.expectedLines)
		})
	}
}

func assertGzipScanner(t *testing.T, detector *GzipDetector, file string, expectedLines []string) {
	t.Helper()
	scanner, cleanup, err := detector.CreateGzipAwareScanner(file)
	if err != nil {
		t.Fatalf("CreateGzipAwareScanner failed: %v", err)
	}
	defer cleanup()

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("Scanner error: %v", err)
	}

	if len(lines) != len(expectedLines) {
		t.Fatalf("Line count = %d, want %d", len(lines), len(expectedLines))
	}

	for i, line := range lines {
		if line != expectedLines[i] {
			t.Errorf("Line %d = %q, want %q", i, line, expectedLines[i])
		}
	}
}

func TestCreateGzipAwareScannerWithBuffer(t *testing.T) {
	detector := NewGzipDetector()

	// Create temp file with long line
	tempDir := t.TempDir()
	longLineFile := filepath.Join(tempDir, "longline.log")
	longLine := strings.Repeat("a", 1000) // 1000 characters
	err := os.WriteFile(longLineFile, []byte(longLine), 0600)
	if err != nil {
		t.Fatalf("Failed to create long line file: %v", err)
	}

	// Test with buffer size larger than line
	scanner, cleanup, err := detector.CreateGzipAwareScannerWithBuffer(longLineFile, 2000)
	if err != nil {
		t.Fatalf("CreateGzipAwareScannerWithBuffer failed: %v", err)
	}
	defer cleanup()

	if scanner.Scan() {
		if len(scanner.Text()) != 1000 {
			t.Errorf("Scanned line length = %d, want 1000", len(scanner.Text()))
		}
	} else {
		t.Error("Scanner failed to read line")
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("Scanner error: %v", err)
	}
}

func TestGlobalFunctions(t *testing.T) {
	// Create temp directory for test files
	tempDir := t.TempDir()

	// Test regular file
	regularFile := filepath.Join(tempDir, "regular.log")
	err := os.WriteFile(regularFile, []byte("test content"), 0600)
	if err != nil {
		t.Fatalf("Failed to create regular file: %v", err)
	}

	// Test IsGzipFile global function
	isGzip, err := IsGzipFile(regularFile)
	if err != nil {
		t.Fatalf("IsGzipFile failed: %v", err)
	}
	if isGzip {
		t.Error("Regular file detected as gzip")
	}

	// Test OpenGzipAwareReader global function
	reader, err := OpenGzipAwareReader(regularFile)
	if err != nil {
		t.Fatalf("OpenGzipAwareReader failed: %v", err)
	}
	defer func() { _ = reader.Close() }()

	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if string(content) != "test content" {
		t.Errorf("Content = %q, want %q", string(content), "test content")
	}

	// Test CreateGzipAwareScanner global function
	scanner, cleanup, err := CreateGzipAwareScanner(regularFile)
	if err != nil {
		t.Fatalf("CreateGzipAwareScanner failed: %v", err)
	}
	defer cleanup()

	if scanner.Scan() {
		if scanner.Text() != "test content" {
			t.Errorf("Scanned text = %q, want %q", scanner.Text(), "test content")
		}
	} else {
		t.Error("Scanner failed to read line")
	}
}

func TestGzipFileReaderClose(t *testing.T) {
	// Create temp gzip file
	tempDir := t.TempDir()
	gzipFile := filepath.Join(tempDir, "test.log.gz")
	createTestGzipFile(t, gzipFile, []byte("test content"))

	// Test that gzipFileReader closes both readers properly
	reader, err := OpenGzipAwareReader(gzipFile)
	if err != nil {
		t.Fatalf("OpenGzipAwareReader failed: %v", err)
	}

	// Read some content
	buf := make([]byte, 4)
	_, err = reader.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// Close should not error
	err = reader.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func BenchmarkGzipDetection(b *testing.B) {
	detector := NewGzipDetector()

	// Create test files
	files := map[string][]byte{
		"regular.log": []byte("test content"),
	}
	tempDir := setupTempDirWithFiles(b, files)

	regularFile := filepath.Join(tempDir, "regular.log")
	gzipFile := filepath.Join(tempDir, "compressed.log.gz")
	createTestGzipFile(b, gzipFile, []byte("compressed content"))

	b.Run("regular file", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = detector.IsGzipFile(regularFile)
		}
	})

	b.Run("gzip file with extension", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = detector.IsGzipFile(gzipFile)
		}
	})
}

// TestGzipDetectionWithRealTestData tests gzip detection with actual test data files
func TestGzipDetectionWithRealTestData(t *testing.T) {
	detector := NewGzipDetector()

	// Test with real test data files
	tests := []struct {
		name     string
		file     string
		wantGzip bool
	}{
		{
			name:     "uncompressed log file",
			file:     filepath.Join("testdata", "fail2ban_sample.log"),
			wantGzip: false,
		},
		{
			name:     "compressed log file",
			file:     filepath.Join("testdata", "fail2ban_compressed.log.gz"),
			wantGzip: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The fixtures are checked in: a missing one is a broken tree,
			// not an environmental precondition, so fail instead of skip.
			if _, err := os.Stat(tt.file); os.IsNotExist(err) {
				t.Fatalf("checked-in test data file missing: %s", tt.file)
			}

			isGzip, err := detector.IsGzipFile(tt.file)
			if err != nil {
				t.Fatalf("IsGzipFile failed: %v", err)
			}

			if isGzip != tt.wantGzip {
				t.Errorf("IsGzipFile(%s) = %v, want %v", tt.file, isGzip, tt.wantGzip)
			}
		})
	}
}

// TestReadCompressedRealLogs tests reading actual compressed log data
func TestReadCompressedRealLogs(t *testing.T) {
	detector := NewGzipDetector()
	compressedFile := filepath.Join("testdata", "fail2ban_compressed.log.gz")

	// Checked-in fixture: missing means broken tree, so fail instead of skip.
	if _, err := os.Stat(compressedFile); os.IsNotExist(err) {
		t.Fatal("checked-in compressed test data file missing:", compressedFile)
	}

	// Create scanner for compressed file
	scanner, cleanup, err := detector.CreateGzipAwareScanner(compressedFile)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer cleanup()

	// Read and verify content
	lineCount := 0
	var firstLine, lastLine string

	for scanner.Scan() {
		line := scanner.Text()
		if lineCount == 0 {
			firstLine = line
		}
		lastLine = line
		lineCount++
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("Scanner error: %v", err)
	}

	// Should have read the expected number of lines
	if lineCount < 50 {
		t.Errorf("Expected at least 50 lines, got %d", lineCount)
	}

	// Verify content looks like fail2ban logs
	if !strings.Contains(firstLine, "fail2ban") {
		t.Error("First line doesn't look like a fail2ban log")
	}

	t.Logf("Read %d lines from compressed file", lineCount)
	t.Logf("First line: %s", firstLine)
	t.Logf("Last line: %s", lastLine)
}

// BenchmarkGzipDetectionWithRealFile benchmarks with actual test data
func BenchmarkGzipDetectionWithRealFile(b *testing.B) {
	detector := NewGzipDetector()
	compressedFile := filepath.Join("testdata", "fail2ban_compressed.log.gz")

	// Skip if test file doesn't exist
	if _, err := os.Stat(compressedFile); os.IsNotExist(err) {
		b.Skip("Compressed test data file not found:", compressedFile)
	}

	b.ResetTimer()
	for b.Loop() {
		isGzip, err := detector.IsGzipFile(compressedFile)
		if err != nil {
			b.Fatalf("IsGzipFile failed: %v", err)
		}
		if !isGzip {
			b.Fatal("Expected file to be detected as gzip")
		}
	}
}
