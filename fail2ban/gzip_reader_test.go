package fail2ban

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testIsGzipFileNonexistent tests isGzipFile with non-existent file
func testIsGzipFileNonexistent(t *testing.T) {
	nonexistentPath := filepath.Join(t.TempDir(), "nonexistent.log")

	isGzip, err := isGzipFile(nonexistentPath)
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
	if isGzip {
		t.Error("Should not detect non-existent file as gzip")
	}
}

// testIsGzipFileDirectory tests isGzipFile with directory path
func testIsGzipFileDirectory(t *testing.T) {
	dirPath := t.TempDir()

	isGzip, err := isGzipFile(dirPath)
	if err == nil {
		t.Error("Expected error when trying to check directory as gzip file")
	}
	if isGzip {
		t.Error("Should not detect directory as gzip file")
	}
}

// testIsGzipFileEmpty tests isGzipFile with empty file
func testIsGzipFileEmpty(t *testing.T) {
	tempDir := t.TempDir()
	emptyFile := filepath.Join(tempDir, "empty.log")

	err := os.WriteFile(emptyFile, []byte{}, 0600)
	if err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}

	isGzip, err := isGzipFile(emptyFile)
	if err != nil {
		t.Errorf("Should not error on empty file: %v", err)
	}
	if isGzip {
		t.Error("Empty file should not be detected as gzip")
	}
}

// testOpenGzipAwareReaderNonexistent tests openGzipAwareReader with non-existent file
func testOpenGzipAwareReaderNonexistent(t *testing.T) {
	nonexistentPath := filepath.Join(t.TempDir(), "nonexistent.log")

	reader, err := openGzipAwareReader(nonexistentPath)
	if err == nil {
		t.Error("Expected error for non-existent file")
		if reader != nil {
			_ = reader.Close()
		}
	}
	if reader != nil {
		t.Error("Should not return reader for non-existent file")
	}
}

// testCreateGzipAwareScannerNonexistent tests createGzipAwareScanner with non-existent file
func testCreateGzipAwareScannerNonexistent(t *testing.T) {
	nonexistentPath := filepath.Join(t.TempDir(), "nonexistent.log")

	scanner, cleanup, err := createGzipAwareScanner(nonexistentPath, 0)
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
	if scanner != nil {
		t.Error("Should not return scanner for non-existent file")
	}
	if cleanup != nil {
		cleanup() // Clean up if returned
	}
}

// testCreateGzipAwareScannerNonPositiveBuffer pins that a zero or negative
// maxLineSize keeps bufio's default buffer instead of failing.
func testCreateGzipAwareScannerNonPositiveBuffer(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.log")

	if err := os.WriteFile(testFile, []byte("test content"), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	for _, size := range []int{0, -1} {
		scanner, cleanup, err := createGzipAwareScanner(testFile, size)
		if err != nil {
			t.Fatalf("maxLineSize %d: unexpected error: %v", size, err)
		}
		if !scanner.Scan() || scanner.Text() != "test content" {
			t.Errorf("maxLineSize %d: scanned %q, want %q", size, scanner.Text(), "test content")
		}
		cleanup()
	}
}

// TestGzipFunctionsErrorHandling tests error handling in gzip detection and reading functions
func TestGzipFunctionsErrorHandling(t *testing.T) {
	t.Run("isGzipFile_nonexistent_file", testIsGzipFileNonexistent)
	t.Run("isGzipFile_directory_path", testIsGzipFileDirectory)
	t.Run("isGzipFile_empty_file", testIsGzipFileEmpty)
	t.Run("openGzipAwareReader_nonexistent_file", testOpenGzipAwareReaderNonexistent)
	t.Run("createGzipAwareScanner_nonexistent_file", testCreateGzipAwareScannerNonexistent)
	t.Run("createGzipAwareScanner_non_positive_buffer", testCreateGzipAwareScannerNonPositiveBuffer)
}

// TestGzipFunctionsFunctionality tests the core functionality of gzip functions
func TestGzipFunctionsFunctionality(t *testing.T) {
	t.Run("isGzipFile_extension_detection", testGzipExtensionDetection)
	t.Run("isGzipFile_magic_bytes_detection", testGzipMagicBytesDetection)
	t.Run("openGzipAwareReader_plain_file", testGzipReaderPlainFile)
	t.Run("openGzipAwareReader_gzip_file", testGzipReaderGzipFile)
	t.Run("createGzipAwareScanner_functionality", testGzipScannerFunctionality)
}

func testGzipExtensionDetection(t *testing.T) {
	tempDir := t.TempDir()
	gzFile := filepath.Join(tempDir, "test.log.gz")

	// Create empty .gz file (extension should be enough for detection)
	err := os.WriteFile(gzFile, []byte{}, 0600)
	if err != nil {
		t.Fatalf("Failed to create .gz file: %v", err)
	}

	isGzip, err := isGzipFile(gzFile)
	if err != nil {
		t.Errorf("Should not error on .gz file: %v", err)
	}
	if !isGzip {
		t.Error(".gz extension should be detected as gzip")
	}
}

func testGzipMagicBytesDetection(t *testing.T) {
	tempDir := t.TempDir()
	gzFile := filepath.Join(tempDir, "test.log") // No .gz extension

	// Create file with gzip magic bytes
	magicBytes := []byte{0x1f, 0x8b, 0x08, 0x00} // gzip magic + compression method
	err := os.WriteFile(gzFile, magicBytes, 0600)
	if err != nil {
		t.Fatalf("Failed to create file with magic bytes: %v", err)
	}

	isGzip, err := isGzipFile(gzFile)
	if err != nil {
		t.Errorf("Should not error on file with magic bytes: %v", err)
	}
	if !isGzip {
		t.Error("Gzip magic bytes should be detected")
	}
}

func testGzipReaderPlainFile(t *testing.T) {
	tempDir := t.TempDir()
	plainFile := filepath.Join(tempDir, "plain.log")
	content := "test log line 1\ntest log line 2\n"

	err := os.WriteFile(plainFile, []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to create plain file: %v", err)
	}

	reader, err := openGzipAwareReader(plainFile)
	if err != nil {
		t.Fatalf("Should not error on plain file: %v", err)
	}
	defer func() { _ = reader.Close() }()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Errorf("Failed to read from plain file: %v", err)
	}
	if string(data) != content {
		t.Errorf("Content mismatch: expected %q, got %q", content, string(data))
	}
}

func testGzipReaderGzipFile(t *testing.T) {
	tempDir := t.TempDir()
	gzFile := filepath.Join(tempDir, "compressed.log.gz")
	originalContent := "compressed log line 1\ncompressed log line 2\n"

	// Create gzip file in temp directory
	f, err := os.Create(gzFile) // #nosec G304 - Test file in temp directory
	if err != nil {
		t.Fatalf("Failed to create gzip file: %v", err)
	}

	gzWriter := gzip.NewWriter(f)
	_, err = gzWriter.Write([]byte(originalContent))
	if err != nil {
		t.Fatalf("Failed to write to gzip file: %v", err)
	}
	_ = gzWriter.Close()
	_ = f.Close()

	reader, err := openGzipAwareReader(gzFile)
	if err != nil {
		t.Fatalf("Should not error on gzip file: %v", err)
	}
	defer func() { _ = reader.Close() }()

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Errorf("Failed to read from gzip file: %v", err)
	}
	if string(data) != originalContent {
		t.Errorf("Content mismatch: expected %q, got %q", originalContent, string(data))
	}
}

func testGzipScannerFunctionality(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.log")
	lines := []string{"line 1", "line 2", "line 3"}
	content := strings.Join(lines, "\n")

	err := os.WriteFile(testFile, []byte(content), 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	scanner, cleanup, err := createGzipAwareScanner(testFile, 0)
	if err != nil {
		t.Fatalf("Should not error on valid file: %v", err)
	}
	defer cleanup()

	var scannedLines []string
	for scanner.Scan() {
		scannedLines = append(scannedLines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		t.Errorf("Scanner error: %v", err)
	}

	if len(scannedLines) != len(lines) {
		t.Fatalf("Line count mismatch: expected %d, got %d", len(lines), len(scannedLines))
	}

	for i, expected := range lines {
		if scannedLines[i] != expected {
			t.Errorf("Line %d mismatch: expected %q, got %q", i, expected, scannedLines[i])
		}
	}
}
