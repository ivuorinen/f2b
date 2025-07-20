package fail2ban

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGzipDetector(t *testing.T) {
	detector := NewGzipDetector()

	// Create temp directory for test files
	tempDir := t.TempDir()

	// Test regular file
	regularFile := filepath.Join(tempDir, "regular.log")
	err := os.WriteFile(regularFile, []byte("test log line\n"), 0600)
	if err != nil {
		t.Fatalf("Failed to create regular file: %v", err)
	}

	// Test gzip file
	gzipFile := filepath.Join(tempDir, "compressed.log.gz")
	// #nosec G304 - Test file path in temp directory, safe for testing
	f, err := os.Create(gzipFile)
	if err != nil {
		t.Fatalf("Failed to create gzip file: %v", err)
	}
	gz := gzip.NewWriter(f)
	_, err = gz.Write([]byte("compressed log line\n"))
	if err != nil {
		t.Fatalf("Failed to write gzip content: %v", err)
	}
	_ = gz.Close()
	_ = f.Close()

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

	// Create temp directory for test files
	tempDir := t.TempDir()

	// Test regular file
	regularFile := filepath.Join(tempDir, "regular.log")
	testContent := "test log line\nsecond line\n"
	err := os.WriteFile(regularFile, []byte(testContent), 0600)
	if err != nil {
		t.Fatalf("Failed to create regular file: %v", err)
	}

	// Test gzip file
	gzipFile := filepath.Join(tempDir, "compressed.log.gz")
	// #nosec G304 - Test file path in temp directory, safe for testing
	f, err := os.Create(gzipFile)
	if err != nil {
		t.Fatalf("Failed to create gzip file: %v", err)
	}
	gz := gzip.NewWriter(f)
	gzipContent := "compressed log line\ncompressed second line\n"
	_, err = gz.Write([]byte(gzipContent))
	if err != nil {
		t.Fatalf("Failed to write gzip content: %v", err)
	}
	_ = gz.Close()
	_ = f.Close()

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
			defer reader.Close()

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

	// Create temp directory for test files
	tempDir := t.TempDir()

	// Test regular file
	regularFile := filepath.Join(tempDir, "regular.log")
	testLines := []string{"line1", "line2", "line3"}
	testContent := strings.Join(testLines, "\n")
	err := os.WriteFile(regularFile, []byte(testContent), 0600)
	if err != nil {
		t.Fatalf("Failed to create regular file: %v", err)
	}

	// Test gzip file
	gzipFile := filepath.Join(tempDir, "compressed.log.gz")
	// #nosec G304 - Test file path in temp directory, safe for testing
	f, err := os.Create(gzipFile)
	if err != nil {
		t.Fatalf("Failed to create gzip file: %v", err)
	}
	gz := gzip.NewWriter(f)
	gzipLines := []string{"gzip1", "gzip2", "gzip3"}
	gzipContent := strings.Join(gzipLines, "\n")
	_, err = gz.Write([]byte(gzipContent))
	if err != nil {
		t.Fatalf("Failed to write gzip content: %v", err)
	}
	_ = gz.Close()
	_ = f.Close()

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
			scanner, cleanup, err := detector.CreateGzipAwareScanner(tt.file)
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

			if len(lines) != len(tt.expectedLines) {
				t.Fatalf("Line count = %d, want %d", len(lines), len(tt.expectedLines))
			}

			for i, line := range lines {
				if line != tt.expectedLines[i] {
					t.Errorf("Line %d = %q, want %q", i, line, tt.expectedLines[i])
				}
			}
		})
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
	defer reader.Close()

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

	// #nosec G304 - Test file path in temp directory, safe for testing
	f, err := os.Create(gzipFile)
	if err != nil {
		t.Fatalf("Failed to create gzip file: %v", err)
	}

	gz := gzip.NewWriter(f)
	_, err = gz.Write([]byte("test content"))
	if err != nil {
		t.Fatalf("Failed to write gzip content: %v", err)
	}
	_ = gz.Close()
	_ = f.Close()

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
	tempDir := b.TempDir()
	detector := NewGzipDetector()

	// Create test files
	regularFile := filepath.Join(tempDir, "regular.log")
	gzipFile := filepath.Join(tempDir, "compressed.log.gz")

	_ = os.WriteFile(regularFile, []byte("test content"), 0600)

	// #nosec G304 - Test file path in temp directory, safe for testing
	f, _ := os.Create(gzipFile)
	gz := gzip.NewWriter(f)
	_, _ = gz.Write([]byte("compressed content"))
	_ = gz.Close()
	_ = f.Close()

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
