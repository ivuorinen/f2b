package fail2ban

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/ivuorinen/f2b/shared"
)

// safeCloseFile closes a file and logs any error.
// This helper consolidates the duplicate close-and-log pattern.
func safeCloseFile(f *os.File, path string) {
	if f == nil {
		return
	}
	if closeErr := f.Close(); closeErr != nil {
		getLogger().WithError(closeErr).
			WithField(shared.LogFieldFile, path).
			Warn("Failed to close file")
	}
}

// safeCloseReader closes a reader and logs any error.
// This helper consolidates the duplicate close-and-log pattern for io.ReadCloser.
func safeCloseReader(r io.ReadCloser, path string) {
	if r == nil {
		return
	}
	if closeErr := r.Close(); closeErr != nil {
		getLogger().WithError(closeErr).
			WithField(shared.LogFieldFile, path).
			Warn("Failed to close reader")
	}
}

// GzipDetector provides utilities for detecting and handling gzip-compressed files
type GzipDetector struct{}

// NewGzipDetector creates a new gzip detector instance
func NewGzipDetector() *GzipDetector {
	return &GzipDetector{}
}

// IsGzipFile checks if a file is gzip compressed by examining the file extension first,
// then falling back to magic byte detection for better performance
func (gd *GzipDetector) IsGzipFile(path string) (bool, error) {
	// Fast path: check file extension first
	if strings.HasSuffix(strings.ToLower(path), shared.GzipExtension) {
		return true, nil
	}

	// Fallback: check magic bytes for files without .gz extension
	return gd.hasGzipMagicBytes(path)
}

// hasGzipMagicBytes checks if a file has gzip magic bytes (0x1f, 0x8b)
func (gd *GzipDetector) hasGzipMagicBytes(path string) (bool, error) {
	// #nosec G304 - Path is validated by caller, this is a legitimate file operation
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer safeCloseFile(f, path)

	var magic [2]byte
	n, err := f.Read(magic[:])
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}

	// Check if we have gzip magic bytes (0x1f, 0x8b)
	if n < 2 {
		return false, nil
	}
	// #nosec G602 - Length check above guarantees slice has at least 2 elements
	return magic[0] == 0x1f && magic[1] == 0x8b, nil
}

// OpenGzipAwareReader opens a file and returns appropriate reader (gzip or regular)
func (gd *GzipDetector) OpenGzipAwareReader(path string) (io.ReadCloser, error) {
	// #nosec G304 - Path is validated by caller, this is a legitimate file operation
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	isGzip, err := gd.IsGzipFile(path)
	if err != nil {
		safeCloseFile(f, path)
		return nil, err
	}

	if isGzip {
		// For gzip files, we need to position at the beginning and create gzip reader
		_, err = f.Seek(0, io.SeekStart)
		if err != nil {
			safeCloseFile(f, path)
			return nil, err
		}

		gz, err := gzip.NewReader(f)
		if err != nil {
			safeCloseFile(f, path)
			return nil, err
		}

		// Return a composite closer that closes both gzip reader and file
		return &gzipFileReader{gz: gz, file: f}, nil
	}

	return f, nil
}

// CreateGzipAwareScanner creates a scanner for the file, handling gzip compression automatically
func (gd *GzipDetector) CreateGzipAwareScanner(path string) (*bufio.Scanner, func(), error) {
	return gd.CreateGzipAwareScannerWithBuffer(path, 0)
}

// CreateGzipAwareScannerWithBuffer creates a scanner with custom buffer size
func (gd *GzipDetector) CreateGzipAwareScannerWithBuffer(path string, maxLineSize int) (*bufio.Scanner, func(), error) {
	reader, err := gd.OpenGzipAwareReader(path)
	if err != nil {
		return nil, nil, err
	}

	scanner := bufio.NewScanner(reader)

	// Set buffer size limit if specified
	if maxLineSize > 0 {
		buf := make([]byte, 0, maxLineSize)
		scanner.Buffer(buf, maxLineSize)
	}

	cleanup := func() {
		safeCloseReader(reader, path)
	}

	return scanner, cleanup, nil
}

// gzipFileReader wraps both gzip.Reader and os.File to ensure both are closed
type gzipFileReader struct {
	gz   *gzip.Reader
	file *os.File
}

func (gfr *gzipFileReader) Read(p []byte) (n int, err error) {
	return gfr.gz.Read(p)
}

func (gfr *gzipFileReader) Close() error {
	// Close gzip reader first
	gzErr := gfr.gz.Close()
	// Then close file
	fileErr := gfr.file.Close()

	// Return the first error encountered
	if gzErr != nil {
		return gzErr
	}
	return fileErr
}

// Global detector instance for convenience
var defaultGzipDetector = NewGzipDetector()

// IsGzipFile checks if a file is gzip compressed using the default detector.
// SECURITY: The caller must validate and sanitize the path argument to prevent
// path traversal attacks and ensure the file is within allowed directories.
func IsGzipFile(path string) (bool, error) {
	return defaultGzipDetector.IsGzipFile(path)
}

// OpenGzipAwareReader opens a file with automatic gzip detection using the default detector.
// SECURITY: The caller must validate and sanitize the path argument to prevent
// path traversal attacks and ensure the file is within allowed directories.
func OpenGzipAwareReader(path string) (io.ReadCloser, error) {
	return defaultGzipDetector.OpenGzipAwareReader(path)
}

// CreateGzipAwareScanner creates a scanner with automatic gzip detection using the default detector.
// SECURITY: The caller must validate and sanitize the path argument to prevent
// path traversal attacks and ensure the file is within allowed directories.
func CreateGzipAwareScanner(path string) (*bufio.Scanner, func(), error) {
	return defaultGzipDetector.CreateGzipAwareScanner(path)
}

// CreateGzipAwareScannerWithBuffer creates a scanner with custom buffer size using the default detector.
// SECURITY: The caller must validate and sanitize the path argument to prevent
// path traversal attacks and ensure the file is within allowed directories.
func CreateGzipAwareScannerWithBuffer(path string, maxLineSize int) (*bufio.Scanner, func(), error) {
	return defaultGzipDetector.CreateGzipAwareScannerWithBuffer(path, maxLineSize)
}
