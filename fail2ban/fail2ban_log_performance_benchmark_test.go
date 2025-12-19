package fail2ban

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkOriginalLogParsing benchmarks the current log parsing implementation
func BenchmarkOriginalLogParsing(b *testing.B) {
	testLogFile := filepath.Join("testdata", "fail2ban_full.log")
	if _, err := os.Stat(testLogFile); os.IsNotExist(err) {
		b.Skip("Test log file not found:", testLogFile)
	}

	cleanup := setupBenchmarkLogEnvironment(b, testLogFile)
	defer cleanup()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := GetLogLinesWithLimit(context.Background(), "sshd", "", 100)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOptimizedLogParsing benchmarks the simplified optimized entrypoint
func BenchmarkOptimizedLogParsing(b *testing.B) {
	testLogFile := filepath.Join("testdata", "fail2ban_full.log")
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

func setupBenchmarkLogEnvironment(b *testing.B, source string) func() {
	b.Helper()
	data, err := os.ReadFile(source) // #nosec G304 // Reading a test file
	if err != nil {
		b.Fatalf("failed to read test log file: %v", err)
	}

	tempDir := b.TempDir()
	dest := filepath.Join(tempDir, "fail2ban.log")
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		b.Fatalf("failed to create benchmark log file: %v", err)
	}

	origDir := GetLogDir()
	SetLogDir(tempDir)

	return func() {
		SetLogDir(origDir)
	}
}
