package fail2ban

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkLimitedLogRead benchmarks a limited, jail-filtered log read through
// the client entry point.
func BenchmarkLimitedLogRead(b *testing.B) {
	testLogFile := filepath.Join("testdata", "fail2ban_full.log")
	if _, err := os.Stat(testLogFile); os.IsNotExist(err) {
		b.Skip("Test log file not found:", testLogFile)
	}

	client := &RealClient{LogDir: setupBenchmarkLogDir(b, testLogFile)}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := client.GetLogLinesWithLimitContext(context.Background(), "sshd", "", 100)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// setupBenchmarkLogDir copies source into a temp dir as fail2ban.log and
// returns the dir.
func setupBenchmarkLogDir(b *testing.B, source string) string {
	b.Helper()
	data, err := os.ReadFile(source) // #nosec G304 // Reading a test file
	if err != nil {
		b.Fatalf("failed to read test log file: %v", err)
	}

	tempDir := b.TempDir()
	dest := filepath.Join(tempDir, "fail2ban.log")
	// #nosec G703 -- dest is constructed from b.TempDir() and a literal string, not user input
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		b.Fatalf("failed to create benchmark log file: %v", err)
	}
	return tempDir
}
