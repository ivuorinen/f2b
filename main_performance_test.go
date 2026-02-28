package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ivuorinen/f2b/fail2ban"
)

// BenchmarkE2E_MainAPIs benchmarks the main API functions end-to-end
func BenchmarkE2E_MainAPIs(b *testing.B) {
	// Setup test environment
	tempDir := b.TempDir()
	fail2ban.SetLogDir(tempDir)

	// Create test log file with realistic content
	testLogFile := filepath.Join(tempDir, "fail2ban.log")
	testContent := []byte(`2024-01-01 12:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100
2024-01-01 12:01:00,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.101
2024-01-01 12:02:00,789 fail2ban.actions [1234]: NOTICE [nginx] Ban 192.168.1.102
2024-01-01 12:03:00,012 fail2ban.actions [1234]: NOTICE [sshd] Unban 192.168.1.100
`)
	err := os.WriteFile(testLogFile, testContent, 0600)
	if err != nil {
		b.Fatalf("Failed to create test log file: %v", err)
	}

	// Setup mock client
	client := setupBenchmarkClient(b)

	b.Run("GetLogLines", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := fail2ban.GetLogLines(context.Background(), "sshd", "192.168.1.100")
			if err != nil {
				b.Fatalf("GetLogLines failed: %v", err)
			}
		}
	})

	b.Run("GetLogLinesWithLimit", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := fail2ban.GetLogLinesWithLimit(context.Background(), "sshd", "192.168.1.100", 100)
			if err != nil {
				b.Fatalf("GetLogLinesWithLimit failed: %v", err)
			}
		}
	})

	b.Run("UltraOptimized", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := fail2ban.GetLogLinesUltraOptimized("sshd", "192.168.1.100", 100)
			if err != nil {
				b.Fatalf("GetLogLinesUltraOptimized failed: %v", err)
			}
		}
	})

	b.Run("Client_GetBanRecords", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := client.GetBanRecords([]string{"sshd"})
			if err != nil {
				b.Fatalf("GetBanRecords failed: %v", err)
			}
		}
	})

	b.Run("Client_GetBanRecordsWithContext", func(b *testing.B) {
		ctx := context.Background()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := client.GetBanRecordsWithContext(ctx, []string{"sshd"})
			if err != nil {
				b.Fatalf("GetBanRecordsWithContext failed: %v", err)
			}
		}
	})
}

// BenchmarkMemoryAllocation_Critical benchmarks memory allocations in critical paths
func BenchmarkMemoryAllocation_Critical(b *testing.B) {
	tempDir := b.TempDir()
	fail2ban.SetLogDir(tempDir)

	// Create test log file with proper line structure
	testLogFile := filepath.Join(tempDir, "fail2ban.log")
	testLine := "2024-01-01 12:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100\n"

	// Create 1MB of realistic log data (about 10,000 lines)
	var testContent []byte
	for len(testContent) < 1024*1024 {
		testContent = append(testContent, testLine...)
	}
	err := os.WriteFile(testLogFile, testContent, 0600)
	if err != nil {
		b.Fatalf("Failed to create test log file: %v", err)
	}

	b.Run("LargeLogProcessing", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, err := fail2ban.GetLogLinesWithLimit(context.Background(), "all", "all", 1000)
			if err != nil {
				b.Fatalf("Large log processing failed: %v", err)
			}
		}
	})

	b.Run("StringPoolingEfficiency", func(b *testing.B) {
		processor := fail2ban.NewOptimizedLogProcessor()
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := processor.GetLogLinesOptimized("sshd", "192.168.1.100", 100)
			if err != nil {
				b.Fatalf("String pooling test failed: %v", err)
			}
		}
	})
}

// BenchmarkConcurrentPerformance benchmarks performance under concurrent load
func BenchmarkConcurrentPerformance(b *testing.B) {
	tempDir := b.TempDir()
	fail2ban.SetLogDir(tempDir)

	// Create test log file
	testLogFile := filepath.Join(tempDir, "fail2ban.log")
	testContent := []byte(`2024-01-01 12:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100
2024-01-01 12:01:00,456 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.101
`)
	err := os.WriteFile(testLogFile, testContent, 0600)
	if err != nil {
		b.Fatalf("Failed to create test log file: %v", err)
	}

	b.Run("ConcurrentLogReading", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := fail2ban.GetLogLinesUltraOptimized("sshd", "all", 50)
				if err != nil {
					b.Fatalf("Concurrent log reading failed: %v", err)
				}
			}
		})
	})

	b.Run("ConcurrentCacheAccess", func(b *testing.B) {
		processor := fail2ban.NewOptimizedLogProcessor()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				// Mix cache operations
				processor.GetCacheStats()
				if pb.Next() {
					_, _ = processor.GetLogLinesOptimized("all", "all", 10)
				}
			}
		})
	})
}

// BenchmarkGlobalStateAccess benchmarks thread-safe global state access
func BenchmarkGlobalStateAccess(b *testing.B) {
	originalLogDir := fail2ban.GetLogDir()
	defer fail2ban.SetLogDir(originalLogDir)

	b.Run("LogDirAccess", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if pb.Next() {
					// 50% reads
					fail2ban.GetLogDir()
				} else {
					// 50% writes
					fail2ban.SetLogDir("/tmp/test-" + string(rune(b.N))) //nolint:gosec // test code, intentional
				}
			}
		})
	})
}

// setupBenchmarkClient creates a properly configured client for benchmarking
func setupBenchmarkClient(b *testing.B) *fail2ban.RealClient {
	b.Helper()

	// Setup mock environment
	_, cleanup := fail2ban.SetupMockEnvironment(b)
	b.Cleanup(cleanup)

	// Get the mock runner and add additional responses
	mockRunner := fail2ban.GetRunner().(*fail2ban.MockRunner)
	mockRunner.SetResponse("fail2ban-client -V", []byte("fail2ban-client v1.0.0"))
	mockRunner.SetResponse("fail2ban-client status", []byte("Status: [sshd] Jail list: sshd"))
	mockRunner.SetResponse(
		"sudo fail2ban-client get sshd banip --with-time",
		[]byte(`192.168.1.100	2024-01-01 12:00:00
192.168.1.101	2024-01-01 12:01:00`),
	)

	client, err := fail2ban.NewClient("", "")
	if err != nil {
		b.Fatalf("Failed to create test client: %v", err)
	}

	return client
}

// MemoryProfile runs a memory profiling session
func MemoryProfile(b *testing.B) {
	b.Helper()
	tempDir := b.TempDir()
	fail2ban.SetLogDir(tempDir)

	// Create large test log file (10MB)
	testLogFile := filepath.Join(tempDir, "fail2ban.log")
	testLine := "2024-01-01 12:00:00,123 fail2ban.actions [1234]: NOTICE [sshd] Ban 192.168.1.100\n"

	// Create 10MB of realistic log data (about 100,000 lines)
	var largeContent []byte
	for len(largeContent) < 10*1024*1024 {
		largeContent = append(largeContent, testLine...)
	}

	err := os.WriteFile(testLogFile, largeContent, 0600)
	if err != nil {
		b.Fatalf("Failed to create large test file: %v", err)
	}

	b.Run("LargeFileMemoryUsage", func(b *testing.B) {
		b.ReportAllocs()
		start := time.Now()

		for i := 0; i < b.N; i++ {
			_, err := fail2ban.GetLogLinesUltraOptimized("all", "all", 10000)
			if err != nil {
				b.Fatalf("Large file processing failed: %v", err)
			}
		}

		duration := time.Since(start)
		b.Logf("Processing 10MB file took %v", duration)
	})
}
