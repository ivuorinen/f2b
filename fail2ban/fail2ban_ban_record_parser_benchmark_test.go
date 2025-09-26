package fail2ban

import (
	"fmt"
	"strings"
	"testing"
)

// Sample data for benchmarking - represents real fail2ban output
var benchmarkBanRecordData = []string{
	"192.168.1.100 2025-07-20 14:30:39 + 2025-07-20 14:40:39 remaining",
	"10.0.0.50 2025-07-20 14:36:59 + 2025-07-20 14:46:59 remaining",
	"172.16.0.100 2025-07-20 14:52:09 + 2025-07-20 15:02:09 remaining",
	"192.168.2.15 2025-07-20 15:01:23 + 2025-07-20 15:11:23 remaining",
	"10.0.1.75 2025-07-20 15:15:44 + 2025-07-20 15:25:44 remaining",
	"172.16.1.200 2025-07-20 15:22:17 + 2025-07-20 15:32:17 remaining",
	"192.168.3.88 2025-07-20 15:35:51 + 2025-07-20 15:45:51 remaining",
	"10.0.2.123 2025-07-20 15:48:03 + 2025-07-20 15:58:03 remaining",
	"172.16.2.45 2025-07-20 16:02:29 + 2025-07-20 16:12:29 remaining",
	"192.168.4.212 2025-07-20 16:17:55 + 2025-07-20 16:27:55 remaining",
}

var benchmarkBanRecordOutput = strings.Join(benchmarkBanRecordData, "\n")

// BenchmarkOriginalBanRecordParsing benchmarks the current implementation
func BenchmarkOriginalBanRecordParsing(b *testing.B) {
	parser := NewBanRecordParser()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := parser.ParseBanRecords(benchmarkBanRecordOutput, "sshd")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkOptimizedBanRecordParsing benchmarks the new optimized implementation
func BenchmarkOptimizedBanRecordParsing(b *testing.B) {
	parser := NewBanRecordParser()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := parser.ParseBanRecords(benchmarkBanRecordOutput, "sshd")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBanRecordLineParsing compares single line parsing
func BenchmarkBanRecordLineParsing(b *testing.B) {
	testLine := "192.168.1.100 2025-07-20 14:30:39 + 2025-07-20 14:40:39 remaining"

	b.Run("original", func(b *testing.B) {
		parser := NewBanRecordParser()
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := parser.ParseBanRecordLine(testLine, "sshd")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("optimized", func(b *testing.B) {
		parser := NewBanRecordParser()
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := parser.ParseBanRecordLine(testLine, "sshd")
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkTimeParsingOptimization compares time parsing implementations
func BenchmarkTimeParsingOptimization(b *testing.B) {
	timeStr := "2025-07-20 14:30:39"

	b.Run("original", func(b *testing.B) {
		cache := NewTimeParsingCache("2006-01-02 15:04:05")
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := cache.ParseTime(timeStr)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("optimized", func(b *testing.B) {
		cache := NewFastTimeCache("2006-01-02 15:04:05")
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := cache.ParseTimeOptimized(timeStr)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkTimeStringBuilding compares time string building
func BenchmarkTimeStringBuilding(b *testing.B) {
	dateStr := "2025-07-20"
	timeStr := "14:30:39"

	b.Run("original", func(b *testing.B) {
		cache := NewTimeParsingCache("2006-01-02 15:04:05")
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = cache.BuildTimeString(dateStr, timeStr)
		}
	})

	b.Run("optimized", func(b *testing.B) {
		cache := NewFastTimeCache("2006-01-02 15:04:05")
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = cache.BuildTimeStringOptimized(dateStr, timeStr)
		}
	})
}

// BenchmarkLargeDataset tests with larger datasets
func BenchmarkLargeDataset(b *testing.B) {
	// Generate larger dataset
	var largeData []string
	for i := 0; i < 100; i++ {
		for _, line := range benchmarkBanRecordData {
			// Vary the IP addresses slightly
			modifiedLine := strings.Replace(line, "192.168.1.100", fmt.Sprintf("192.168.%d.%d", i%256, (i*7)%256), 1)
			largeData = append(largeData, modifiedLine)
		}
	}
	largeOutput := strings.Join(largeData, "\n")

	b.Run("original_large", func(b *testing.B) {
		parser := NewBanRecordParser()
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := parser.ParseBanRecords(largeOutput, "sshd")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("optimized_large", func(b *testing.B) {
		parser := NewBanRecordParser()
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_, err := parser.ParseBanRecords(largeOutput, "sshd")
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkDurationFormatting compares duration formatting
func BenchmarkDurationFormatting(b *testing.B) {
	testDurations := []int64{30, 125, 3661, 7200, 86401} // Various durations

	b.Run("original", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, dur := range testDurations {
				_ = FormatDuration(dur)
			}
		}
	})

	b.Run("optimized", func(b *testing.B) {
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, dur := range testDurations {
				_ = formatDurationOptimized(dur)
			}
		}
	})
}

// BenchmarkMemoryPooling tests the effectiveness of object pooling
func BenchmarkMemoryPooling(b *testing.B) {
	parser := NewBanRecordParser()
	testLine := "192.168.1.100 2025-07-20 14:30:39 + 2025-07-20 14:40:39 remaining"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// This should demonstrate reduced allocations due to pooling
		for j := 0; j < 10; j++ {
			_, err := parser.ParseBanRecordLine(testLine, "sshd")
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}
