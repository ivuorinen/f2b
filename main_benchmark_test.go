package main

import (
	"testing"
)

// BenchmarkArgumentParsing benchmarks the argument parsing logic
func BenchmarkArgumentParsing(b *testing.B) {
	testArgs := [][]string{
		{"f2b", "version"},
		{"f2b", "service", "status"},
		{"f2b", "test-filter", "sshd"},
		{"f2b", "completion", "bash"},
		{"f2b", "help"},
		{"f2b", "list-jails"},
		{"f2b", "ban", "192.168.1.100"},
		{"f2b", "status", "all"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, args := range testArgs {
			skip := shouldSkipClientInit(args)
			_ = skip // Use the result to prevent optimization
		}
	}
}

// BenchmarkMainLogic benchmarks the main function's decision logic
func BenchmarkMainLogic(b *testing.B) {
	testArgs := [][]string{
		{"f2b", "version"},
		{"f2b", "service", "status"},
		{"f2b", "ban", "192.168.1.100"},
		{"f2b", "list-jails"},
		{"f2b", "completion", "bash"},
		{"f2b", "help"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, args := range testArgs {
			// Simulate main function logic
			skip := shouldSkipClientInit(args)

			// Simulate config building
			config := struct {
				LogDir    string
				FilterDir string
				Format    string
			}{
				LogDir:    "/var/log",
				FilterDir: "/etc/fail2ban/filter.d",
				Format:    "plain",
			}

			_ = skip
			_ = config
		}
	}
}
