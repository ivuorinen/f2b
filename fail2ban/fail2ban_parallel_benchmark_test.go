package fail2ban

import (
	"context"
	"testing"
	"time"
)

// BenchmarkGetBanRecordsSequential simulates the original sequential approach
func BenchmarkGetBanRecordsSequential(b *testing.B) {
	jails := []string{"sshd", "apache", "nginx", "postfix", "dovecot"}

	// Simulate network delay for fail2ban-client calls
	workFunc := func(jail string) []BanRecord {
		time.Sleep(10 * time.Millisecond) // Simulate 10ms network call
		return []BanRecord{
			{Jail: jail, IP: "192.168.1.100"},
			{Jail: jail, IP: "192.168.1.101"},
		}
	}

	b.ResetTimer()
	for b.Loop() {
		for _, jail := range jails {
			_ = workFunc(jail) // Simulate work without storing results
		}
	}
}

// BenchmarkGetBanRecordsParallel simulates the new parallel approach
func BenchmarkGetBanRecordsParallel(b *testing.B) {
	jails := []string{"sshd", "apache", "nginx", "postfix", "dovecot"}
	ctx := context.Background()

	// Simulate network delay for fail2ban-client calls
	workFunc := func(_ context.Context, jail string) ([]BanRecord, error) {
		time.Sleep(10 * time.Millisecond) // Simulate 10ms network call
		return []BanRecord{
			{Jail: jail, IP: "192.168.1.100"},
			{Jail: jail, IP: "192.168.1.101"},
		}, nil
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = ProcessJailsParallel(ctx, jails, workFunc)
	}
}

// BenchmarkSingleJailOperation tests overhead for single jail operations
func BenchmarkSingleJailOperation(b *testing.B) {
	jail := "sshd"
	ctx := context.Background()

	workFunc := func(_ context.Context, jail string) ([]BanRecord, error) {
		return []BanRecord{{Jail: jail, IP: "192.168.1.100"}}, nil
	}

	b.Run("sequential", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = workFunc(ctx, jail)
		}
	})

	b.Run("parallel", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = ProcessJailsParallel(ctx, []string{jail}, workFunc)
		}
	})
}
