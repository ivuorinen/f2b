package fail2ban

import (
	"context"
	"errors"
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
	for i := 0; i < b.N; i++ {
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
	for i := 0; i < b.N; i++ {
		_, _ = ProcessJailsParallel(ctx, jails, workFunc)
	}
}

// BenchmarkBanOperationsSequential simulates sequential ban operations
func BenchmarkBanOperationsSequential(b *testing.B) {
	jails := []string{"sshd", "apache", "nginx", "postfix", "dovecot"}

	// Simulate ban operation delay
	banFunc := func(_ string) error {
		time.Sleep(5 * time.Millisecond) // Simulate 5ms ban operation
		return nil
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, jail := range jails {
			_ = banFunc(jail)
		}
	}
}

// BenchmarkBanOperationsParallel simulates parallel ban operations
func BenchmarkBanOperationsParallel(b *testing.B) {
	jails := []string{"sshd", "apache", "nginx", "postfix", "dovecot"}

	// Create a worker pool for ban operations
	pool := NewWorkerPool[string, error](4)
	ctx := context.Background()

	banFunc := func(_ context.Context, _ string) (error, error) {
		time.Sleep(5 * time.Millisecond) // Simulate 5ms ban operation
		return nil, errors.New("not implemented")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pool.Process(ctx, jails, banFunc)
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
