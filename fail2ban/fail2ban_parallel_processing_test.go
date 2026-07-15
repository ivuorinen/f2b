package fail2ban

import (
	"context"
	"errors"
	"testing"
)

func TestProcessJailsParallel(t *testing.T) {
	jails := []string{"sshd", "apache", "nginx"}
	ctx := context.Background()

	// Mock work function that returns records for each jail
	workFunc := func(_ context.Context, jail string) ([]BanRecord, error) {
		return []BanRecord{
			{Jail: jail, IP: "192.168.1.100"},
			{Jail: jail, IP: "192.168.1.101"},
		}, nil
	}

	records, err := ProcessJailsParallel(ctx, jails, workFunc)
	if err != nil {
		t.Fatalf("ProcessJailsParallel failed: %v", err)
	}

	// Should have 6 records (2 per jail * 3 jails)
	if len(records) != 6 {
		t.Fatalf("Expected 6 records, got %d", len(records))
	}

	// Check that all jails are represented
	jailCounts := make(map[string]int)
	for _, record := range records {
		jailCounts[record.Jail]++
	}

	for _, jail := range jails {
		if jailCounts[jail] != 2 {
			t.Errorf("Jail %s should have 2 records, got %d", jail, jailCounts[jail])
		}
	}
}

func TestProcessJailsParallelSingleJail(t *testing.T) {
	jails := []string{"sshd"}
	ctx := context.Background()

	workFunc := func(_ context.Context, jail string) ([]BanRecord, error) {
		return []BanRecord{{Jail: jail, IP: "192.168.1.100"}}, nil
	}

	records, err := ProcessJailsParallel(ctx, jails, workFunc)
	if err != nil {
		t.Fatalf("ProcessJailsParallel failed: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(records))
	}

	if records[0].Jail != "sshd" {
		t.Errorf("Expected jail 'sshd', got '%s'", records[0].Jail)
	}
}

func TestProcessJailsParallelWithErrors(t *testing.T) {
	jails := []string{"sshd", "apache", "nginx"}
	ctx := context.Background()

	workFunc := func(_ context.Context, jail string) ([]BanRecord, error) {
		if jail == "apache" {
			return nil, errors.New("apache error")
		}
		return []BanRecord{{Jail: jail, IP: "192.168.1.100"}}, nil
	}

	records, err := ProcessJailsParallel(ctx, jails, workFunc)
	if err != nil {
		t.Fatalf("ProcessJailsParallel failed: %v", err)
	}

	// A partial failure is a valid result: the two succeeding jails' records
	// come back and the apache error is logged, not returned.
	if len(records) != 2 {
		t.Fatalf("Expected 2 records, got %d", len(records))
	}

	for _, record := range records {
		if record.Jail == "apache" {
			t.Error("Apache records should be excluded due to error")
		}
	}
}

func TestProcessJailsParallelAllFail(t *testing.T) {
	jails := []string{"sshd", "apache"}
	ctx := context.Background()
	sentinel := errors.New("jail unreachable")

	workFunc := func(_ context.Context, _ string) ([]BanRecord, error) {
		return nil, sentinel
	}

	// When every jail fails, the joined error is returned rather than an empty
	// slice with nil error (which would read as "no bans").
	records, err := ProcessJailsParallel(ctx, jails, workFunc)
	if err == nil {
		t.Fatal("expected an error when all jails fail, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected joined error to wrap the per-jail error, got %v", err)
	}
	if records != nil {
		t.Errorf("expected nil records when all jails fail, got %v", records)
	}
}

func TestProcessJailsParallelCancellation(t *testing.T) {
	jails := []string{"sshd", "apache", "nginx"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before processing starts

	workFunc := func(workCtx context.Context, _ string) ([]BanRecord, error) {
		return nil, workCtx.Err()
	}

	// A canceled run must surface the context error, never mask it as an empty
	// successful result (a real past regression).
	records, err := ProcessJailsParallel(ctx, jails, workFunc)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("ProcessJailsParallel err = %v, want context.Canceled", err)
	}
	if records != nil {
		t.Errorf("expected nil records on cancellation, got %v", records)
	}
}
