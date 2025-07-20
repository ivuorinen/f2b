package fail2ban

import (
	"context"
	"errors"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestWorkerPool(t *testing.T) {
	pool := NewWorkerPool[int, int](2)

	// Test simple processing
	items := []int{1, 2, 3, 4, 5}
	ctx := context.Background()

	results, err := pool.Process(ctx, items, func(_ context.Context, item int) (int, error) {
		return item * 2, nil
	})

	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if len(results) != len(items) {
		t.Fatalf("Expected %d results, got %d", len(items), len(results))
	}

	// Check results are in correct order
	for i, result := range results {
		if result.Error != nil {
			t.Errorf("Result %d had error: %v", i, result.Error)
		}
		expected := items[i] * 2
		if result.Value != expected {
			t.Errorf("Result %d: got %d, want %d", i, result.Value, expected)
		}
		if result.Index != i {
			t.Errorf("Result %d: wrong index %d", i, result.Index)
		}
	}
}

func TestWorkerPoolWithErrors(t *testing.T) {
	pool := NewWorkerPool[int, int](2)
	items := []int{1, 2, 3, 4, 5}
	ctx := context.Background()

	results, err := pool.Process(ctx, items, func(_ context.Context, item int) (int, error) {
		if item == 3 {
			return 0, errors.New("error for item 3")
		}
		return item * 2, nil
	})

	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if len(results) != len(items) {
		t.Fatalf("Expected %d results, got %d", len(items), len(results))
	}

	// Check that item 3 has an error, others don't
	for i, result := range results {
		if items[i] == 3 {
			if result.Error == nil {
				t.Errorf("Result %d should have error", i)
			}
		} else {
			if result.Error != nil {
				t.Errorf("Result %d should not have error: %v", i, result.Error)
			}
		}
	}
}

func TestWorkerPoolCancellation(t *testing.T) {
	pool := NewWorkerPool[int, int](3) // Multiple workers for better concurrency
	items := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	ctx, cancel := context.WithCancel(context.Background())

	// Create a channel to coordinate cancellation timing
	workStarted := make(chan struct{})
	var startOnce sync.Once

	// Cancel after first work item starts, with enough delay for multiple items to start
	go func() {
		<-workStarted                     // Wait for first work item to start
		time.Sleep(10 * time.Millisecond) // Allow multiple work items to start
		cancel()
	}()

	results, err := pool.Process(ctx, items, func(workCtx context.Context, item int) (int, error) {
		// Signal that work has started (only once)
		startOnce.Do(func() {
			close(workStarted)
		})

		// Simulate longer work that's more likely to be canceled
		select {
		case <-time.After(50 * time.Millisecond): // Longer work duration
			return item * 2, nil
		case <-workCtx.Done():
			return 0, workCtx.Err()
		}
	})

	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	// Some results should be canceled
	cancelledCount := 0
	completedCount := 0
	for _, result := range results {
		if errors.Is(result.Error, context.Canceled) {
			cancelledCount++
		} else if result.Error == nil {
			completedCount++
		}
	}

	// Verify that we have both completed and canceled results
	if cancelledCount == 0 {
		t.Errorf("Expected some results to be canceled, but got 0 canceled, %d completed", completedCount)
	}

	if completedCount == 0 {
		t.Error("Expected some results to complete successfully")
	}

	t.Logf("Test results: %d completed, %d canceled", completedCount, cancelledCount)
}

func TestWorkerPoolEmpty(t *testing.T) {
	pool := NewWorkerPool[int, int](2)
	var items []int
	ctx := context.Background()

	results, err := pool.Process(ctx, items, func(_ context.Context, item int) (int, error) {
		return item * 2, nil
	})

	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if len(results) != 0 {
		t.Fatalf("Expected 0 results, got %d", len(results))
	}
}

func TestWorkerPoolErrorAggregation(t *testing.T) {
	pool := NewWorkerPool[int, int](2)
	items := []int{1, 2, 3, 4, 5}
	ctx := context.Background()

	values, errors := pool.ProcessWithErrorAggregation(ctx, items, func(_ context.Context, item int) (int, error) {
		if item%2 == 0 {
			return 0, errors.New("even number error")
		}
		return item * 2, nil
	})

	// Should have 3 values (1, 3, 5) and 2 errors (2, 4)
	if len(values) != 3 {
		t.Errorf("Expected 3 values, got %d", len(values))
	}

	if len(errors) != 2 {
		t.Errorf("Expected 2 errors, got %d", len(errors))
	}

	// Values should be processed odd numbers
	expectedValues := []int{2, 6, 10} // 1*2, 3*2, 5*2
	sort.Ints(values)
	for i, v := range values {
		if v != expectedValues[i] {
			t.Errorf("Value %d: got %d, want %d", i, v, expectedValues[i])
		}
	}
}

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

	// Should have 2 records (errors are ignored)
	if len(records) != 2 {
		t.Fatalf("Expected 2 records, got %d", len(records))
	}

	// Check that apache is not present
	for _, record := range records {
		if record.Jail == "apache" {
			t.Error("Apache records should be excluded due to error")
		}
	}
}

func TestWorkerPoolConcurrency(t *testing.T) {
	pool := NewWorkerPool[int, int](runtime.NumCPU())
	items := make([]int, 100)
	for i := range items {
		items[i] = i
	}

	ctx := context.Background()
	var processedCount int64
	var mu sync.Mutex

	results, err := pool.Process(ctx, items, func(_ context.Context, item int) (int, error) {
		// Simulate work and track concurrent processing
		mu.Lock()
		processedCount++
		mu.Unlock()

		time.Sleep(time.Millisecond) // Small delay to allow concurrency
		return item * 2, nil
	})

	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if len(results) != len(items) {
		t.Fatalf("Expected %d results, got %d", len(items), len(results))
	}

	// Verify all items were processed
	mu.Lock()
	finalCount := processedCount
	mu.Unlock()

	if finalCount != int64(len(items)) {
		t.Errorf("Expected %d items processed, got %d", len(items), finalCount)
	}
}

func BenchmarkWorkerPoolSerial(b *testing.B) {
	items := make([]int, 100)
	for i := range items {
		items[i] = i
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool := NewWorkerPool[int, int](1) // Single worker = serial
		_, err := pool.Process(ctx, items, func(_ context.Context, item int) (int, error) {
			return item * 2, nil
		})
		if err != nil {
			b.Fatalf("Process failed: %v", err)
		}
	}
}

func BenchmarkWorkerPoolParallel(b *testing.B) {
	items := make([]int, 100)
	for i := range items {
		items[i] = i
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool := NewWorkerPool[int, int](runtime.NumCPU()) // Parallel
		_, err := pool.Process(ctx, items, func(_ context.Context, item int) (int, error) {
			return item * 2, nil
		})
		if err != nil {
			b.Fatalf("Process failed: %v", err)
		}
	}
}
