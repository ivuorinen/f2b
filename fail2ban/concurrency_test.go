package fail2ban

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestRunnerConcurrentAccess tests that concurrent access to the runner
// is safe and doesn't cause race conditions.
func TestRunnerConcurrentAccess(t *testing.T) {
	original := GetRunner()
	defer SetRunner(original)

	const numGoroutines = 100
	const numOperations = 50

	var wg sync.WaitGroup

	// Test concurrent SetRunner/GetRunner operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				// Alternate between different mock runners
				if (id+j)%2 == 0 {
					mockRunner := NewMockRunner()
					mockRunner.SetResponse("test", []byte("response"))
					SetRunner(mockRunner)
				} else {
					SetRunner(&OSRunner{})
				}

				// Get runner and verify it's not nil
				runner := GetRunner()
				if runner == nil {
					t.Errorf("GetRunner() returned nil")
					return
				}

				// Force small delay to increase chances of race condition
				runtime.Gosched()
			}
		}(i)
	}

	wg.Wait()
}

// TestRunnerCombinedOutputConcurrency tests that concurrent calls to
// RunnerCombinedOutput are safe.
func TestRunnerCombinedOutputConcurrency(t *testing.T) {
	original := GetRunner()
	defer SetRunner(original)

	mockRunner := NewMockRunner()
	mockRunner.SetResponse("echo test", []byte("test output"))
	SetRunner(mockRunner)

	const numGoroutines = 50
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			output, err := RunnerCombinedOutput("echo", "test")
			if err != nil {
				t.Errorf("RunnerCombinedOutput failed: %v", err)
				return
			}

			if string(output) != "test output" {
				t.Errorf("Expected 'test output', got '%s'", string(output))
			}
		}()
	}

	wg.Wait()
}

// TestRunnerCombinedOutputWithSudoConcurrency tests concurrent calls to
// RunnerCombinedOutputWithSudo.
func TestRunnerCombinedOutputWithSudoConcurrency(t *testing.T) {
	original := GetRunner()
	defer SetRunner(original)

	originalChecker := GetSudoChecker()
	defer SetSudoChecker(originalChecker)

	mockRunner := NewMockRunner()
	mockRunner.SetResponse("fail2ban-client status", []byte("status output"))
	SetRunner(mockRunner)

	// Set up mock sudo checker as root to avoid sudo prefix
	mockChecker := NewMockSudoChecker(true, true, true)
	SetSudoChecker(mockChecker)

	const numGoroutines = 50
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			output, err := RunnerCombinedOutputWithSudo("fail2ban-client", "status")
			if err != nil {
				t.Errorf("RunnerCombinedOutputWithSudo failed: %v", err)
				return
			}

			if string(output) != "status output" {
				t.Errorf("Expected 'status output', got '%s'", string(output))
			}
		}()
	}

	wg.Wait()
}

// TestMixedConcurrentOperations tests mixed concurrent operations including
// setting runners and executing commands.
func TestMixedConcurrentOperations(t *testing.T) {
	original := GetRunner()
	defer SetRunner(original)

	const numGoroutines = 30
	var wg sync.WaitGroup

	// Group 1: Set runners
	for i := 0; i < numGoroutines/3; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < 20; j++ {
				mockRunner := NewMockRunner()
				mockRunner.SetResponse("test", []byte("response"))
				mockRunner.SetResponse("echo test", []byte("response"))
				mockRunner.SetResponse("fail2ban-client status", []byte("response"))
				SetRunner(mockRunner)
				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	// Group 2: Execute commands
	for i := 0; i < numGoroutines/3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for j := 0; j < 20; j++ {
				_, _ = RunnerCombinedOutput("echo", "test")
				time.Sleep(time.Microsecond)
			}
		}()
	}

	// Group 3: Execute sudo commands
	for i := 0; i < numGoroutines/3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for j := 0; j < 20; j++ {
				_, _ = RunnerCombinedOutputWithSudo("test", "arg")
				time.Sleep(time.Microsecond)
			}
		}()
	}

	wg.Wait()
}

// TestRunnerManagerLockOrdering verifies there are no deadlocks in the
// runner manager's lock ordering.
func TestRunnerManagerLockOrdering(t *testing.T) {
	original := GetRunner()
	defer SetRunner(original)

	// This test specifically looks for deadlocks by creating scenarios
	// where multiple goroutines could potentially deadlock if locks
	// are not acquired/released properly.

	done := make(chan bool, 1)
	timeout := time.After(5 * time.Second)

	go func() {
		var wg sync.WaitGroup

		// Multiple goroutines doing mixed operations
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					SetRunner(NewMockRunner())
					GetRunner()
					_, _ = RunnerCombinedOutput("test")
					_, _ = RunnerCombinedOutputWithSudo("test")
				}
			}()
		}

		wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		// Test completed successfully
	case <-timeout:
		t.Fatal("Test timed out - potential deadlock detected")
	}
}

// TestRunnerStateConsistency verifies that the runner state remains
// consistent across concurrent operations.
func TestRunnerStateConsistency(t *testing.T) {
	original := GetRunner()
	defer SetRunner(original)

	// Set initial state
	initialRunner := NewMockRunner()
	initialRunner.SetResponse("initial", []byte("initial response"))
	SetRunner(initialRunner)

	const numReaders = 50
	const numWriters = 10
	var wg sync.WaitGroup

	// Multiple readers
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for j := 0; j < 100; j++ {
				runner := GetRunner()
				if runner == nil {
					t.Errorf("GetRunner() returned nil")
					return
				}
				runtime.Gosched()
			}
		}()
	}

	// Fewer writers
	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < 10; j++ {
				mockRunner := NewMockRunner()
				mockRunner.SetResponse("test", []byte("test response"))
				mockRunner.SetResponse("echo test", []byte("test response"))
				mockRunner.SetResponse("fail2ban-client status", []byte("test response"))
				SetRunner(mockRunner)
				time.Sleep(time.Microsecond)
			}
		}(i)
	}

	wg.Wait()

	// Verify final state is consistent
	finalRunner := GetRunner()
	if finalRunner == nil {
		t.Fatal("Final runner state is nil")
	}
}
