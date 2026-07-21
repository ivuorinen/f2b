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
	restoreRunner := WithTestRunner(t, GetRunner())
	defer restoreRunner()

	const numGoroutines = 100
	const numOperations = 50

	var wg sync.WaitGroup

	// Test concurrent SetRunner/GetRunner operations
	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := range numOperations {
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
	mockRunner := NewMockRunner()
	restoreRunner := WithTestRunner(t, mockRunner)
	defer restoreRunner()
	mockRunner.SetResponse("fail2ban-client status", []byte("test output"))

	const numGoroutines = 50
	var wg sync.WaitGroup

	for range numGoroutines {
		wg.Go(func() {
			output, err := RunnerCombinedOutput("fail2ban-client", "status")
			if err != nil {
				t.Errorf("RunnerCombinedOutput failed: %v", err)
				return
			}

			if string(output) != "test output" {
				t.Errorf("Expected 'test output', got '%s'", string(output))
			}
		})
	}

	wg.Wait()
}

// TestRunnerCombinedOutputWithSudoConcurrency tests concurrent calls to
// RunnerCombinedOutputWithSudo.
func TestRunnerCombinedOutputWithSudoConcurrency(t *testing.T) {
	// Set up mock environment with root privileges to avoid sudo prefix
	_, cleanup := SetupMockEnvironment(t)
	defer cleanup()

	// Get the mock runner and configure additional responses
	mockRunner := MustMockRunner(t)
	mockRunner.SetResponse("fail2ban-client status", []byte("status output"))

	const numGoroutines = 50
	var wg sync.WaitGroup

	for range numGoroutines {
		wg.Go(func() {
			output, err := RunnerCombinedOutputWithSudo("fail2ban-client", "status")
			if err != nil {
				t.Errorf("RunnerCombinedOutputWithSudo failed: %v", err)
				return
			}

			if string(output) != "status output" {
				t.Errorf("Expected 'status output', got '%s'", string(output))
			}
		})
	}

	wg.Wait()
}

// TestMixedConcurrentOperations tests mixed concurrent operations including
// setting runners and executing commands.
func TestMixedConcurrentOperations(t *testing.T) {
	// Set up a single shared MockRunner with all required responses
	// This avoids race conditions from multiple goroutines setting different runners
	sharedMockRunner := NewMockRunner()
	restoreRunner := WithTestRunner(t, sharedMockRunner)
	defer restoreRunner()

	// Set up responses for valid fail2ban commands to avoid validation errors
	sharedMockRunner.SetResponse("fail2ban-client status", []byte("Status: OK"))
	sharedMockRunner.SetResponse("fail2ban-client -V", []byte("Version: 1.0.0"))

	// Set up both sudo and non-sudo versions to handle different execution paths
	sharedMockRunner.SetResponse("sudo fail2ban-client status", []byte("Status: OK"))
	sharedMockRunner.SetResponse("sudo fail2ban-client -V", []byte("Version: 1.0.0"))

	const numGoroutines = 30
	var wg sync.WaitGroup

	// Group 1: Set runners (now just validates that setting runners works concurrently)
	for range numGoroutines / 3 {
		wg.Go(mixedConcurrentSetRunnerWorker)
	}

	// Group 2: Execute regular commands (using valid fail2ban commands)
	for range numGoroutines / 3 {
		wg.Go(func() { mixedConcurrentRegularWorker(t) })
	}

	// Group 3: Execute sudo commands (using valid fail2ban commands)
	for range numGoroutines / 3 {
		wg.Go(func() { mixedConcurrentSudoWorker(t) })
	}

	wg.Wait()
}

// mixedConcurrentSetRunnerWorker repeatedly swaps in fresh mock runners to
// exercise concurrent SetRunner calls.
func mixedConcurrentSetRunnerWorker() {
	for range 20 {
		// Create a new runner with the same responses to test concurrent setting
		mockRunner := NewMockRunner()
		mockRunner.SetResponse("fail2ban-client status", []byte("Status: OK"))
		mockRunner.SetResponse("fail2ban-client -V", []byte("Version: 1.0.0"))
		mockRunner.SetResponse("sudo fail2ban-client status", []byte("Status: OK"))
		mockRunner.SetResponse("sudo fail2ban-client -V", []byte("Version: 1.0.0"))
		SetRunner(mockRunner)
		time.Sleep(time.Millisecond)
	}
}

// mixedConcurrentRegularWorker repeatedly runs a regular command and verifies
// its output.
func mixedConcurrentRegularWorker(t *testing.T) {
	t.Helper()
	for range 20 {
		output, err := RunnerCombinedOutput("fail2ban-client", "status")
		if err != nil {
			t.Errorf("RunnerCombinedOutput failed: %v", err)
		}
		if len(output) == 0 {
			t.Error("RunnerCombinedOutput returned empty output")
		}
		time.Sleep(time.Millisecond)
	}
}

// mixedConcurrentSudoWorker repeatedly runs a sudo command and verifies its
// output.
func mixedConcurrentSudoWorker(t *testing.T) {
	t.Helper()
	for range 20 {
		output, err := RunnerCombinedOutputWithSudo("fail2ban-client", "-V")
		if err != nil {
			t.Errorf("RunnerCombinedOutputWithSudo failed: %v", err)
		}
		if len(output) == 0 {
			t.Error("RunnerCombinedOutputWithSudo returned empty output")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestRunnerManagerLockOrdering verifies there are no deadlocks in the
// runner manager's lock ordering.
func TestRunnerManagerLockOrdering(t *testing.T) {
	restoreRunner := WithTestRunner(t, GetRunner())
	defer restoreRunner()

	// This test specifically looks for deadlocks by creating scenarios
	// where multiple goroutines could potentially deadlock if locks
	// are not acquired/released properly.

	done := make(chan bool, 1)
	timeout := time.After(5 * time.Second)

	go func() {
		var wg sync.WaitGroup

		// Multiple goroutines doing mixed operations
		for range 20 {
			wg.Go(func() {
				for range 100 {
					SetRunner(NewMockRunner())
					GetRunner()
					_, _ = RunnerCombinedOutput("test")
					_, _ = RunnerCombinedOutputWithSudo("test")
				}
			})
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
	// Set initial state
	initialRunner := NewMockRunner()
	initialRunner.SetResponse("initial", []byte("initial response"))
	restoreRunner := WithTestRunner(t, initialRunner)
	defer restoreRunner()

	const numReaders = 50
	const numWriters = 10
	var wg sync.WaitGroup

	// Multiple readers
	for range numReaders {
		wg.Go(func() {
			for range 100 {
				runner := GetRunner()
				if runner == nil {
					t.Errorf("GetRunner() returned nil")
					return
				}
				runtime.Gosched()
			}
		})
	}

	// Fewer writers
	for range numWriters {
		wg.Go(func() {
			for range 10 {
				mockRunner := NewMockRunner()
				mockRunner.SetResponse("test", []byte("test response"))
				mockRunner.SetResponse("echo test", []byte("test response"))
				mockRunner.SetResponse("fail2ban-client status", []byte("test response"))
				SetRunner(mockRunner)
				time.Sleep(time.Microsecond)
			}
		})
	}

	wg.Wait()

	// Verify final state is consistent
	finalRunner := GetRunner()
	if finalRunner == nil {
		t.Fatal("Final runner state is nil")
	}
}
