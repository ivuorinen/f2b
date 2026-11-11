package fail2ban_test

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestRunnerConcurrentAccess tests that concurrent access to the runner
// is safe and doesn't cause race conditions.
func TestRunnerConcurrentAccess(t *testing.T) {
	restoreRunner := fail2bantest.WithTestRunner(t, fail2ban.GetRunner())
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
					mockRunner := fail2bantest.NewMockRunner()
					mockRunner.SetResponse("test", []byte("response"))
					fail2ban.SetRunner(mockRunner)
				} else {
					fail2ban.SetRunner(&fail2ban.OSRunner{})
				}

				// Get runner and verify it's not nil
				runner := fail2ban.GetRunner()
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

// TestRunnerCombinedOutputWithSudoConcurrency tests concurrent calls to
// RunnerCombinedOutputWithSudoContext.
func TestRunnerCombinedOutputWithSudoConcurrency(t *testing.T) {
	// Set up mock environment with root privileges to avoid sudo prefix
	_, cleanup := fail2bantest.SetupMockEnvironment(t)
	defer cleanup()

	// Get the mock runner and configure additional responses
	mockRunner := fail2bantest.MustMockRunner(t)
	mockRunner.SetResponse("fail2ban-client status", []byte("status output"))

	const numGoroutines = 50
	var wg sync.WaitGroup

	for range numGoroutines {
		wg.Go(func() {
			output, err := fail2ban.GetRunner().
				CombinedOutputWithSudoContext(context.Background(), "fail2ban-client", "status")
			if err != nil {
				t.Errorf("RunnerCombinedOutputWithSudoContext failed: %v", err)
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
	sharedMockRunner := fail2bantest.NewMockRunner()
	restoreRunner := fail2bantest.WithTestRunner(t, sharedMockRunner)
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
		mockRunner := fail2bantest.NewMockRunner()
		mockRunner.SetResponse("fail2ban-client status", []byte("Status: OK"))
		mockRunner.SetResponse("fail2ban-client -V", []byte("Version: 1.0.0"))
		mockRunner.SetResponse("sudo fail2ban-client status", []byte("Status: OK"))
		mockRunner.SetResponse("sudo fail2ban-client -V", []byte("Version: 1.0.0"))
		fail2ban.SetRunner(mockRunner)
		time.Sleep(time.Millisecond)
	}
}

// mixedConcurrentRegularWorker repeatedly runs a regular command and verifies
// its output.
func mixedConcurrentRegularWorker(t *testing.T) {
	t.Helper()
	for range 20 {
		output, err := fail2ban.GetRunner().
			CombinedOutputWithSudoContext(context.Background(), "fail2ban-client", "status")
		if err != nil {
			t.Errorf("CombinedOutputWithContext failed: %v", err)
		}
		if len(output) == 0 {
			t.Error("CombinedOutputWithContext returned empty output")
		}
		time.Sleep(time.Millisecond)
	}
}

// mixedConcurrentSudoWorker repeatedly runs a sudo command and verifies its
// output.
func mixedConcurrentSudoWorker(t *testing.T) {
	t.Helper()
	for range 20 {
		output, err := fail2ban.GetRunner().CombinedOutputWithSudoContext(context.Background(), "fail2ban-client", "-V")
		if err != nil {
			t.Errorf("RunnerCombinedOutputWithSudoContext failed: %v", err)
		}
		if len(output) == 0 {
			t.Error("RunnerCombinedOutputWithSudoContext returned empty output")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestRunnerManagerLockOrdering verifies there are no deadlocks in the
// runner manager's lock ordering.
func TestRunnerManagerLockOrdering(t *testing.T) {
	restoreRunner := fail2bantest.WithTestRunner(t, fail2ban.GetRunner())
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
					fail2ban.SetRunner(fail2bantest.NewMockRunner())
					fail2ban.GetRunner()
					_, _ = fail2ban.GetRunner().CombinedOutputWithSudoContext(context.Background(), "test")
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
	initialRunner := fail2bantest.NewMockRunner()
	initialRunner.SetResponse("initial", []byte("initial response"))
	restoreRunner := fail2bantest.WithTestRunner(t, initialRunner)
	defer restoreRunner()

	const numReaders = 50
	const numWriters = 10
	var wg sync.WaitGroup

	// Multiple readers
	for range numReaders {
		wg.Go(func() {
			for range 100 {
				runner := fail2ban.GetRunner()
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
				mockRunner := fail2bantest.NewMockRunner()
				mockRunner.SetResponse("test", []byte("test response"))
				mockRunner.SetResponse("echo test", []byte("test response"))
				mockRunner.SetResponse("fail2ban-client status", []byte("test response"))
				fail2ban.SetRunner(mockRunner)
				time.Sleep(time.Microsecond)
			}
		})
	}

	wg.Wait()

	// Verify final state is consistent
	finalRunner := fail2ban.GetRunner()
	if finalRunner == nil {
		t.Fatal("Final runner state is nil")
	}
}
