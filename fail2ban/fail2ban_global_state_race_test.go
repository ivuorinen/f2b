package fail2ban

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestLogDir_ConcurrentAccess(t *testing.T) {
	// Save original log directory
	originalLogDir := GetLogDir()
	defer SetLogDir(originalLogDir)

	numGoroutines := 100
	opsPerGoroutine := 100

	var wg sync.WaitGroup
	// Error channel for thread-safe error collection
	errors := make(chan string, numGoroutines*opsPerGoroutine)

	// Start multiple goroutines that set and get log directory
	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := range opsPerGoroutine {
				if j%2 == 0 {
					// Set log directory
					testDir := fmt.Sprintf("/tmp/test-logs-%d-%d", id, j)
					SetLogDir(testDir)
				} else {
					// Get log directory
					dir := GetLogDir()
					if dir == "" {
						errors <- "GetLogDir returned empty string"
					}
				}
			}
		}(i)
	}

	wg.Wait()

	// Close error channel and process all errors
	close(errors)
	for errMsg := range errors {
		t.Errorf("%s", errMsg)
	}

	// Verify final state is consistent
	finalDir := GetLogDir()
	if finalDir == "" {
		t.Errorf("Final log directory should not be empty")
	}
}

func TestLogDir_GetSetConsistency(t *testing.T) {
	// Save original log directory
	originalLogDir := GetLogDir()
	defer SetLogDir(originalLogDir)

	testDir := "/tmp/test-log-consistency"

	// Set and immediately get
	SetLogDir(testDir)
	retrievedDir := GetLogDir()

	if retrievedDir != testDir {
		t.Errorf("Expected log dir %s, got %s", testDir, retrievedDir)
	}
}

func TestLogDir_ConcurrentSetAndRead(t *testing.T) {
	// Save original log directory
	originalLogDir := GetLogDir()
	defer SetLogDir(originalLogDir)

	numWriters := 10
	numReaders := 50
	duration := 100 * time.Millisecond

	var wg sync.WaitGroup
	done := make(chan struct{})
	// Error channel for thread-safe error collection
	errors := make(chan string, numReaders*100)

	// Start writer goroutines
	for i := range numWriters {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			counter := 0
			for {
				select {
				case <-done:
					return
				default:
					testDir := fmt.Sprintf("/tmp/writer-%d-count-%d", id, counter)
					SetLogDir(testDir)
					counter++
					time.Sleep(time.Millisecond)
				}
			}
		}(i)
	}

	// Start reader goroutines
	for i := range numReaders {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					dir := GetLogDir()
					if dir == "" {
						errors <- fmt.Sprintf("Reader %d got empty log directory", id)
					}
					time.Sleep(time.Millisecond / 2)
				}
			}
		}(i)
	}

	// Let them run for a short time
	time.Sleep(duration)
	close(done)
	wg.Wait()

	// Close error channel and process all errors
	close(errors)
	for errMsg := range errors {
		t.Errorf("%s", errMsg)
	}
}

func BenchmarkLogDir_ConcurrentAccess(b *testing.B) {
	// Save original log directory
	originalLogDir := GetLogDir()
	defer SetLogDir(originalLogDir)

	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			if counter%10 == 0 {
				// 10% writes
				SetLogDir(fmt.Sprintf("/tmp/bench-%d", counter))
			} else {
				// 90% reads
				GetLogDir()
			}
			counter++
		}
	})
}
