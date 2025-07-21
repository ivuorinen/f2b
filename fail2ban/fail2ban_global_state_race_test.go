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

	// Start multiple goroutines that set and get log directory
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < opsPerGoroutine; j++ {
				if j%2 == 0 {
					// Set log directory
					testDir := fmt.Sprintf("/tmp/test-logs-%d-%d", id, j)
					SetLogDir(testDir)
				} else {
					// Get log directory
					dir := GetLogDir()
					if dir == "" {
						t.Errorf("GetLogDir returned empty string")
					}
				}
			}
		}(i)
	}

	wg.Wait()

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

	// Start writer goroutines
	for i := 0; i < numWriters; i++ {
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
	for i := 0; i < numReaders; i++ {
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
						t.Errorf("Reader %d got empty log directory", id)
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
