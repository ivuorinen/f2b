package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestReadStdout_WithData tests reading stdout with actual data
func TestReadStdout_WithData(t *testing.T) {
	env := NewTestEnvironment()
	defer env.Cleanup()

	// Set up pipes and write test data
	r, w, err := os.Pipe()
	assert.NoError(t, err)
	env.stdoutReader = r
	env.stdoutWriter = w

	// Write test data in background goroutine with synchronization
	testData := "test output data"
	done := make(chan struct{})
	go func() {
		_, _ = w.Write([]byte(testData))
		_ = w.Close()
		close(done)
	}()

	// Wait for write and close to complete
	<-done

	output := env.ReadStdout()
	assert.Equal(t, testData, output, "Should read the test data from stdout")
}

// TestReadStdout_WriterAlreadyClosed tests the scenario where writer is pre-closed
func TestReadStdout_WriterAlreadyClosed(t *testing.T) {
	env := NewTestEnvironment()
	defer env.Cleanup()

	// Set up pipes
	r, w, err := os.Pipe()
	assert.NoError(t, err)
	env.stdoutReader = r
	env.stdoutWriter = w

	// Write data and close writer before calling ReadStdout
	testData := "pre-closed data"
	done := make(chan struct{})
	go func() {
		_, _ = w.Write([]byte(testData))
		_ = w.Close()
		close(done)
	}()

	// Wait for write and close to complete
	<-done
	// Don't set env.stdoutWriter to nil - ReadStdout will close it

	output := env.ReadStdout()
	assert.Equal(t, testData, output, "Should read data even if writer was pre-closed")
}

// TestReadStdout_NilReader tests behavior when reader is nil
func TestReadStdout_NilReader(t *testing.T) {
	env := NewTestEnvironment()
	defer env.Cleanup()

	// Set up only writer, no reader
	_, w, err := os.Pipe()
	assert.NoError(t, err)
	env.stdoutWriter = w
	env.stdoutReader = nil

	output := env.ReadStdout()
	assert.Equal(t, "", output, "Should return empty string when reader is nil")

	// Clean up writer
	_ = w.Close()
}

// TestReadStdout_NilWriter tests behavior when writer is nil but reader exists
func TestReadStdout_NilWriter(t *testing.T) {
	env := NewTestEnvironment()
	defer env.Cleanup()

	// Set up only reader, no writer (simulates already-closed writer)
	r, w, err := os.Pipe()
	assert.NoError(t, err)
	_ = w.Close() // Close immediately
	env.stdoutReader = r
	env.stdoutWriter = nil

	output := env.ReadStdout()
	// Should handle nil writer gracefully and try to read (will get empty or EOF)
	assert.Equal(t, "", output)
}

// TestReadStdout_MultipleReads tests that ReadStdout can't be called twice safely
func TestReadStdout_MultipleReads(t *testing.T) {
	env := NewTestEnvironment()
	defer env.Cleanup()

	// Set up pipes
	r, w, err := os.Pipe()
	assert.NoError(t, err)
	env.stdoutReader = r
	env.stdoutWriter = w

	testData := "single read data"
	done := make(chan struct{})
	go func() {
		_, _ = w.Write([]byte(testData))
		_ = w.Close()
		close(done)
	}()

	// Wait for write and close to complete
	<-done

	// First read gets the data
	output1 := env.ReadStdout()
	assert.Equal(t, testData, output1)

	// Second read should return empty (writer already closed by first read)
	output2 := env.ReadStdout()
	assert.Equal(t, "", output2, "Second read should return empty")
}

// TestReadStdout_EmptyData tests reading when no data is written
func TestReadStdout_EmptyData(t *testing.T) {
	env := NewTestEnvironment()
	defer env.Cleanup()

	// Set up pipes but write nothing
	r, w, err := os.Pipe()
	assert.NoError(t, err)
	env.stdoutReader = r
	env.stdoutWriter = w

	// Close writer immediately without writing
	go func() {
		_ = w.Close()
	}()

	output := env.ReadStdout()
	assert.Equal(t, "", output, "Should return empty string when no data written")
}
