package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// pipeWithData wires a fresh pipe into env, writes data to the writer, closes
// it, and returns once the write completes.
func pipeWithData(t *testing.T, env *TestEnvironment, data string) {
	t.Helper()
	r, w, err := os.Pipe()
	assert.NoError(t, err)
	env.stdoutReader = r
	env.stdoutWriter = w
	done := make(chan struct{})
	go func() {
		_, _ = w.Write([]byte(data))
		_ = w.Close()
		close(done)
	}()
	<-done
}

// TestReadStdout_WithData tests reading stdout with actual data
func TestReadStdout_WithData(t *testing.T) {
	env := NewTestEnvironment()
	defer env.Cleanup()

	pipeWithData(t, env, "test output data")

	assert.Equal(t, "test output data", env.ReadStdout(), "Should read the test data from stdout")
}

// TestReadStdout_WriterAlreadyClosed tests the scenario where the writer is
// closed before ReadStdout is called (ReadStdout must tolerate the double-close).
func TestReadStdout_WriterAlreadyClosed(t *testing.T) {
	env := NewTestEnvironment()
	defer env.Cleanup()

	pipeWithData(t, env, "pre-closed data")

	assert.Equal(t, "pre-closed data", env.ReadStdout(), "Should read data even if writer was pre-closed")
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

	pipeWithData(t, env, "single read data")

	// First read gets the data
	output1 := env.ReadStdout()
	assert.Equal(t, "single read data", output1)

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
