package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestProcessBanOperationParallel tests the ProcessBanOperationParallel wrapper function
func TestProcessBanOperationParallel(t *testing.T) {
	// Save and restore original runner
	originalRunner := fail2ban.GetRunner()
	defer fail2ban.SetRunner(originalRunner)

	mockRunner := fail2ban.NewMockRunner()
	setupBasicMockResponses(mockRunner)
	mockRunner.SetResponse("fail2ban-client set sshd banip 192.168.1.1", []byte("1"))
	mockRunner.SetResponse("sudo fail2ban-client set sshd banip 192.168.1.1", []byte("1"))
	mockRunner.SetResponse("fail2ban-client set apache banip 192.168.1.1", []byte("1"))
	mockRunner.SetResponse("sudo fail2ban-client set apache banip 192.168.1.1", []byte("1"))
	fail2ban.SetRunner(mockRunner)

	client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	results, err := ProcessBanOperationParallel(client, "192.168.1.1", []string{"sshd", "apache"})
	assert.NoError(t, err)
	assert.Len(t, results, 2)
}

// TestProcessUnbanOperationParallel tests the ProcessUnbanOperationParallel wrapper function
func TestProcessUnbanOperationParallel(t *testing.T) {
	// Save and restore original runner
	originalRunner := fail2ban.GetRunner()
	defer fail2ban.SetRunner(originalRunner)

	mockRunner := fail2ban.NewMockRunner()
	setupBasicMockResponses(mockRunner)
	mockRunner.SetResponse("fail2ban-client set sshd unbanip 192.168.1.1", []byte("1"))
	mockRunner.SetResponse("sudo fail2ban-client set sshd unbanip 192.168.1.1", []byte("1"))
	fail2ban.SetRunner(mockRunner)

	client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	results, err := ProcessUnbanOperationParallel(client, "192.168.1.1", []string{"sshd"})
	assert.NoError(t, err)
	assert.Len(t, results, 1)
}

// TestProcessBanOperationParallelWithContext tests the wrapper with context
func TestProcessBanOperationParallelWithContext(t *testing.T) {
	// Save and restore original runner
	originalRunner := fail2ban.GetRunner()
	defer fail2ban.SetRunner(originalRunner)

	mockRunner := fail2ban.NewMockRunner()
	setupBasicMockResponses(mockRunner)
	mockRunner.SetResponse("fail2ban-client set sshd banip 192.168.1.1", []byte("1"))
	mockRunner.SetResponse("sudo fail2ban-client set sshd banip 192.168.1.1", []byte("1"))
	fail2ban.SetRunner(mockRunner)

	client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	ctx := context.Background()
	results, err := ProcessBanOperationParallelWithContext(ctx, client, "192.168.1.1", []string{"sshd"})
	assert.NoError(t, err)
	assert.Len(t, results, 1)
}

// TestProcessUnbanOperationParallelWithContext tests the wrapper with context
func TestProcessUnbanOperationParallelWithContext(t *testing.T) {
	// Save and restore original runner
	originalRunner := fail2ban.GetRunner()
	defer fail2ban.SetRunner(originalRunner)

	mockRunner := fail2ban.NewMockRunner()
	setupBasicMockResponses(mockRunner)
	mockRunner.SetResponse("fail2ban-client set sshd unbanip 192.168.1.1", []byte("1"))
	mockRunner.SetResponse("sudo fail2ban-client set sshd unbanip 192.168.1.1", []byte("1"))
	fail2ban.SetRunner(mockRunner)

	client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)

	ctx := context.Background()
	results, err := ProcessUnbanOperationParallelWithContext(ctx, client, "192.168.1.1", []string{"sshd"})
	assert.NoError(t, err)
	assert.Len(t, results, 1)
}

// MockTestingT is a mock for testing.T used to test test helper functions
type MockTestingT struct {
	helperCalled  bool
	fatalfCalled  bool
	fatalfMessage string
	fatalfArgs    []interface{}
}

func (m *MockTestingT) Helper() {
	m.helperCalled = true
}

func (m *MockTestingT) Fatalf(format string, args ...interface{}) {
	m.fatalfCalled = true
	m.fatalfMessage = format
	m.fatalfArgs = args
}

// TestAssertOutputContains tests the AssertOutputContains function
func TestAssertOutputContains(t *testing.T) {
	tests := []struct {
		name              string
		output            string
		expectedSubstring string
		shouldFail        bool
	}{
		{
			name:              "output contains substring",
			output:            "This is a test output with some content",
			expectedSubstring: "test output",
			shouldFail:        false,
		},
		{
			name:              "output does not contain substring",
			output:            "This is a test output",
			expectedSubstring: "missing content",
			shouldFail:        true,
		},
		{
			name:              "empty substring always matches",
			output:            "any output",
			expectedSubstring: "",
			shouldFail:        false,
		},
		{
			name:              "exact match",
			output:            "exact",
			expectedSubstring: "exact",
			shouldFail:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockTestingT{}
			AssertOutputContains(mock, tt.output, tt.expectedSubstring, "test")

			assert.True(t, mock.helperCalled, "Helper() should be called")

			if tt.shouldFail {
				assert.True(t, mock.fatalfCalled, "Fatalf should be called when assertion fails")
				assert.Contains(t, mock.fatalfMessage, "expected output containing")
			} else {
				assert.False(t, mock.fatalfCalled, "Fatalf should not be called when assertion succeeds")
			}
		})
	}
}
