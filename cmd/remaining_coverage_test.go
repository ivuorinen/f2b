package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
)

// newParallelTestClient builds a RealClient over a mock runner that answers a
// successful (count "1") response for `set <jail> <action> 192.168.1.1` on each
// given jail. Shared by the parallel ban/unban wrapper tests.
func newParallelTestClient(t *testing.T, action string, jails ...string) fail2ban.Client {
	t.Helper()
	mockRunner := fail2ban.NewMockRunner()
	t.Cleanup(fail2ban.WithTestRunner(t, mockRunner))
	fail2ban.StandardMockSetup(mockRunner)
	for _, jail := range jails {
		cmd := "fail2ban-client set " + jail + " " + action + " 192.168.1.1"
		mockRunner.SetResponse(cmd, []byte("1"))
		mockRunner.SetResponse("sudo "+cmd, []byte("1"))
	}
	client, err := fail2ban.NewClient("/var/log/fail2ban", "/etc/fail2ban/filter.d")
	require.NoError(t, err)
	return client
}

// assertParallelResults checks each per-jail outcome, not just the slice
// length — a regression that fails every jail while still returning a
// populated slice must fail these tests.
func assertParallelResults(t *testing.T, results []OperationResult, ip, wantStatus string, jails ...string) {
	t.Helper()
	assert.Len(t, results, len(jails))
	seen := map[string]bool{}
	for _, r := range results {
		assert.Equal(t, ip, r.IP)
		assert.Equal(t, wantStatus, r.Status, "jail %s", r.Jail)
		seen[r.Jail] = true
	}
	for _, jail := range jails {
		assert.True(t, seen[jail], "no result for jail %s", jail)
	}
}

// TestProcessBanOperationParallel tests the ProcessBanOperationParallel wrapper function
func TestProcessBanOperationParallel(t *testing.T) {
	client := newParallelTestClient(t, "banip", "sshd", "apache")
	results, err := ProcessBanOperationParallel(client, "192.168.1.1", []string{"sshd", "apache"})
	assert.NoError(t, err)
	assertParallelResults(t, results, "192.168.1.1", "Banned", "sshd", "apache")
}

// TestProcessUnbanOperationParallel tests the ProcessUnbanOperationParallel wrapper function
func TestProcessUnbanOperationParallel(t *testing.T) {
	client := newParallelTestClient(t, "unbanip", "sshd")
	results, err := ProcessUnbanOperationParallel(client, "192.168.1.1", []string{"sshd"})
	assert.NoError(t, err)
	assertParallelResults(t, results, "192.168.1.1", "Unbanned", "sshd")
}

// TestProcessBanOperationParallelWithContext tests the wrapper with context
func TestProcessBanOperationParallelWithContext(t *testing.T) {
	client := newParallelTestClient(t, "banip", "sshd")
	results, err := ProcessBanOperationParallelWithContext(
		context.Background(),
		client,
		"192.168.1.1",
		[]string{"sshd"},
	)
	assert.NoError(t, err)
	assertParallelResults(t, results, "192.168.1.1", "Banned", "sshd")
}

// TestProcessUnbanOperationParallelWithContext tests the wrapper with context
func TestProcessUnbanOperationParallelWithContext(t *testing.T) {
	client := newParallelTestClient(t, "unbanip", "sshd")
	results, err := ProcessUnbanOperationParallelWithContext(
		context.Background(),
		client,
		"192.168.1.1",
		[]string{"sshd"},
	)
	assert.NoError(t, err)
	assertParallelResults(t, results, "192.168.1.1", "Unbanned", "sshd")
}

// MockTestingT is a mock for testing.T used to test test helper functions
type MockTestingT struct {
	helperCalled  bool
	fatalfCalled  bool
	fatalfMessage string
}

func (m *MockTestingT) Helper() {
	m.helperCalled = true
}

func (m *MockTestingT) Fatalf(format string, _ ...any) {
	m.fatalfCalled = true
	m.fatalfMessage = format
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
