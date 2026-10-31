package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// MockClient is a type alias for the enhanced MockClient from fail2ban package
type MockClient = fail2ban.MockClient

// validTestConfig returns a Config that passes ValidateConfig (system default
// directories, positive timeouts). Tests exercising Execute must use a valid
// config now that validation is a hard error in PersistentPreRunE.
func validTestConfig(format string) Config {
	return Config{
		LogDir:          constants.DefaultLogDir,
		FilterDir:       constants.DefaultFilterDir,
		Format:          format,
		CommandTimeout:  constants.DefaultCommandTimeout,
		FileTimeout:     constants.DefaultFileTimeout,
		ParallelTimeout: constants.DefaultParallelTimeout,
	}
}

// NewMockClient creates a new MockClient for testing
func NewMockClient() *MockClient {
	return fail2ban.NewMockClient()
}

// setMockJails sets jails for the enhanced MockClient
func setMockJails(mock *MockClient, jails []string) {
	mock.Jails = make(map[string]struct{})
	for _, jail := range jails {
		mock.Jails[jail] = struct{}{}
	}
}

// AssertError provides standardized error checking for command tests
func AssertError(t interface {
	Helper()
	Fatalf(string, ...any)
}, err error, expectError bool, testName string) {
	t.Helper()
	if expectError && err == nil {
		t.Fatalf(constants.ErrTestExpectedError, testName)
	}
	if !expectError && err != nil {
		t.Fatalf(constants.ErrTestUnexpected, testName, err)
	}
}

// AssertOutputContains checks that output contains expected substring
func AssertOutputContains(t interface {
	Helper()
	Fatalf(string, ...any)
}, output, expectedSubstring, testName string) {
	t.Helper()
	if !strings.Contains(output, expectedSubstring) {
		t.Fatalf("%s: expected output containing %q but got %q", testName, expectedSubstring, output)
	}
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
		},
		{
			name: "output does not contain substring", output: "This is a test output",
			expectedSubstring: "missing content", shouldFail: true,
		},
		{name: "empty substring always matches", output: "any output", expectedSubstring: ""},
		{name: "exact match", output: "exact", expectedSubstring: "exact"},
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
