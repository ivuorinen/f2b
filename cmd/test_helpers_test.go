package cmd

import (
	"strings"

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
