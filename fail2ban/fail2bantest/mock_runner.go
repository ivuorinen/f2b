package fail2bantest

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// MockRunner is a simple mock for Runner, used in unit tests.
type MockRunner struct {
	mu        sync.Mutex // protects concurrent access to fields
	Responses map[string][]byte
	Errors    map[string]error
	CallLog   []string
}

// NewMockRunner creates a new mock runner instance for testing.
func NewMockRunner() *MockRunner {
	return &MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
		CallLog:   []string{},
	}
}

// validateInvocation mirrors OSRunner's input validation so tests exercise the
// same trust boundary as production: a fixture passing an invalid command or
// argument must fail here too, not only outside tests. A caller-supplied
// "sudo" is refused as production refuses it; only the mock's own privilege
// selection looks up sudo-keyed responses.
func validateInvocation(name string, args []string) error {
	if err := fail2ban.ValidateCommand(name); err != nil {
		return fmt.Errorf(constants.ErrCommandValidationFailed, err)
	}
	if err := fail2ban.ValidateArguments(args); err != nil {
		return fmt.Errorf(constants.ErrArgumentValidationFailed, err)
	}
	return nil
}

// CombinedOutput returns a mocked response or error for a command.
func (m *MockRunner) CombinedOutput(name string, args ...string) ([]byte, error) {
	if err := validateInvocation(name, args); err != nil {
		return nil, err
	}

	key := name + " " + strings.Join(args, " ")
	m.mu.Lock()
	defer m.mu.Unlock()

	m.CallLog = append(m.CallLog, key)

	if err, exists := m.Errors[key]; exists {
		return nil, err
	}

	if response, exists := m.Responses[key]; exists {
		return response, nil
	}

	return nil, fmt.Errorf("unexpected command: %s", key)
}

// CombinedOutputWithSudo returns a mocked response for sudo commands. It
// validates before looking up a sudo-keyed response, as OSRunner validates
// before running anything.
func (m *MockRunner) CombinedOutputWithSudo(name string, args ...string) ([]byte, error) {
	if err := validateInvocation(name, args); err != nil {
		return nil, err
	}
	checker := fail2ban.GetSudoChecker()

	// If mock checker says we're root, don't use sudo
	if checker.IsRoot() {
		return m.CombinedOutput(name, args...)
	}

	// If command requires sudo and we have privileges, mock with sudo
	if fail2ban.RequiresSudo(name, args...) && checker.HasSudoPrivileges() {
		sudoKey := "sudo " + name + " " + strings.Join(args, " ")

		// Check for sudo-specific response first (with lock protection)
		m.mu.Lock()
		m.CallLog = append(m.CallLog, sudoKey)

		if err, exists := m.Errors[sudoKey]; exists {
			m.mu.Unlock()
			return nil, err
		}

		if response, exists := m.Responses[sudoKey]; exists {
			m.mu.Unlock()
			return response, nil
		}
		m.mu.Unlock()

		// Fall back to non-sudo version if sudo version not mocked
		return m.CombinedOutput(name, args...)
	}

	// Otherwise run without sudo
	return m.CombinedOutput(name, args...)
}

// withContextCheck wraps an operation with context cancellation check.
// This helper consolidates the duplicate context cancellation pattern.
func withContextCheck(ctx context.Context, fn func() ([]byte, error)) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return fn()
}

// SetResponse sets a response for a command.
func (m *MockRunner) SetResponse(cmd string, response []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Responses[cmd] = response
}

// SetError sets an error for a command.
func (m *MockRunner) SetError(cmd string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Errors[cmd] = err
}

// GetCalls returns the log of commands called.
func (m *MockRunner) GetCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return a copy to prevent external modification
	calls := make([]string, len(m.CallLog))
	copy(calls, m.CallLog)
	return calls
}

// CombinedOutputWithSudoContext returns a mocked response for sudo commands with context support.
func (m *MockRunner) CombinedOutputWithSudoContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	return withContextCheck(ctx, func() ([]byte, error) {
		return m.CombinedOutputWithSudo(name, args...)
	})
}
