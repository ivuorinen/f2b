package fail2ban

import (
	"context"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/constants"
)

// TestRealClientKeepsInjectedRunner pins the runner field: a client built
// with one runner keeps using it after the process-global runner changes, so
// tests (and callers) do not depend on SetRunner state at call time.
func TestRealClientKeepsInjectedRunner(t *testing.T) {
	built := NewMockRunner()
	StandardMockSetup(built)
	t.Cleanup(WithTestRunner(t, built))

	client, err := NewClient("/var/log", "/etc/fail2ban/filter.d")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Swap the global runner; the client must not follow it.
	SetRunner(NewMockRunner())

	out, err := client.StatusAllWithContext(context.Background())
	if err != nil {
		t.Fatalf("StatusAllWithContext used the swapped global runner: %v", err)
	}
	if !strings.Contains(out, "Jail list") {
		t.Errorf("StatusAllWithContext output = %q, want the built runner's status", out)
	}
}

// TestZeroValueRealClientUsesGlobalRunner pins the nil-safe fallback: a
// RealClient literal without an injected runner reads the global runner.
func TestZeroValueRealClientUsesGlobalRunner(t *testing.T) {
	mock := NewMockRunner()
	mock.SetResponse("fail2ban-client status", []byte("global status"))
	t.Cleanup(WithTestRunner(t, mock))

	client := &RealClient{Path: constants.Fail2BanClientCommand}
	out, err := client.StatusAllWithContext(context.Background())
	if err != nil {
		t.Fatalf("StatusAllWithContext: %v", err)
	}
	if out != "global status" {
		t.Errorf("StatusAllWithContext output = %q, want %q", out, "global status")
	}
}

// TestNewClientInvalidFilterDirMessage pins the filter-directory error text:
// the constant already carries %w, and nesting it printed a literal "%w".
func TestNewClientInvalidFilterDirMessage(t *testing.T) {
	t.Setenv("ALLOW_DEV_PATHS", "")
	t.Cleanup(WithTestRunner(t, NewMockRunner()))

	_, err := NewClient("/var/log", "/home/not-a-filter-dir")
	if err == nil {
		t.Fatal("NewClient accepted a filter directory outside the allowlist")
	}
	if strings.Contains(err.Error(), "%w") || strings.Contains(err.Error(), "%!") {
		t.Errorf("error %q contains a formatting artifact", err)
	}
	if !strings.HasPrefix(err.Error(), "invalid filter directory: ") {
		t.Errorf("error %q, want prefix %q", err, "invalid filter directory: ")
	}
}
