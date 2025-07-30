package fail2ban

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// isContextError checks if an error is related to context timeout/cancellation
func isContextError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		strings.Contains(err.Error(), "context deadline exceeded") ||
		strings.Contains(err.Error(), "context canceled")
}

// TestContextCancellationSupport verifies that client operations respect context cancellation
func TestContextCancellationSupport(t *testing.T) {
	// Set up mock environment
	mock := NewMockRunner()
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mock.SetResponse("sudo fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mock.SetResponse("fail2ban-client ping", []byte("Server replied: pong"))
	mock.SetResponse("sudo fail2ban-client ping", []byte("Server replied: pong"))
	SetRunner(mock)

	// Create a real client for testing (will use mock environment)
	client, err := NewClient("/var/log", "/etc/fail2ban/filter.d")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test with canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = client.GetLogLinesWithContext(ctx, "sshd", "192.168.1.100")
	if !errors.Is(err, context.Canceled) && !isContextError(err) {
		t.Errorf("Expected context cancellation error, got: %v", err)
	}
}

// TestBanOperationContextTimeout tests that ban operations respect context timeouts
func TestBanOperationContextTimeout(t *testing.T) {
	// Set up mock environment
	mock := NewMockRunner()
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mock.SetResponse("sudo fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mock.SetResponse("fail2ban-client ping", []byte("Server replied: pong"))
	mock.SetResponse("sudo fail2ban-client ping", []byte("Server replied: pong"))
	SetRunner(mock)

	client, err := NewClient("/var/log", "/etc/fail2ban/filter.d")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Add small delay to ensure timeout
	time.Sleep(2 * time.Millisecond)

	_, err = client.BanIPWithContext(ctx, "192.168.1.100", "sshd")
	if !errors.Is(err, context.DeadlineExceeded) && !isContextError(err) {
		t.Errorf("Expected context timeout error, got: %v", err)
	}
}

// TestGetBanRecordsContextTimeout tests that ban record retrieval respects context timeouts
func TestGetBanRecordsContextTimeout(t *testing.T) {
	// Set up mock environment
	mock := NewMockRunner()
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("sudo fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mock.SetResponse("sudo fail2ban-client -V", []byte("Fail2Ban v0.11.0"))
	mock.SetResponse("fail2ban-client ping", []byte("Server replied: pong"))
	mock.SetResponse("sudo fail2ban-client ping", []byte("Server replied: pong"))
	SetRunner(mock)

	client, err := NewClient("/var/log", "/etc/fail2ban/filter.d")
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test with reasonable timeout (should succeed)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.GetBanRecordsWithContext(ctx, []string{"sshd"})
	if errors.Is(err, context.DeadlineExceeded) {
		t.Error("Unexpected timeout error with reasonable timeout")
	}
}
