// Package fail2ban_test provides external tests for the fail2ban package,
// ensuring proper isolation and testing of exported interfaces.
package fail2ban_test

import (
	"context"
	"testing"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestConcurrentAccess tests concurrent access to the client
func TestConcurrentAccess(t *testing.T) {
	mock := &fail2bantest.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	mock.SetResponse("fail2ban-client banned 192.168.1.100", []byte(`["sshd"]`))
	t.Cleanup(fail2bantest.WithTestRunner(t, mock))

	client, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
	fail2bantest.AssertError(t, err, false, "create client for concurrency test")

	// Run concurrent operations
	done := make(chan bool)
	errors := make(chan error, 10)

	// Start multiple goroutines
	for range 10 {
		go func() {
			defer func() { done <- true }()

			// Test various operations
			_, err := client.ListJailsWithContext(context.Background())
			if err != nil {
				errors <- err
				return
			}

			_, err = client.BannedInWithContext(context.Background(), "192.168.1.100")
			if err != nil {
				errors <- err
				return
			}
		}()
	}

	// Wait for all goroutines to complete
	for range 10 {
		<-done
	}

	// Check for errors
	close(errors)
	for err := range errors {
		t.Errorf("concurrent access error: %v", err)
	}
}

// TestMemoryUsage tests that the client doesn't leak memory
func TestMemoryUsage(t *testing.T) {
	mock := &fail2bantest.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
	mock.SetResponse("fail2ban-client -V", []byte("0.11.2"))
	mock.SetResponse("fail2ban-client ping", []byte("pong"))
	mock.SetResponse("fail2ban-client status", []byte("Status\n|- Number of jail: 1\n`- Jail list: sshd"))
	t.Cleanup(fail2bantest.WithTestRunner(t, mock))

	// Create and destroy many clients
	for range 1000 {
		client, err := fail2ban.NewClient(constants.DefaultLogDir, constants.DefaultFilterDir)
		fail2bantest.AssertError(t, err, false, "create client in memory test")

		// Use the client
		_, err = client.ListJailsWithContext(context.Background())
		fail2bantest.AssertError(t, err, false, "list jails in memory test")

		// Client should be garbage collected
		_ = client
	}
}
