package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/fail2ban"
)

func TestServiceCmd(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		mockResponse string
		mockError    error
		wantOutput   string
		wantError    bool
	}{
		{
			name:         "service status",
			args:         []string{"status"},
			mockResponse: "fail2ban is running",
			wantOutput:   "fail2ban is running",
			wantError:    false,
		},
		{
			name:         "service start",
			args:         []string{"start"},
			mockResponse: "Starting fail2ban service",
			wantOutput:   "Starting fail2ban service",
			wantError:    false,
		},
		{
			name:         "service stop",
			args:         []string{"stop"},
			mockResponse: "Stopping fail2ban service",
			wantOutput:   "Stopping fail2ban service",
			wantError:    false,
		},
		{
			name:         "service restart",
			args:         []string{"restart"},
			mockResponse: "Restarting fail2ban service",
			wantOutput:   "Restarting fail2ban service",
			wantError:    false,
		},
		{
			name:      "no action provided",
			args:      []string{},
			wantError: true, // Command should return error for missing action
		},
		{
			name:      "invalid action",
			args:      []string{"invalid"},
			wantError: true, // Command should return error for invalid action
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewCommandTest(t, "service").
				WithArgs(tt.args...).
				WithServiceSetup(func(mock *fail2ban.MockRunner) {
					if tt.mockResponse != "" {
						command := "sudo service fail2ban " + strings.Join(tt.args, " ")
						mock.SetResponse(command, []byte(tt.mockResponse))
					}
					if tt.mockError != nil {
						command := "sudo service fail2ban " + strings.Join(tt.args, " ")
						mock.SetError(command, tt.mockError)
					}
				})

			if tt.wantError {
				builder.ExpectError()
			} else {
				builder.ExpectSuccess()
			}

			if tt.wantOutput != "" {
				builder.ExpectOutput(tt.wantOutput)
			}

			builder.Run()
		})
	}
}

func TestServiceCmdWithJSONFormat(t *testing.T) {
	NewCommandTest(t, "service").
		WithArgs("status").
		WithJSONFormat().
		WithServiceSetup(func(mock *fail2ban.MockRunner) {
			mock.SetResponse("sudo service fail2ban status", []byte("fail2ban is running"))
		}).
		ExpectSuccess().
		ExpectOutput("fail2ban is running").
		Run()
}

func TestServiceCmdErrorHandling(t *testing.T) {
	NewCommandTest(t, "service").
		WithArgs("status").
		WithServiceSetup(func(mock *fail2ban.MockRunner) {
			mock.SetError("sudo service fail2ban status", &testServiceError{"service failed"})
		}).
		ExpectError().
		Run()
}

func TestServiceCmdValidActions(t *testing.T) {
	validActions := []string{"start", "stop", "restart", "status", "reload", "enable", "disable"}

	for _, action := range validActions {
		t.Run("action_"+action, func(t *testing.T) {
			wantOutput := "Action " + action + " completed"
			NewCommandTest(t, "service").
				WithArgs(action).
				WithServiceSetup(func(mock *fail2ban.MockRunner) {
					// enable/disable route through systemctl; everything else
					// through service(8).
					command := "sudo service fail2ban " + action
					if action == "enable" || action == "disable" {
						command = "sudo systemctl " + action + " fail2ban"
					}
					mock.SetResponse(command, []byte(wantOutput))
				}).
				ExpectSuccess().
				ExpectOutput(wantOutput).
				Run()
		})
	}
}

func TestServiceCmdMultipleArgs(t *testing.T) {
	// Test that service command only uses first arg:
	NewCommandTest(t, "service").
		WithArgs("start", "extra").
		WithServiceSetup(func(mock *fail2ban.MockRunner) {
			mock.SetResponse("sudo service fail2ban start", []byte("Starting fail2ban service"))
		}).
		ExpectSuccess().
		ExpectOutput("Starting fail2ban service").
		Run()
}

func TestServiceCmdEmptyResponse(t *testing.T) {
	// Test that empty response is handled gracefully:
	NewCommandTest(t, "service").
		WithArgs("status").
		WithServiceSetup(func(mock *fail2ban.MockRunner) {
			mock.SetResponse("sudo service fail2ban status", []byte(""))
		}).
		ExpectSuccess().
		Run()
}

// testServiceError implements error interface for testing
type testServiceError struct {
	message string
}

func (e *testServiceError) Error() string {
	return e.message
}

// TestServiceCmdSecurityValidation tests that command injection attempts are blocked
func TestServiceCmdSecurityValidation(t *testing.T) {
	maliciousActions := []string{
		"start; touch /tmp/test",
		"status && whoami",
		"restart | curl example.com",
		"stop`whoami`",
		"status$(id)",
		"start'||'curl example.com",
		"../../../etc/passwd",
		"start\ntouch /tmp/test",
		"status\techo test",
		"reload;curl example.com",
		"enable & echo test",
		"disable || curl example.com",
	}

	for _, maliciousAction := range maliciousActions {
		t.Run("malicious_action", func(t *testing.T) {
			// Test that malicious actions are rejected:
			result := NewCommandTest(t, "service").
				WithArgs(maliciousAction).
				WithServiceSetup(func(_ *fail2ban.MockRunner) {
					// No responses needed - command should be rejected before execution
				}).
				ExpectError(). // Command should return error for malicious actions
				Run()

			// Verify error message is present in output
			if !strings.Contains(result.Output, "invalid service action") {
				t.Errorf(
					"expected error message for malicious action %q, got output: %q",
					maliciousAction,
					result.Output,
				)
			}
		})
	}
}

// TestServiceCmdValidActionsOnly ensures only valid actions are accepted
func TestServiceCmdValidActionsOnly(t *testing.T) {
	validActions := []string{"start", "stop", "restart", "status", "reload", "enable", "disable"}
	invalidActions := []string{"invalid", "badaction", "test", "debug", "config", "init"}

	// Test valid actions
	for _, action := range validActions {
		t.Run("valid_action_"+action, func(t *testing.T) {
			wantOutput := "Action " + action + " completed"
			NewCommandTest(t, "service").
				WithArgs(action).
				WithServiceSetup(func(mock *fail2ban.MockRunner) {
					// enable/disable route through systemctl; everything else
					// through service(8).
					command := "sudo service fail2ban " + action
					if action == "enable" || action == "disable" {
						command = "sudo systemctl " + action + " fail2ban"
					}
					mock.SetResponse(command, []byte(wantOutput))
				}).
				ExpectSuccess().
				ExpectOutput(wantOutput).
				Run()
		})
	}

	// Test invalid actions
	for _, action := range invalidActions {
		t.Run("invalid_action_"+action, func(t *testing.T) {
			result := NewCommandTest(t, "service").
				WithArgs(action).
				WithServiceSetup(func(_ *fail2ban.MockRunner) {
					// No responses needed for invalid actions
				}).
				ExpectError(). // Command should return error for invalid actions
				Run()

			// Verify error message is present
			if !strings.Contains(result.Output, "invalid service action") {
				t.Errorf("invalid action %q should show error message, got output: %q", action, result.Output)
			}
		})
	}
}

// BenchmarkServiceCmd benchmarks the service command execution
func BenchmarkServiceCmd(b *testing.B) {
	// Set up mock environment once
	_, cleanup := fail2ban.SetupMockEnvironment(b)
	defer cleanup()

	// Get the mock runner and configure it
	mock := fail2ban.MustMockRunner(b)
	mock.SetResponse("sudo service fail2ban status", []byte("fail2ban is running"))

	// Framework could be used here but benchmark needs manual approach for performance:
	config := &Config{Format: "plain"}

	b.ResetTimer()
	for b.Loop() {
		cmd := ServiceCmd(config)
		oldStdout := os.Stdout
		r, w, err := os.Pipe()
		if err != nil {
			b.Fatalf("failed to create pipe: %v", err)
		}

		os.Stdout = w

		cmd.SetArgs([]string{"status"})
		if err := cmd.Execute(); err != nil {
			_ = w.Close()
			_ = r.Close()
			os.Stdout = oldStdout
			b.Fatalf("execute failed: %v", err)
		}

		if err := w.Close(); err != nil {
			_ = r.Close()
			os.Stdout = oldStdout
			b.Fatalf("failed to close writer: %v", err)
		}

		var stdoutBuf bytes.Buffer
		if _, err := stdoutBuf.ReadFrom(r); err != nil {
			_ = r.Close()
			os.Stdout = oldStdout
			b.Fatalf("failed to read output: %v", err)
		}

		// Clean up at end of iteration
		_ = r.Close()
		os.Stdout = oldStdout
	}
}
