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
		name           string
		args           []string
		mockResponse   string
		mockError      error
		expectedOutput string
		expectError    bool
	}{
		{
			name:           "service status",
			args:           []string{"status"},
			mockResponse:   "fail2ban is running",
			expectedOutput: "fail2ban is running",
			expectError:    false,
		},
		{
			name:           "service start",
			args:           []string{"start"},
			mockResponse:   "Starting fail2ban service",
			expectedOutput: "Starting fail2ban service",
			expectError:    false,
		},
		{
			name:           "service stop",
			args:           []string{"stop"},
			mockResponse:   "Stopping fail2ban service",
			expectedOutput: "Stopping fail2ban service",
			expectError:    false,
		},
		{
			name:           "service restart",
			args:           []string{"restart"},
			mockResponse:   "Restarting fail2ban service",
			expectedOutput: "Restarting fail2ban service",
			expectError:    false,
		},
		{
			name:        "no action provided",
			args:        []string{},
			expectError: false, // The command will show error but returns nil error (PrintError is called)
		},
		{
			name:        "invalid action",
			args:        []string{"invalid"},
			expectError: false, // PrintError is called but returns nil error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original checker and set up mock with privileges
			originalChecker := fail2ban.GetSudoChecker()
			defer fail2ban.SetSudoChecker(originalChecker)
			mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
			fail2ban.SetSudoChecker(mockChecker)

			// Create mock runner
			mock := &fail2ban.MockRunner{
				Responses: make(map[string][]byte),
				Errors:    make(map[string]error),
			}

			if tt.mockResponse != "" {
				command := "sudo service fail2ban " + strings.Join(tt.args, " ")
				mock.SetResponse(command, []byte(tt.mockResponse))
			}

			if tt.mockError != nil {
				command := "sudo service fail2ban " + strings.Join(tt.args, " ")
				mock.SetError(command, tt.mockError)
			}

			// Set the mock runner
			fail2ban.SetRunner(mock)

			// Create service command
			config := &Config{Format: "plain"}
			cmd := ServiceCmd(config)

			// Capture stdout since PrintOutput writes to os.Stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Capture stderr for error output
			var errBuf bytes.Buffer
			cmd.SetErr(&errBuf)

			// Set args and execute
			cmd.SetArgs(tt.args)
			err := cmd.Execute()

			// Restore stdout and get output
			if err := w.Close(); err != nil {
				t.Fatalf("failed to close writer: %v", err)
			}
			os.Stdout = oldStdout

			var stdoutBuf bytes.Buffer
			if _, err := stdoutBuf.ReadFrom(r); err != nil {
				t.Fatalf("failed to read output: %v", err)
			}
			output := stdoutBuf.String() + errBuf.String()

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.expectedOutput != "" && !strings.Contains(output, tt.expectedOutput) {
					t.Errorf("expected output to contain %q, got %q", tt.expectedOutput, output)
				}
			}
		})
	}
}

func TestServiceCmdWithJSONFormat(t *testing.T) {
	// Save original checker and set up mock with privileges
	originalChecker := fail2ban.GetSudoChecker()
	defer fail2ban.SetSudoChecker(originalChecker)
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)

	// Create mock runner
	mock := &fail2ban.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}

	mock.SetResponse("sudo service fail2ban status", []byte("fail2ban is running"))
	fail2ban.SetRunner(mock)

	// Create service command with JSON format
	config := &Config{Format: JSONFormat}
	cmd := ServiceCmd(config)

	// Capture stdout since PrintOutput writes to os.Stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmd.SetArgs([]string{"status"})
	err := cmd.Execute()

	// Restore stdout and get output
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	os.Stdout = oldStdout

	var stdoutBuf bytes.Buffer
	if _, err := stdoutBuf.ReadFrom(r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	output := stdoutBuf.String()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// JSON format should still work, though service output is typically plain text
	if !strings.Contains(output, "fail2ban is running") {
		t.Errorf("expected service output, got: %s", output)
	}
}

func TestServiceCmdErrorHandling(t *testing.T) {
	// Save original checker and set up mock with privileges
	originalChecker := fail2ban.GetSudoChecker()
	defer fail2ban.SetSudoChecker(originalChecker)
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)

	// Create mock runner that returns an error
	mock := &fail2ban.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}

	mock.SetError("sudo service fail2ban status", &testServiceError{"service failed"})
	fail2ban.SetRunner(mock)

	// Capture log output
	oldOutput := Logger.Out
	var logBuf bytes.Buffer
	Logger.SetOutput(&logBuf)
	defer Logger.SetOutput(oldOutput)

	// Create and execute command
	config := &Config{Format: "plain"}
	cmd := ServiceCmd(config)

	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{"status"})

	err := cmd.Execute()

	// Should return error
	if err == nil {
		t.Errorf("expected error but got none")
	}

	// Should log error
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "Command failed") {
		t.Errorf("expected error to be logged, got: %s", logOutput)
	}
}

func TestServiceCmdValidActions(t *testing.T) {
	validActions := []string{"start", "stop", "restart", "status", "reload", "enable", "disable"}

	// Save original checker and set up mock with privileges
	originalChecker := fail2ban.GetSudoChecker()
	defer fail2ban.SetSudoChecker(originalChecker)
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)

	// Create mock runner
	mock := &fail2ban.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}

	// Set up responses for all valid actions
	for _, action := range validActions {
		command := "sudo service fail2ban " + action
		mock.SetResponse(command, []byte("Action "+action+" completed"))
	}

	fail2ban.SetRunner(mock)

	config := &Config{Format: "plain"}

	for _, action := range validActions {
		t.Run("action_"+action, func(t *testing.T) {
			// Create a fresh mock for each test
			testMock := &fail2ban.MockRunner{
				Responses: make(map[string][]byte),
				Errors:    make(map[string]error),
			}
			command := "sudo service fail2ban " + action
			testMock.SetResponse(command, []byte("Action "+action+" completed"))
			fail2ban.SetRunner(testMock)

			cmd := ServiceCmd(config)

			// Capture stdout since PrintOutput writes to os.Stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			cmd.SetArgs([]string{action})
			err := cmd.Execute()

			// Restore stdout and get output
			if err := w.Close(); err != nil {
				t.Fatalf("failed to close writer: %v", err)
			}
			os.Stdout = oldStdout

			var stdoutBuf bytes.Buffer
			if _, err := stdoutBuf.ReadFrom(r); err != nil {
				t.Fatalf("failed to read output: %v", err)
			}
			output := stdoutBuf.String()

			if err != nil {
				t.Errorf("unexpected error for action %s: %v", action, err)
			}

			expectedOutput := "Action " + action + " completed"
			if !strings.Contains(output, expectedOutput) {
				t.Errorf("expected output to contain %q for action %s, got %q", expectedOutput, action, output)
			}
		})
	}
}

func TestServiceCmdMultipleArgs(t *testing.T) {
	// Save original checker and set up mock with privileges
	originalChecker := fail2ban.GetSudoChecker()
	defer fail2ban.SetSudoChecker(originalChecker)
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)

	// Test service command with multiple arguments - service command only uses first arg
	mock := &fail2ban.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}

	// Service command only uses the first argument after "service fail2ban"
	mock.SetResponse("sudo service fail2ban start", []byte("Starting fail2ban service"))
	fail2ban.SetRunner(mock)

	config := &Config{Format: "plain"}
	cmd := ServiceCmd(config)

	// Capture stdout since PrintOutput writes to os.Stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmd.SetArgs([]string{"start", "extra"})
	err := cmd.Execute()

	// Restore stdout and get output
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	os.Stdout = oldStdout

	var stdoutBuf bytes.Buffer
	if _, err := stdoutBuf.ReadFrom(r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	output := stdoutBuf.String()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "Starting fail2ban service") {
		t.Errorf("expected service output, got: %q", output)
	}
}

func TestServiceCmdEmptyResponse(t *testing.T) {
	// Save original checker and set up mock with privileges
	originalChecker := fail2ban.GetSudoChecker()
	defer fail2ban.SetSudoChecker(originalChecker)
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)

	// Test service command with empty response
	mock := &fail2ban.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}

	mock.SetResponse("sudo service fail2ban status", []byte(""))
	fail2ban.SetRunner(mock)

	config := &Config{Format: "plain"}
	cmd := ServiceCmd(config)

	// Capture stdout since PrintOutput writes to os.Stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cmd.SetArgs([]string{"status"})
	err := cmd.Execute()

	// Restore stdout and get output
	if err := w.Close(); err != nil {
		t.Fatalf("failed to close writer: %v", err)
	}
	os.Stdout = oldStdout

	var stdoutBuf bytes.Buffer
	if _, err := stdoutBuf.ReadFrom(r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	output := stdoutBuf.String()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Empty response should still be handled gracefully
	// Output might be empty, but command should not fail
	_ = output // Just verify no panic occurs
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

	// Save original checker and set up mock with privileges
	originalChecker := fail2ban.GetSudoChecker()
	defer fail2ban.SetSudoChecker(originalChecker)
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)

	// Create mock runner - shouldn't be called for invalid actions
	mock := &fail2ban.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}
	fail2ban.SetRunner(mock)

	config := &Config{Format: "plain"}

	for _, maliciousAction := range maliciousActions {
		t.Run("malicious_action", func(t *testing.T) {
			cmd := ServiceCmd(config)

			// Capture stderr where PrintError writes
			oldStderr := os.Stderr
			errR, errW, _ := os.Pipe()
			os.Stderr = errW

			// Capture logger output
			var logBuf bytes.Buffer
			originalLogOutput := Logger.Out
			Logger.SetOutput(&logBuf)

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			cmd.SetArgs([]string{maliciousAction})
			err := cmd.Execute()

			// Close writers and restore
			if err := w.Close(); err != nil {
				t.Fatalf("failed to close stdout writer: %v", err)
			}
			if err := errW.Close(); err != nil {
				t.Fatalf("failed to close stderr writer: %v", err)
			}
			os.Stdout = oldStdout
			os.Stderr = oldStderr
			Logger.SetOutput(originalLogOutput)

			// Read captured output
			var stdoutBuf bytes.Buffer
			if _, err := stdoutBuf.ReadFrom(r); err != nil {
				t.Fatalf("failed to read stdout: %v", err)
			}

			var stderrBuf bytes.Buffer
			if _, err := stderrBuf.ReadFrom(errR); err != nil {
				t.Fatalf("failed to read stderr: %v", err)
			}

			allOutput := stdoutBuf.String() + stderrBuf.String() + logBuf.String()

			// Should not return error (PrintError is called but command returns nil)
			if err != nil {
				t.Errorf("unexpected error for malicious action: %v", err)
			}

			// Should contain error message about invalid action
			if !strings.Contains(allOutput, "invalid service action") {
				t.Errorf("expected error message for malicious action, got output: %q", allOutput)
			}

			// Verify that the mock runner was not called (no actual command execution)
			if len(mock.GetCalls()) > 0 {
				t.Errorf("malicious action should not have executed any commands, but got calls: %v", mock.GetCalls())
			}
		})
	}
}

// TestServiceCmdValidActionsOnly ensures only valid actions are accepted
func TestServiceCmdValidActionsOnly(t *testing.T) {
	validActions := []string{"start", "stop", "restart", "status", "reload", "enable", "disable"}
	invalidActions := []string{"invalid", "badaction", "test", "debug", "config", "init"}

	// Save original checker and set up mock with privileges
	originalChecker := fail2ban.GetSudoChecker()
	defer fail2ban.SetSudoChecker(originalChecker)
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)

	// Create mock runner
	mock := &fail2ban.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}

	// Set up responses only for valid actions
	for _, action := range validActions {
		command := "sudo service fail2ban " + action
		mock.SetResponse(command, []byte("Action "+action+" completed"))
	}

	fail2ban.SetRunner(mock)
	config := &Config{Format: "plain"}

	// Test valid actions
	for _, action := range validActions {
		t.Run("valid_action_"+action, func(t *testing.T) {
			cmd := ServiceCmd(config)

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			cmd.SetArgs([]string{action})
			err := cmd.Execute()

			// Restore stdout
			if err := w.Close(); err != nil {
				t.Fatalf("failed to close writer: %v", err)
			}
			os.Stdout = oldStdout

			var stdoutBuf bytes.Buffer
			if _, err := stdoutBuf.ReadFrom(r); err != nil {
				t.Fatalf("failed to read output: %v", err)
			}
			output := stdoutBuf.String()

			if err != nil {
				t.Errorf("valid action %q should not fail: %v", action, err)
			}

			expectedOutput := "Action " + action + " completed"
			if !strings.Contains(output, expectedOutput) {
				t.Errorf("valid action %q should execute, expected %q in output: %q", action, expectedOutput, output)
			}
		})
	}

	// Test invalid actions
	for _, action := range invalidActions {
		t.Run("invalid_action_"+action, func(t *testing.T) {
			cmd := ServiceCmd(config)

			// Capture stderr where PrintError writes
			oldStderr := os.Stderr
			errR, errW, _ := os.Pipe()
			os.Stderr = errW

			// Capture logger output
			var logBuf bytes.Buffer
			originalLogOutput := Logger.Out
			Logger.SetOutput(&logBuf)

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			cmd.SetArgs([]string{action})
			err := cmd.Execute()

			// Close writers and restore
			if err := w.Close(); err != nil {
				t.Fatalf("failed to close stdout writer: %v", err)
			}
			if err := errW.Close(); err != nil {
				t.Fatalf("failed to close stderr writer: %v", err)
			}
			os.Stdout = oldStdout
			os.Stderr = oldStderr
			Logger.SetOutput(originalLogOutput)

			// Read captured output
			var stdoutBuf bytes.Buffer
			if _, err := stdoutBuf.ReadFrom(r); err != nil {
				t.Fatalf("failed to read stdout: %v", err)
			}

			var stderrBuf bytes.Buffer
			if _, err := stderrBuf.ReadFrom(errR); err != nil {
				t.Fatalf("failed to read stderr: %v", err)
			}

			allOutput := stdoutBuf.String() + stderrBuf.String() + logBuf.String()

			if err != nil {
				t.Errorf("invalid action %q should not return error (PrintError is used): %v", action, err)
			}

			if !strings.Contains(allOutput, "invalid service action") {
				t.Errorf("invalid action %q should show error message, got output: %q", action, allOutput)
			}
		})
	}
}

// BenchmarkServiceCmd benchmarks the service command execution
func BenchmarkServiceCmd(b *testing.B) {
	// Save original checker and set up mock with privileges
	originalChecker := fail2ban.GetSudoChecker()
	defer fail2ban.SetSudoChecker(originalChecker)
	mockChecker := fail2ban.NewMockSudoCheckerWithPrivileges(true)
	fail2ban.SetSudoChecker(mockChecker)

	mock := &fail2ban.MockRunner{
		Responses: make(map[string][]byte),
		Errors:    make(map[string]error),
	}

	mock.SetResponse("sudo service fail2ban status", []byte("fail2ban is running"))
	fail2ban.SetRunner(mock)

	config := &Config{Format: "plain"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := ServiceCmd(config)

		// Capture stdout since PrintOutput writes to os.Stdout
		oldStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		cmd.SetArgs([]string{"status"})
		if err := cmd.Execute(); err != nil {
			b.Fatalf("execute failed: %v", err)
		}

		// Restore stdout
		if err := w.Close(); err != nil {
			b.Fatalf("failed to close writer: %v", err)
		}
		os.Stdout = oldStdout

		// Read and discard output
		var stdoutBuf bytes.Buffer
		if _, err := stdoutBuf.ReadFrom(r); err != nil {
			b.Fatalf("failed to read output: %v", err)
		}
	}
}
