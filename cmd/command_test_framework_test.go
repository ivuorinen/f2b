// Package cmd provides a comprehensive testing framework for CLI commands.
// This package offers fluent testing utilities, mock builders, and standardized
// test patterns to ensure robust testing of f2b command functionality.
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ivuorinen/f2b/constants"

	"github.com/ivuorinen/f2b/fail2ban"
)

// CommandTestResult represents the result of a command execution
// resultTestingT is the subset of *testing.T the assert methods use. Tests
// inject a recording implementation to verify the failure paths — the
// direction a plain green-path test can't check.
type resultTestingT interface {
	Helper()
	Fatalf(format string, args ...any)
}

// CommandTestResult carries a command's captured output and error together
// with the testing handle its Assert* methods report through.
type CommandTestResult struct {
	Output string
	Error  error
	t      resultTestingT
	name   string
}

// CommandTestBuilder provides a fluent interface for testing commands
type CommandTestBuilder struct {
	t              *testing.T
	name           string
	command        string
	args           []string
	mockClient     *fail2ban.MockClient
	config         *Config
	expectError    bool
	expectedOut    string
	expectedOutSet bool
	exactMatch     bool
	setupFunc      func(*fail2ban.MockClient)
	environment    *TestEnvironment
}

// TestEnvironment manages test environment setup and cleanup
type TestEnvironment struct {
	originalChecker fail2ban.SudoChecker
	originalRunner  fail2ban.Runner
	originalStdout  *os.File
	stdoutReader    *os.File
	stdoutWriter    *os.File
	cleanup         []func()
}

// NewTestEnvironment creates a new test environment manager
func NewTestEnvironment() *TestEnvironment {
	return &TestEnvironment{
		cleanup: make([]func(), 0),
	}
}

// WithPrivileges sets up sudo checker with specified privileges
func (env *TestEnvironment) WithPrivileges(hasPrivileges bool) *TestEnvironment {
	env.originalChecker = fail2ban.GetSudoChecker()
	mockChecker := &fail2ban.MockSudoChecker{
		MockHasPrivileges:     hasPrivileges,
		ExplicitPrivilegesSet: true,
	}
	fail2ban.SetSudoChecker(mockChecker)
	env.cleanup = append(env.cleanup, func() {
		fail2ban.SetSudoChecker(env.originalChecker)
	})
	return env
}

// WithMockRunner sets up a mock runner with common responses
func (env *TestEnvironment) WithMockRunner() *TestEnvironment {
	env.originalRunner = fail2ban.GetRunner()
	mockRunner := fail2ban.NewMockRunner()
	// Set up common responses
	mockRunner.SetResponse(constants.MockCommandVersion, []byte(constants.VersionOutput))
	mockRunner.SetResponse(constants.MockCommandPing, []byte(constants.PingOutput))
	mockRunner.SetResponse(constants.MockCommandStatus, []byte(constants.StatusOutput))
	mockRunner.SetResponse("sudo service fail2ban status", []byte("● fail2ban.service - Fail2Ban Service"))
	fail2ban.SetRunner(mockRunner)

	env.cleanup = append(env.cleanup, func() {
		fail2ban.SetRunner(env.originalRunner)
	})
	return env
}

// WithStdoutCapture captures stdout for testing output
func (env *TestEnvironment) WithStdoutCapture() *TestEnvironment {
	env.originalStdout = os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		// Test scaffolding must fail loudly: silently continuing with nil
		// fields made every later stdout assertion vacuously pass.
		panic(fmt.Sprintf("WithStdoutCapture: os.Pipe failed: %v", err))
	}
	env.stdoutReader = r
	env.stdoutWriter = w
	os.Stdout = w

	env.cleanup = append(env.cleanup, func() {
		os.Stdout = env.originalStdout
		if env.stdoutWriter != nil {
			_ = env.stdoutWriter.Close()
		}
		if env.stdoutReader != nil {
			_ = env.stdoutReader.Close()
		}
	})
	return env
}

// Cleanup restores the original environment
func (env *TestEnvironment) Cleanup() {
	for _, v := range slices.Backward(env.cleanup) {
		v()
	}
}

// ReadStdout reads the captured stdout content
func (env *TestEnvironment) ReadStdout() string {
	if env.stdoutWriter == nil || env.stdoutReader == nil {
		return ""
	}

	// Close writer if not already closed
	if env.stdoutWriter != nil {
		_ = env.stdoutWriter.Close()
		env.stdoutWriter = nil // Prevent multiple closures
	}

	// Use io.ReadAll for dynamic buffer reading
	data, err := io.ReadAll(env.stdoutReader)
	if err != nil {
		// Fail loudly rather than returning "" that vacuously satisfies
		// empty-output assertions.
		panic(fmt.Sprintf("ReadStdout: reading captured stdout failed: %v", err))
	}
	return string(data)
}

// NewCommandTest creates a new command test builder
func NewCommandTest(t *testing.T, commandName string) *CommandTestBuilder {
	t.Helper()
	return &CommandTestBuilder{
		t:       t,
		name:    commandName,
		command: commandName,
		args:    make([]string, 0),
		config: &Config{
			Format:          PlainFormat,
			CommandTimeout:  constants.DefaultCommandTimeout,
			FileTimeout:     constants.DefaultFileTimeout,
			ParallelTimeout: constants.DefaultParallelTimeout,
		},
	}
}

// WithName sets the test name for better error reporting
func (ctb *CommandTestBuilder) WithName(name string) *CommandTestBuilder {
	ctb.name = name
	return ctb
}

// WithArgs sets the command arguments
func (ctb *CommandTestBuilder) WithArgs(args ...string) *CommandTestBuilder {
	ctb.args = args
	return ctb
}

// WithMockClient sets the mock client for the test
func (ctb *CommandTestBuilder) WithMockClient(mock *fail2ban.MockClient) *CommandTestBuilder {
	ctb.mockClient = mock
	return ctb
}

// WithJSONFormat sets the output format to JSON
func (ctb *CommandTestBuilder) WithJSONFormat() *CommandTestBuilder {
	if ctb.config == nil {
		ctb.config = &Config{}
	}
	ctb.config.Format = JSONFormat
	return ctb
}

// WithSetup provides a function to set up the mock client with specific data
func (ctb *CommandTestBuilder) WithSetup(setupFunc func(*fail2ban.MockClient)) *CommandTestBuilder {
	ctb.setupFunc = setupFunc
	return ctb
}

// WithServiceSetup provides a function to set up mock runner for service commands
func (ctb *CommandTestBuilder) WithServiceSetup(setupFunc func(*fail2ban.MockRunner)) *CommandTestBuilder {
	ctb.setupFunc = func(_ *fail2ban.MockClient) {
		// Save and restore the package-global sudo checker and runner so this
		// setup does not leak mock state into later tests (which made outcomes
		// order-dependent under `go test -shuffle=on`).
		origChecker := fail2ban.GetSudoChecker()
		origRunner := fail2ban.GetRunner()
		ctb.t.Cleanup(func() {
			fail2ban.SetSudoChecker(origChecker)
			fail2ban.SetRunner(origRunner)
		})

		// Set up sudo checker
		mockChecker := &fail2ban.MockSudoChecker{
			MockHasPrivileges:     true,
			ExplicitPrivilegesSet: true,
		}
		fail2ban.SetSudoChecker(mockChecker)

		// Create and set up mock runner
		mockRunner := &fail2ban.MockRunner{
			Responses: make(map[string][]byte),
			Errors:    make(map[string]error),
		}
		setupFunc(mockRunner)
		fail2ban.SetRunner(mockRunner)
	}
	return ctb
}

// WithEnvironment sets the test environment
func (ctb *CommandTestBuilder) WithEnvironment(env *TestEnvironment) *CommandTestBuilder {
	ctb.environment = env
	return ctb
}

// ExpectError indicates that the command should fail
func (ctb *CommandTestBuilder) ExpectError() *CommandTestBuilder {
	ctb.expectError = true
	return ctb
}

// ExpectSuccess indicates that the command should succeed
func (ctb *CommandTestBuilder) ExpectSuccess() *CommandTestBuilder {
	ctb.expectError = false
	return ctb
}

// ExpectOutput sets the expected output substring
func (ctb *CommandTestBuilder) ExpectOutput(expectedOut string) *CommandTestBuilder {
	ctb.expectedOut = expectedOut
	ctb.expectedOutSet = true
	return ctb
}

// ExpectExactOutput sets the expected output for exact matching
func (ctb *CommandTestBuilder) ExpectExactOutput(expectedOut string) *CommandTestBuilder {
	ctb.expectedOut = expectedOut
	ctb.exactMatch = true
	ctb.expectedOutSet = true
	return ctb
}

// Run executes the command test and performs all validations
func (ctb *CommandTestBuilder) Run() *CommandTestResult {
	ctb.t.Helper()

	// Set up default mock client if none provided
	if ctb.mockClient == nil {
		ctb.mockClient = fail2ban.NewMockClient()
	}

	// Apply setup function if provided
	if ctb.setupFunc != nil {
		ctb.setupFunc(ctb.mockClient)
	}

	// Execute the command
	output, err := ctb.executeCommand()

	// Create result
	result := &CommandTestResult{
		Output: output,
		Error:  err,
		t:      ctb.t,
		name:   ctb.name,
	}

	// Perform basic validations
	result.AssertError(ctb.expectError)

	if ctb.expectedOutSet {
		if ctb.exactMatch {
			result.AssertExactOutput(ctb.expectedOut)
		} else {
			result.AssertContains(ctb.expectedOut)
		}
	}

	return result
}

// executeCommand runs the actual command with the configured parameters
func (ctb *CommandTestBuilder) executeCommand() (string, error) {
	var cmd *cobra.Command

	switch ctb.command {
	case "ban":
		cmd = BanCmd(ctb.mockClient, ctb.config)
	case "unban":
		cmd = UnbanCmd(ctb.mockClient, ctb.config)
	case "status":
		cmd = StatusCmd(ctb.mockClient, ctb.config)
	case constants.CLICmdListJails:
		cmd = ListJailsCmd(ctb.mockClient, ctb.config)
	case "banned":
		cmd = BannedCmd(ctb.mockClient, ctb.config)
	case "test":
		cmd = TestIPCmd(ctb.mockClient, ctb.config)
	case "logs":
		cmd = LogsCmd(ctb.mockClient, ctb.config)
	case "test-filter":
		cmd = TestFilterCmd(ctb.mockClient, ctb.config)
	case constants.ServiceCommand:
		cmd = ServiceCmd(ctb.config)
	case constants.CLICmdVersion:
		cmd = VersionCmd(ctb.config)
	default:
		return "", fmt.Errorf("unknown command: %s", ctb.command)
	}

	// For service commands, we need to capture os.Stdout since PrintOutput writes directly to it
	if ctb.command == constants.ServiceCommand {
		return ctb.executeServiceCommand(cmd)
	}

	// Execute regular commands. Capture os.Stdout/os.Stderr as well as the
	// command's own buffers, since PrintOutput/PrintError write directly to the
	// process streams (and cobra's error output is silenced).
	var outBuf, errBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(ctb.args)

	captured, err := captureStdoutStderr(cmd.Execute)
	output := captured + outBuf.String() + errBuf.String()

	return output, err
}

// captureStdoutStderr redirects os.Stdout and os.Stderr into pipes, runs fn,
// and returns everything written to them. The pipes are drained by goroutines
// started before fn runs, so output larger than the OS pipe buffer cannot
// deadlock the command inside fn.
//
// Mutates the process-global os.Stdout/os.Stderr: tests routed through this
// helper must not use t.Parallel().
func captureStdoutStderr(fn func() error) (string, error) {
	oldStdout, oldStderr := os.Stdout, os.Stderr
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		return "", fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	os.Stdout, os.Stderr = stdoutW, stderrW

	var wg sync.WaitGroup
	var outBuf, errBuf bytes.Buffer
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = outBuf.ReadFrom(stdoutR) }()
	go func() { defer wg.Done(); _, _ = errBuf.ReadFrom(stderrR) }()

	runErr := fn()

	_ = stdoutW.Close()
	_ = stderrW.Close()
	wg.Wait()
	os.Stdout, os.Stderr = oldStdout, oldStderr

	return outBuf.String() + errBuf.String(), runErr
}

// executeServiceCommand handles service command execution with stdout/stderr capture
func (ctb *CommandTestBuilder) executeServiceCommand(cmd *cobra.Command) (string, error) {
	var cmdErrBuf bytes.Buffer
	cmd.SetErr(&cmdErrBuf)
	cmd.SetArgs(ctb.args)

	captured, err := captureStdoutStderr(cmd.Execute)
	return captured + cmdErrBuf.String(), err
}

// AssertError validates the error state
func (result *CommandTestResult) AssertError(expectError bool) *CommandTestResult {
	result.t.Helper()
	if expectError && result.Error == nil {
		result.t.Fatalf(constants.ErrTestExpectedError, result.name)
	}
	if !expectError && result.Error != nil {
		result.t.Fatalf(constants.ErrTestUnexpectedWithOutput, result.name, result.Error, result.Output)
	}
	return result
}

// AssertContains validates that output contains expected text
func (result *CommandTestResult) AssertContains(expected string) *CommandTestResult {
	result.t.Helper()
	if !strings.Contains(result.Output, expected) {
		result.t.Fatalf(constants.ErrTestExpectedOutput, result.name, expected, result.Output)
	}
	return result
}

// AssertNotContains validates that output does not contain specified text
func (result *CommandTestResult) AssertNotContains(notExpected string) *CommandTestResult {
	result.t.Helper()
	if strings.Contains(result.Output, notExpected) {
		result.t.Fatalf("%s: expected output to not contain %q, got: %s", result.name, notExpected, result.Output)
	}
	return result
}

// AssertExactOutput validates exact output match
func (result *CommandTestResult) AssertExactOutput(expected string) *CommandTestResult {
	result.t.Helper()
	if result.Output != expected {
		result.t.Fatalf("%s: expected exact output %q, got %q", result.name, expected, result.Output)
	}
	return result
}

// checkJSONFieldValue validates that a JSON field value matches the expected string.
func (result *CommandTestResult) checkJSONFieldValue(val any, fieldName, expected string) {
	result.t.Helper()
	if fmt.Sprintf("%v", val) != expected {
		result.t.Fatalf(constants.ErrTestJSONFieldMismatch, result.name, fieldName, expected, val)
	}
}

// failMissingJSONField reports a missing JSON field with context.
func (result *CommandTestResult) failMissingJSONField(fieldName, context string) {
	result.t.Helper()
	result.t.Fatalf("%s: JSON field %q not found%s: %s", result.name, fieldName, context, result.Output)
}

// AssertJSONField validates a specific field in JSON output
func (result *CommandTestResult) AssertJSONField(fieldPath, expected string) *CommandTestResult {
	result.t.Helper()

	var data any
	if err := json.Unmarshal([]byte(result.Output), &data); err != nil {
		result.t.Fatalf("%s: failed to parse JSON output: %v, output: %s", result.name, err, result.Output)
	}

	// Simple field path parsing (can be enhanced later)
	// For now, support simple paths like "$.field", "[0].field" or direct field names
	fieldName := strings.TrimPrefix(fieldPath, "$.")

	switch v := data.(type) {
	case map[string]any:
		if val, ok := v[fieldName]; ok {
			result.checkJSONFieldValue(val, fieldName, expected)
		} else {
			result.failMissingJSONField(fieldName, " in output")
		}
	case []any:
		// Handle array case - look in first element
		if len(v) > 0 {
			if firstItem, ok := v[0].(map[string]any); ok {
				if val, ok := firstItem[fieldName]; ok {
					result.checkJSONFieldValue(val, fieldName, expected)
				} else {
					result.failMissingJSONField(fieldName, " in first array element")
				}
			} else {
				result.t.Fatalf("%s: first array element is not an object in output: %s", result.name, result.Output)
			}
		} else {
			result.t.Fatalf("%s: JSON array is empty in output: %s", result.name, result.Output)
		}
	default:
		result.t.Fatalf("%s: expected JSON object or array but got %T in output: %s", result.name, data, result.Output)
	}

	return result
}

// AssertEmpty validates that output is empty
func (result *CommandTestResult) AssertEmpty() *CommandTestResult {
	result.t.Helper()
	if strings.TrimSpace(result.Output) != "" {
		result.t.Fatalf("%s: expected empty output, got: %s", result.name, result.Output)
	}
	return result
}

// AssertNotEmpty validates that output is not empty
func (result *CommandTestResult) AssertNotEmpty() *CommandTestResult {
	result.t.Helper()
	if strings.TrimSpace(result.Output) == "" {
		result.t.Fatalf("%s: expected non-empty output", result.name)
	}
	return result
}

// MockClientBuilder provides a fluent interface for building complex mock configurations
type MockClientBuilder struct {
	client     *fail2ban.MockClient
	jails      []string
	banRecords []fail2ban.BanRecord
	logLines   []string
	responses  map[string]string
	errors     map[string]error
}

// NewMockClientBuilder creates a new mock client builder
func NewMockClientBuilder() *MockClientBuilder {
	return &MockClientBuilder{
		client:    fail2ban.NewMockClient(),
		responses: make(map[string]string),
		errors:    make(map[string]error),
	}
}

// WithJails configures available jails
func (b *MockClientBuilder) WithJails(jails ...string) *MockClientBuilder {
	b.jails = append(b.jails, jails...)
	return b
}

// WithBannedIP marks an IP as already banned in a specific jail.
// MockClient.BanIP reads BanResults[jail][ip] (jail-major); the previous
// [ip][jail] order meant this configuration was never seen by BanIP. Result
// code 1 means "already banned" per the Client contract.
func (b *MockClientBuilder) WithBannedIP(ip, jail string) *MockClientBuilder {
	if b.client.BanResults == nil {
		b.client.BanResults = make(map[string]map[string]int)
	}
	if b.client.BanResults[jail] == nil {
		b.client.BanResults[jail] = make(map[string]int)
	}
	b.client.BanResults[jail][ip] = 1 // 1 = already banned
	return b
}

// WithBanRecord adds a ban record
func (b *MockClientBuilder) WithBanRecord(jail, ip, remaining string) *MockClientBuilder {
	b.banRecords = append(b.banRecords, fail2ban.BanRecord{
		Jail:      jail,
		IP:        ip,
		Remaining: remaining,
	})
	return b
}

// WithLogLine adds a log line
func (b *MockClientBuilder) WithLogLine(logLine string) *MockClientBuilder {
	b.logLines = append(b.logLines, logLine)
	return b
}

// WithStatusResponse sets status response for specific target
func (b *MockClientBuilder) WithStatusResponse(target, response string) *MockClientBuilder {
	if b.client.StatusJailData == nil {
		b.client.StatusJailData = make(map[string]string)
	}
	if target == constants.AllFilter {
		b.client.StatusAllData = response
	} else {
		b.client.StatusJailData[target] = response
	}
	return b
}

// WithBanError sets an error for banning specific IP in jail
func (b *MockClientBuilder) WithBanError(jail, ip string, err error) *MockClientBuilder {
	b.client.SetBanError(jail, ip, err)
	return b
}

// WithUnbanError sets an error for unbanning specific IP in jail
func (b *MockClientBuilder) WithUnbanError(jail, ip string, err error) *MockClientBuilder {
	b.client.SetUnbanError(jail, ip, err)
	return b
}

// WithLogError is not supported by MockClient - logs are returned via LogLines field
// Use WithLogLine to add log entries or modify LogLines directly

// Build creates the configured mock client
func (b *MockClientBuilder) Build() *fail2ban.MockClient {
	// Apply jails
	if len(b.jails) > 0 {
		setMockJails(b.client, b.jails)
	}

	// Apply ban records
	if len(b.banRecords) > 0 {
		b.client.BanRecords = b.banRecords
	}

	// Apply log lines
	if len(b.logLines) > 0 {
		b.client.LogLines = b.logLines
	}

	return b.client
}

// WithMockBuilder configures the test with a MockClientBuilder for advanced mock setup
func (ctb *CommandTestBuilder) WithMockBuilder(builder *MockClientBuilder) *CommandTestBuilder {
	ctb.mockClient = builder.Build()
	return ctb
}
