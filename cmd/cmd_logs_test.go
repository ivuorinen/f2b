package cmd

import (
	"strconv"
	"testing"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// TestLogsCommand pins plain output to one log line per output line. It used
// to assert the Go-slice rendering ("[a b]" on one line), which locked in the
// defect that made `f2b logs | wc -l` print 1 regardless of matches.
func TestLogsCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		logLines   []string
		wantOutput string
	}{
		{
			name: "show all logs",
			args: []string{},
			logLines: []string{
				"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100",
				"2024-01-01 12:01:00 [apache] Ban 192.168.1.101",
			},
			wantOutput: "2024-01-01 12:00:00 [sshd] Ban 192.168.1.100\n2024-01-01 12:01:00 [apache] Ban 192.168.1.101\n",
		},
		{
			name: "show logs with jail filter",
			args: []string{"sshd"},
			logLines: []string{
				"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100",
				"2024-01-01 12:01:00 [apache] Ban 192.168.1.101",
			},
			wantOutput: "2024-01-01 12:00:00 [sshd] Ban 192.168.1.100\n",
		},
		{
			name:       "show logs with jail and IP filter",
			args:       []string{"sshd", "192.168.1.100"},
			logLines:   []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100"},
			wantOutput: "2024-01-01 12:00:00 [sshd] Ban 192.168.1.100\n",
		},
		{
			name:       "show logs when no logs exist prints nothing",
			args:       []string{},
			logLines:   []string{}, // Explicitly set empty slice
			wantOutput: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			NewCommandTest(t, "logs").
				WithArgs(tt.args...).
				WithSetup(func(mock *fail2bantest.MockClient) {
					mock.LogLines = tt.logLines
				}).
				ExpectSuccess().
				ExpectExactOutput(tt.wantOutput).
				Run()
		})
	}
}

// TestLogsCommandJSONIsArray pins that JSON output stays an array, including
// [] for no matches.
func TestLogsCommandJSONIsArray(t *testing.T) {
	NewCommandTest(t, "logs").
		WithArgs("sshd").
		WithJSONFormat().
		WithSetup(func(mock *fail2bantest.MockClient) {
			mock.LogLines = []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100"}
		}).
		ExpectSuccess().
		ExpectExactOutput("[\n  \"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100\"\n]\n").
		Run()

	NewCommandTest(t, "logs").
		WithArgs("sshd", "9.9.9.9").
		WithJSONFormat().
		WithSetup(func(mock *fail2bantest.MockClient) {
			mock.LogLines = []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100"}
		}).
		ExpectSuccess().
		ExpectExactOutput("[]\n").
		Run()
}

// TestLogsCommandClampsLimit pins the --limit clamp: a value above
// MaxLogLinesLimit reaches the client as exactly MaxLogLinesLimit.
func TestLogsCommandClampsLimit(t *testing.T) {
	mock := NewMockClient()
	NewCommandTest(t, "logs").
		WithArgs("--limit", strconv.Itoa(constants.MaxLogLinesLimit+1)).
		WithMockClient(mock).
		ExpectSuccess().
		Run()
	if mock.LastLogLimit != constants.MaxLogLinesLimit {
		t.Errorf("forwarded limit = %d, want %d", mock.LastLogLimit, constants.MaxLogLinesLimit)
	}
}
