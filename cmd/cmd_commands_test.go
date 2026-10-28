package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

func TestMain(m *testing.M) {
	Logger.SetOutput(io.Discard)

	// Set up mock environment for all tests
	_, cleanup := fail2ban.SetupMockEnvironment(&testingT{})
	defer cleanup()

	code := m.Run()

	os.Exit(code)
}

// testingT implements TestingInterface for TestMain
type testingT struct{}

func (t *testingT) Helper() {}
func (t *testingT) Fatalf(format string, args ...any) {
	fmt.Printf("TestMain setup fatal: "+format+"\n", args...)
}
func (t *testingT) Skipf(format string, args ...any) {
	fmt.Printf("TestMain setup skip: "+format+"\n", args...)
}
func (t *testingT) TempDir() string { return os.TempDir() }

// All common test helpers are now in test_helpers.go to eliminate duplication

// Helper function to set up commands (mimics the real cmd package)

func TestListJailsCommand(t *testing.T) {
	tests := []struct {
		name       string
		jails      []string
		wantOutput string
		wantError  bool
	}{
		{
			name:       "list single jail",
			jails:      []string{"sshd"},
			wantOutput: "sshd\n",
			wantError:  false,
		},
		{
			name:       "list multiple jails",
			jails:      []string{"sshd", "apache", "nginx"},
			wantOutput: "apache nginx sshd\n", // alphabetical order
			wantError:  false,
		},
		{
			name:       "list no jails",
			jails:      []string{},
			wantOutput: "\n",
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			NewCommandTest(t, "list-jails").
				WithSetup(func(mock *fail2ban.MockClient) {
					setMockJails(mock, tt.jails)
				}).
				ExpectSuccess().
				ExpectExactOutput(tt.wantOutput).
				Run()
		})
	}
}

// TestListJailsCommandJSON pins that list-jails honors --format json; it used
// to print the space-joined plain list regardless of the format flag.
func TestListJailsCommandJSON(t *testing.T) {
	NewCommandTest(t, "list-jails").
		WithSetup(func(mock *fail2ban.MockClient) {
			setMockJails(mock, []string{"sshd", "apache"})
		}).
		WithJSONFormat().
		ExpectSuccess().
		ExpectExactOutput("[\n  \"apache\",\n  \"sshd\"\n]\n").
		Run()
}

func TestStatusCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		jails      []string
		statusAll  string
		statusJail map[string]string
		wantOutput string
		wantError  bool
	}{
		{
			name:       "status all",
			args:       []string{"all"},
			jails:      []string{"sshd"},
			statusAll:  "Status for all jails\n",
			wantOutput: "Status for all jails\n",
			wantError:  false,
		},
		{
			name:       "status specific jail",
			args:       []string{"sshd"},
			jails:      []string{"sshd"},
			statusJail: map[string]string{"sshd": "Status for sshd jail\n"},
			wantOutput: "Status for sshd jail\n",
			wantError:  false,
		},
		{
			name:       "status nonexistent jail",
			args:       []string{"nonexistent"},
			jails:      []string{"sshd"},
			wantOutput: "Error: jail 'nonexistent' not found",
			wantError:  true,
		},
		{
			name:  "status no args shows usage",
			args:  []string{},
			jails: []string{"sshd"},
			wantOutput: "Usage: status [all|<jail>] status all   (show all jails)\n" +
				"       status [all|<jail>] status <jail> (show specific jail)\nAvailable jails: sshd\n",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertStatusCommandCase(t, tt.args, tt.jails, tt.statusAll,
				tt.statusJail, tt.wantOutput, tt.wantError)
		})
	}
}

// assertStatusCommandCase runs a single TestStatusCommand table case.
func assertStatusCommandCase(t *testing.T, args, jails []string, statusAll string,
	statusJail map[string]string, wantOutput string, wantError bool) {
	t.Helper()
	builder := NewCommandTest(t, "status").
		WithArgs(args...).
		WithSetup(func(mock *fail2ban.MockClient) {
			setMockJails(mock, jails)
			if statusAll != "" {
				mock.StatusAllData = statusAll
			}
			if statusJail != nil {
				mock.StatusJailData = statusJail
			}
		})

	if wantError {
		builder.ExpectError()
	} else {
		builder.ExpectSuccess()
	}

	if wantOutput != "" {
		builder.ExpectOutput(wantOutput)
	}

	builder.Run()
}

func TestBannedCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		banRecords []fail2ban.BanRecord
		wantOutput string
		wantError  bool
	}{
		{
			name: "show banned IPs",
			args: []string{},
			banRecords: []fail2ban.BanRecord{
				{Jail: "sshd", IP: "192.168.1.100", Remaining: "01:30:00"},
				{Jail: "apache", IP: "192.168.1.101", Remaining: "02:15:30"},
			},
			wantOutput: "sshd | 192.168.1.100 | 01:30:00 remaining\napache | 192.168.1.101 | 02:15:30 remaining\n",
			wantError:  false,
		},
		{
			name:       "show banned IPs with specific jail",
			args:       []string{"sshd"},
			banRecords: []fail2ban.BanRecord{},
			wantOutput: "",
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Using new mock builder pattern for cleaner setup
			mockBuilder := NewMockClientBuilder()
			for _, record := range tt.banRecords {
				mockBuilder.WithBanRecord(record.Jail, record.IP, record.Remaining)
			}

			NewCommandTest(t, "banned").
				WithArgs(tt.args...).
				WithMockBuilder(mockBuilder).
				ExpectSuccess().
				ExpectExactOutput(tt.wantOutput).
				Run()
		})
	}
}

// ipCommandTestCase describes a ban/unban command test scenario.
type ipCommandTestCase struct {
	name        string
	args        []string
	jails       []string
	banResults  map[string]map[string]int
	setupBanned bool
	wantOutput  string
	wantError   bool
}

// runIPCommandTests runs the shared ban/unban command test harness for the
// given command ("ban" or "unban").
func runIPCommandTests(t *testing.T, command string, tests []ipCommandTestCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewCommandTest(t, command).
				WithArgs(tt.args...).
				WithSetup(func(mock *fail2ban.MockClient) {
					setMockJails(mock, tt.jails)
					mock.BanResults = tt.banResults
					if tt.setupBanned {
						_, _ = mock.BanIPWithContext(context.Background(), "192.168.1.100", "sshd")
					}
				})

			if tt.wantError {
				builder.ExpectError().ExpectOutput(tt.wantOutput)
			} else {
				builder.ExpectSuccess().ExpectOutput(tt.wantOutput)
			}

			builder.Run()
		})
	}
}

func TestBanCommand(t *testing.T) {
	tests := []ipCommandTestCase{
		{
			name:       "ban IP without jail specified",
			args:       []string{"192.168.1.100"},
			jails:      []string{"sshd", "apache"},
			banResults: map[string]map[string]int{"192.168.1.100": {"sshd": 0, "apache": 0}},
			wantOutput: "Banned 192.168.1.100 in apache\nBanned 192.168.1.100 in sshd\n", // alphabetical order
			wantError:  false,
		},
		{
			name:       "ban IP with specific jail",
			args:       []string{"192.168.1.100", "sshd"},
			jails:      []string{"sshd"},
			banResults: map[string]map[string]int{"192.168.1.100": {"sshd": 0}},
			wantOutput: "Banned 192.168.1.100 in sshd\n",
			wantError:  false,
		},
		{
			name:        "ban IP already banned",
			args:        []string{"192.168.1.100", "sshd"},
			jails:       []string{"sshd"},
			setupBanned: true,
			wantOutput:  "Already banned 192.168.1.100 in sshd\n",
			wantError:   false,
		},
		{
			name:       "ban command without IP",
			args:       []string{},
			wantOutput: "Error: IP address required",
			wantError:  true,
		},
	}

	runIPCommandTests(t, "ban", tests)
}

func TestUnbanCommand(t *testing.T) {
	tests := []ipCommandTestCase{
		{
			name:        "unban IP with specific jail",
			args:        []string{"192.168.1.100", "sshd"},
			jails:       []string{"sshd"},
			setupBanned: true,
			wantOutput:  "Unbanned 192.168.1.100 in sshd\n",
			wantError:   false,
		},
		{
			name:        "unban IP already unbanned",
			args:        []string{"192.168.1.100", "sshd"},
			jails:       []string{"sshd"},
			setupBanned: false,
			wantOutput:  "Already unbanned 192.168.1.100 in sshd\n",
			wantError:   false,
		},
		{
			name:       "unban command without IP",
			args:       []string{},
			wantOutput: "Error: IP address required",
			wantError:  true,
		},
	}

	runIPCommandTests(t, "unban", tests)
}

func TestTestIPCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		setupBans  map[string][]string // jail -> IPs to ban
		wantOutput string
		wantError  bool
	}{
		{
			name:       "test IP not banned",
			args:       []string{"192.168.1.100"},
			setupBans:  map[string][]string{}, // no bans
			wantOutput: "IP 192.168.1.100 is not banned",
			wantError:  false,
		},
		{
			name:       "test IP banned in one jail",
			args:       []string{"192.168.1.100"},
			setupBans:  map[string][]string{"sshd": {"192.168.1.100"}},
			wantOutput: "IP 192.168.1.100 is banned in: [sshd]\n",
			wantError:  false,
		},
		{
			name:       "test IP banned in multiple jails",
			args:       []string{"192.168.1.100"},
			setupBans:  map[string][]string{"sshd": {"192.168.1.100"}, "apache": {"192.168.1.100"}},
			wantOutput: "IP 192.168.1.100 is banned in: [apache sshd]\n", // alphabetical order
			wantError:  false,
		},
		{
			name:       "test command without IP",
			args:       []string{},
			wantOutput: "Error: IP address required",
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewCommandTest(t, "test").
				WithArgs(tt.args...).
				WithSetup(func(mock *fail2ban.MockClient) {
					// Set up bans
					for jail, ips := range tt.setupBans {
						for _, ip := range ips {
							_, _ = mock.BanIPWithContext(context.Background(), ip, jail)
						}
					}
				})

			if tt.wantError {
				builder.ExpectError().ExpectOutput(tt.wantOutput)
			} else {
				builder.ExpectSuccess().ExpectOutput(tt.wantOutput)
			}

			builder.Run()
		})
	}
}

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
				WithSetup(func(mock *fail2ban.MockClient) {
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
		WithSetup(func(mock *fail2ban.MockClient) {
			mock.LogLines = []string{"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100"}
		}).
		ExpectSuccess().
		ExpectExactOutput("[\n  \"2024-01-01 12:00:00 [sshd] Ban 192.168.1.100\"\n]\n").
		Run()

	NewCommandTest(t, "logs").
		WithArgs("sshd", "9.9.9.9").
		WithJSONFormat().
		WithSetup(func(mock *fail2ban.MockClient) {
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

// TestTestFilterCommandAcceptsListedNames pins that test-filter validates with
// the client's filter rules: a name test-filter lists (e.g. "foo.bar") must
// not be rejected by a stricter cmd-only check.
func TestTestFilterCommandAcceptsListedNames(t *testing.T) {
	mock := NewMockClient()
	mock.Filters = []string{"foo.bar"}
	mock.FilterTests = map[string]string{"foo.bar": "Success: 1 matched"}
	NewCommandTest(t, "test-filter").
		WithArgs("foo.bar").
		WithMockClient(mock).
		ExpectSuccess().
		ExpectOutput("Success: 1 matched").
		Run()

	NewCommandTest(t, "test-filter").
		WithArgs("../etc/passwd").
		WithMockClient(mock).
		ExpectError().
		Run()
}

func TestTestFilterCommand(t *testing.T) {
	t.Run("configured filter succeeds", func(t *testing.T) {
		mock := NewMockClient()
		mock.FilterTests = map[string]string{"sshd": "Success: 3 matched"}
		NewCommandTest(t, "test-filter").
			WithArgs("sshd").
			WithMockClient(mock).
			ExpectSuccess().
			ExpectOutput("Success: 3 matched").
			Run()
	})

	t.Run("unknown filter errors", func(t *testing.T) {
		mock := NewMockClient()
		NewCommandTest(t, "test-filter").
			WithArgs("nosuchfilter").
			WithMockClient(mock).
			ExpectError().
			Run()
	})
}

func TestVersionCommand(t *testing.T) {
	wantOutput := fmt.Sprintf("f2b version %s\n", Version)

	NewCommandTest(t, "version").
		ExpectSuccess().
		ExpectExactOutput(wantOutput).
		Run()
}

func TestCommandErrorHandling(t *testing.T) {
	tests := []struct {
		name         string
		command      string
		args         []string
		setupMock    func(*fail2ban.MockClient)
		wantError    bool
		wantErrorMsg string
	}{
		{
			name:    "ban IP error",
			command: "ban",
			args:    []string{"192.168.1.100", "sshd"},
			setupMock: func(m *fail2ban.MockClient) {
				setMockJails(m, []string{"sshd"})
				m.SetBanError("sshd", "192.168.1.100", fmt.Errorf("ban failed"))
			},
			wantError:    true,
			wantErrorMsg: "ban failed",
		},
		{
			name:    "unban IP error",
			command: "unban",
			args:    []string{"192.168.1.100", "sshd"},
			setupMock: func(m *fail2ban.MockClient) {
				setMockJails(m, []string{"sshd"})
				m.SetUnbanError("sshd", "192.168.1.100", fmt.Errorf("unban failed"))
			},
			wantError:    true,
			wantErrorMsg: "unban failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewCommandTest(t, tt.command).
				WithArgs(tt.args...).
				WithSetup(tt.setupMock).
				ExpectError().
				Run()

			// Validate specific error message
			if tt.wantErrorMsg != "" && !strings.Contains(result.Error.Error(), tt.wantErrorMsg) {
				t.Errorf("expected error to contain %q, got %q", tt.wantErrorMsg, result.Error.Error())
			}
		})
	}
}

// TestCommandInvalidArguments tests commands with invalid arguments
func TestCommandInvalidArguments(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		args      []string
		wantError bool
	}{
		{
			name:      "ban without IP",
			command:   "ban",
			args:      []string{},
			wantError: true,
		},
		{
			name:      "unban without IP",
			command:   "unban",
			args:      []string{},
			wantError: true,
		},
		{
			name:      "test without IP",
			command:   "test",
			args:      []string{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			NewCommandTest(t, tt.command).
				WithArgs(tt.args...).
				ExpectError().
				Run()
		})
	}
}
