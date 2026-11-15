package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban/fail2bantest"
)

// titleSequence is an OSC escape that retitles the terminal, as an attacker
// can plant it in a log line through a captured F-ID.
const titleSequence = "\x1b]0;pwned\x07"

// TestPlainLogLinesEscapeControlCharacters pins that plain `logs` and
// `logs-watch` output shows control characters from log lines as visible
// escapes instead of handing them to the terminal. Tab and the newline that
// separates lines stay as they are.
func TestPlainLogLinesEscapeControlCharacters(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  string
	}{
		{"terminal title sequence", []string{"Ban " + titleSequence}, `Ban \x1b]0;pwned\x07`},
		{"carriage return hiding a line", []string{"real\rfake"}, `real\x0dfake`},
		{"UTF-8 encoded C1 CSI", []string{"a\u009b2J"}, `a\x9b2J`},
		{"raw 8-bit C1 CSI byte", []string{"a\x9b2J"}, `a\x9b2J`},
		{"delete", []string{"a\x7fb"}, `a\x7fb`},
		{"tab and non-ASCII text kept", []string{"a\tä"}, "a\tä"},
		{"invalid UTF-8 text byte kept", []string{"caf\xe9"}, "caf\xe9"},
		{"lines stay newline separated", []string{"one", "two"}, "one\ntwo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			require.NoError(t, printLogLines(&out, tt.lines, PlainFormat))
			assert.Equal(t, tt.want+"\n", out.String())
		})
	}
}

// TestJSONLogLinesKeepTheirText pins that JSON output is left alone: the
// encoder escapes control characters, and decoding returns the line unchanged.
func TestJSONLogLinesKeepTheirText(t *testing.T) {
	lines := []string{"Ban " + titleSequence}
	var out bytes.Buffer
	require.NoError(t, printLogLines(&out, lines, JSONFormat))

	assert.NotContains(t, out.String(), "\x1b")
	var decoded []string
	require.NoError(t, json.Unmarshal(out.Bytes(), &decoded))
	assert.Equal(t, lines, decoded)
}

// TestTestFilterOutputEscapesControlCharacters pins the same for test-filter:
// fail2ban-regex echoes the log lines it reads. JSON output keeps the text.
func TestTestFilterOutputEscapesControlCharacters(t *testing.T) {
	result := "Lines: 1\n|  " + titleSequence + "\tmissed\n"
	run := func(format string) string {
		t.Helper()
		client := fail2bantest.NewMockClient()
		client.FilterTests["sshd"] = result
		cmd := TestFilterCmd(client, &Config{Format: format, FileTimeout: time.Second})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"sshd"})
		require.NoError(t, cmd.ExecuteContext(context.Background()))
		return out.String()
	}

	assert.Equal(t, "Lines: 1\n|  \\x1b]0;pwned\\x07\tmissed\n\n", run(PlainFormat))

	var decoded string
	require.NoError(t, json.Unmarshal([]byte(run(JSONFormat)), &decoded))
	assert.Equal(t, result, decoded)
}
