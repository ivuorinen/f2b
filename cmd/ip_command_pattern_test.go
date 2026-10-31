package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOutputOperationResults pins the ban/unban result rendering for both
// output formats.
func TestOutputOperationResults(t *testing.T) {
	tests := []struct {
		name      string
		results   []OperationResult
		format    string
		expectOut string
	}{
		{
			name: "json format output",
			results: []OperationResult{
				{IP: "192.168.1.1", Jail: "sshd", Status: "Banned"},
			},
			format:    JSONFormat,
			expectOut: "[\n  {\n    \"ip\": \"192.168.1.1\",\n    \"jail\": \"sshd\",\n    \"status\": \"Banned\"\n  }\n]\n",
		},
		{
			name: "plain format output",
			results: []OperationResult{
				{IP: "192.168.1.1", Jail: "sshd", Status: "Banned"},
			},
			format:    PlainFormat,
			expectOut: "Banned 192.168.1.1 in sshd\n",
		},
		{
			name: "multiple results",
			results: []OperationResult{
				{IP: "192.168.1.1", Jail: "sshd", Status: "Banned"},
				{IP: "192.168.1.2", Jail: "apache", Status: "Banned"},
			},
			format:    PlainFormat,
			expectOut: "Banned 192.168.1.1 in sshd\nBanned 192.168.1.2 in apache\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			var buf bytes.Buffer
			cmd.SetOut(&buf)

			require.NoError(t, outputOperationResults(cmd, tt.results, tt.format))
			assert.Equal(t, tt.expectOut, buf.String())
		})
	}
}
