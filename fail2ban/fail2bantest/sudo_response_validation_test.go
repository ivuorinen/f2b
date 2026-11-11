package fail2bantest

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSudoResponseDoesNotBypassValidation pins that MockRunner validates the
// command and its arguments before returning a registered sudo response, as
// OSRunner does: otherwise a test passes on input production refuses.
func TestSudoResponseDoesNotBypassValidation(t *testing.T) {
	tests := map[string]struct {
		name string
		args []string
		want string
	}{
		"injection argument": {
			"fail2ban-client",
			[]string{"set", "sshd", "banip", "1.2.3.4;id"},
			"argument validation failed",
		},
		"invalid address": {
			"fail2ban-client",
			[]string{"set", "sshd", "banip", "999.1.1.1"},
			"argument validation failed",
		},
		"untrusted path": {"/tmp/evil/fail2ban-client", []string{"status"}, "command validation failed"},
	}
	for label, tt := range tests {
		t.Run(label, func(t *testing.T) {
			_, cleanup := SetupMockEnvironmentWithSudo(t, true)
			t.Cleanup(cleanup)
			runner := MustMockRunner(t)
			runner.SetResponse("sudo "+tt.name+" "+strings.Join(tt.args, " "), []byte("1"))

			out, err := runner.CombinedOutputWithSudoContext(context.Background(), tt.name, tt.args...)

			require.Error(t, err)
			assert.ErrorContains(t, err, tt.want)
			assert.Nil(t, out)
			assert.Empty(t, runner.GetCalls(), "a refused invocation is not recorded as a call")
		})
	}
}
