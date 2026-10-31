package fail2ban

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
)

// TestProbeSudoAcceptsFail2banScopedGrant drives the sudo probe with a fake
// runner (never the real sudo). A sudoers grant limited to fail2ban-client
// fails `sudo -n true`; the second probe must accept it, or a least-privilege
// user is refused operations sudo would run.
func TestProbeSudoAcceptsFail2banScopedGrant(t *testing.T) {
	errDenied := errors.New("sudo: a password is required")
	scoped := []string{"-n", "-l", constants.Fail2BanClientCommand}

	tests := []struct {
		name      string
		allowed   func(args []string) bool
		wantErr   error
		wantCalls [][]string
	}{
		{
			name:      "full sudo passes on the first probe",
			allowed:   func([]string) bool { return true },
			wantCalls: [][]string{{"-n", "true"}},
		},
		{
			name:      "grant scoped to fail2ban-client passes on the second probe",
			allowed:   func(args []string) bool { return slices.Equal(args, scoped) },
			wantCalls: [][]string{{"-n", "true"}, scoped},
		},
		{
			name:      "no grant fails both probes",
			allowed:   func([]string) bool { return false },
			wantErr:   errDenied,
			wantCalls: [][]string{{"-n", "true"}, scoped},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls [][]string
			err := probeSudo(context.Background(), func(_ context.Context, args ...string) error {
				calls = append(calls, args)
				if tt.allowed(args) {
					return nil
				}
				return errDenied
			})
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.wantCalls, calls)
		})
	}
}
