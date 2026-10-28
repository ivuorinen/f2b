package fail2ban

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

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
		wantErr   bool
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
			wantErr:   true,
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
			if (err != nil) != tt.wantErr {
				t.Fatalf("probeSudo() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(calls) != len(tt.wantCalls) {
				t.Fatalf("probe calls = %v, want %v", calls, tt.wantCalls)
			}
			for i := range calls {
				if strings.Join(calls[i], " ") != strings.Join(tt.wantCalls[i], " ") {
					t.Fatalf("probe call %d = %v, want %v", i, calls[i], tt.wantCalls[i])
				}
			}
		})
	}
}
