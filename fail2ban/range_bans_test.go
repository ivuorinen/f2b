package fail2ban_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
	"github.com/ivuorinen/f2b/fail2ban"
)

// TestValidateBanTargetAcceptsAddressesAndRanges pins what ban and unban act
// on: fail2ban bans a CIDR range as one entry.
func TestValidateBanTargetAcceptsAddressesAndRanges(t *testing.T) {
	for _, target := range []string{"192.0.2.1", "198.51.100.0/24", "2001:db8::1", "2001:db8::/32"} {
		t.Run(target, func(t *testing.T) {
			assert.NoError(t, fail2ban.ValidateBanTarget(target))
		})
	}
	for _, target := range []string{"", "198.51.100.0/33", "198.51.100.0/", "/24", "sshd/24", "192.0.2.1;id"} {
		t.Run("rejects "+target, func(t *testing.T) {
			assert.Error(t, fail2ban.ValidateBanTarget(target))
		})
	}
}

// TestValidateArgumentsLetsAnIPv6RangeThrough pins the runner's argument check:
// an IPv6 range has the shape of an address, and checking it as a single
// address refused every IPv6 range ban.
func TestValidateArgumentsLetsAnIPv6RangeThrough(t *testing.T) {
	require.NoError(t, fail2ban.ValidateArguments([]string{"set", "sshd", "banip", "2001:db8::/32"}))
	require.Error(t, fail2ban.ValidateArguments([]string{"set", "sshd", "banip", "2001:db8::/129"}))
}

// TestRangeBansReachFail2ban pins that ban passes a range to fail2ban-client
// unchanged and that unban names it twice. fail2ban 0.11 removes a range's own
// entry and stops there, and unbans the addresses inside a range only when the
// range itself is not banned, so with one mention a host ban inside a banned
// range survives an unban that reports success.
func TestRangeBansReachFail2ban(t *testing.T) {
	tests := map[string]struct {
		args func(target string) string
		run  func(*fail2ban.RealClient, string) (int, error)
	}{
		"ban": {
			args: func(target string) string { return "banip " + target },
			run: func(c *fail2ban.RealClient, target string) (int, error) {
				return c.BanIPWithContext(context.Background(), target, "sshd")
			},
		},
		"unban": {
			args: func(target string) string { return "unbanip " + target + " " + target },
			run: func(c *fail2ban.RealClient, target string) (int, error) {
				return c.UnbanIPWithContext(context.Background(), target, "sshd")
			},
		},
	}
	for name, tt := range tests {
		for _, target := range []string{"198.51.100.0/24", "2001:db8::/32"} {
			t.Run(name+" "+target, func(t *testing.T) {
				client, mock := clientOverMockRunner(t, "sshd")
				mock.SetResponse("fail2ban-client set sshd "+tt.args(target), []byte("1"))

				code, err := tt.run(client, target)

				require.NoError(t, err)
				assert.Zero(t, code, "1 from fail2ban means the range was newly processed")
			})
		}
	}
}

// TestWithIPKeepsARange pins that a range ban carries its target into the log
// context instead of logging it as an invalid IP.
func TestWithIPKeepsARange(t *testing.T) {
	ctx := fail2ban.WithIP(context.Background(), "198.51.100.0/24")

	assert.Equal(t, "198.51.100.0/24", ctx.Value(constants.ContextKeyIP))
}
