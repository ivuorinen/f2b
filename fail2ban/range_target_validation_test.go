package fail2ban_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestValidateBanTargetRejectsACatchAllRange pins that a /0 range is refused:
// with no jail argument it would ban every source in every jail, including the
// operator's own session.
func TestValidateBanTargetRejectsACatchAllRange(t *testing.T) {
	for _, target := range []string{"0.0.0.0/0", "::/0"} {
		t.Run(target, func(t *testing.T) {
			err := fail2ban.ValidateBanTarget(target)

			require.Error(t, err)
			assert.ErrorContains(t, err, "/0")
		})
	}
}

// TestValidateBanTargetRejectsHostBits pins that a range whose address is not
// its network address is refused with the canonical form: fail2ban masks it to
// a wider network than the success message would name.
func TestValidateBanTargetRejectsHostBits(t *testing.T) {
	tests := map[string]string{
		"192.168.1.23/24": "use 192.168.1.0/24",
		"10.0.0.5/8":      "use 10.0.0.0/8",
		"10.0.0.5/0":      "/0",
		"2001:db8::1/32":  "use 2001:db8::/32",
	}
	for target, want := range tests {
		t.Run(target, func(t *testing.T) {
			err := fail2ban.ValidateBanTarget(target)

			require.Error(t, err)
			assert.ErrorContains(t, err, want)
		})
	}
}

// TestValidateBanTargetKeepsCanonicalRanges pins that the range checks leave
// single addresses and network-address ranges, including a one-host range,
// accepted.
func TestValidateBanTargetKeepsCanonicalRanges(t *testing.T) {
	for _, target := range []string{"192.0.2.1", "2001:db8::1", "198.51.100.0/24", "192.0.2.1/32", "2001:db8::/32"} {
		t.Run(target, func(t *testing.T) {
			assert.NoError(t, fail2ban.ValidateBanTarget(target))
		})
	}
}

// TestValidateArgumentsRejectsAnIPv6RangeWithHostBits pins that the runner's
// argument check applies the same range rules to an IP-shaped argument.
func TestValidateArgumentsRejectsAnIPv6RangeWithHostBits(t *testing.T) {
	err := fail2ban.ValidateArguments([]string{"set", "sshd", "banip", "2001:db8::1/32"})

	require.Error(t, err)
	assert.ErrorContains(t, err, "use 2001:db8::/32")
}
