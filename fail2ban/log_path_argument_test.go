package fail2ban_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/fail2ban"
)

// TestValidateArgumentsAcceptsALogPathWithColons pins that an absolute path is
// never checked as an IP address: a log named after a timestamp has two colons,
// the IPv6 shape, and test-filter passes it to fail2ban-regex.
func TestValidateArgumentsAcceptsALogPathWithColons(t *testing.T) {
	for _, path := range []string{"/var/log/app/2026-11-11T10:00:00.log", "/var/log/app/::1.log"} {
		t.Run(path, func(t *testing.T) {
			assert.NoError(t, fail2ban.ValidateArguments([]string{path, "/etc/fail2ban/filter.d/sshd.conf"}))
		})
	}
}

// TestValidateArgumentsStillChecksIPv6ShapedArguments pins that the path
// exemption leaves an IPv6-shaped argument checked as an address.
func TestValidateArgumentsStillChecksIPv6ShapedArguments(t *testing.T) {
	require.NoError(t, fail2ban.ValidateArguments([]string{"set", "sshd", "banip", "2001:db8::1"}))
	assert.Error(t, fail2ban.ValidateArguments([]string{"set", "sshd", "banip", "2001:db8::zz"}))
}
