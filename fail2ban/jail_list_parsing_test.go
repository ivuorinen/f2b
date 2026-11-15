package fail2ban

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseJailListStopsAtTheEndOfItsLine pins that text after the jail list is
// not read as jail names; the other tests end the output at the list.
func TestParseJailListStopsAtTheEndOfItsLine(t *testing.T) {
	jails, err := ParseJailList("Status\n|- Number of jail:\t2\n`- Jail list:\tsshd, nginx\nNext: ignored\n")

	require.NoError(t, err)
	assert.Equal(t, []string{"sshd", "nginx"}, jails)
}

func TestParseBracketedListDropsEmptyElements(t *testing.T) {
	assert.Equal(t, []string{"sshd", "nginx"}, ParseBracketedList("['sshd', '', 'nginx']"))
}
