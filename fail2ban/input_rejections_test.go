package fail2ban

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivuorinen/f2b/constants"
)

func TestRequiredInputsMustBePresent(t *testing.T) {
	require.ErrorIs(t, ValidateIP(""), ErrIPRequiredError)
	require.ErrorIs(t, ValidateJail(""), ErrJailRequiredError)
}

// TestValidateIPNeverEchoesHostileInput pins that the error for injection-like
// or oversized input omits the input, which would otherwise reach the terminal
// and the logs verbatim.
func TestValidateIPNeverEchoesHostileInput(t *testing.T) {
	hostile := map[string]string{
		"shell metacharacter": "192.0.2.1;reboot",
		"oversized":           strings.Repeat("9", constants.MaxIPAddressLength+1),
	}
	for name, input := range hostile {
		t.Run(name, func(t *testing.T) {
			err := ValidateIP(input)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), input)
		})
	}
}

// TestValidateJailRejectsALeadingSeparator pins the first-character rule: a
// name starting with a dash would reach fail2ban-client as an option.
func TestValidateJailRejectsALeadingSeparator(t *testing.T) {
	for _, jail := range []string{"-sshd", "_sshd", ".sshd"} {
		t.Run(jail, func(t *testing.T) {
			require.Error(t, ValidateJail(jail))
		})
	}
}

func TestValidateFilterDotPatterns(t *testing.T) {
	tests := map[string]bool{
		"..":         false,
		"..sshd":     false,
		"sshd..":     false,
		".sshd":      true,
		"sshd.":      true,
		"sshd.local": true,
	}
	for filter, valid := range tests {
		t.Run(filter, func(t *testing.T) {
			err := ValidateFilter(filter)
			if valid {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
		})
	}
}

// TestIsLikelyIPArgumentShapes pins which arguments get force-validated as IP
// addresses: a jail name classified as one fails the whole command.
func TestIsLikelyIPArgumentShapes(t *testing.T) {
	tests := map[string]bool{
		"":            false,
		"1.2.3":       false,
		"1..3.4":      false,
		"1234.1.1.1":  false,
		"a.b.c.d":     false,
		"abc.def":     false,
		"a:b":         false,
		"192.0.2.1":   true,
		"999.1.1.1":   true,
		"::1":         true,
		"2001:db8:1a": true,
	}
	for arg, want := range tests {
		t.Run(arg, func(t *testing.T) {
			assert.Equal(t, want, isLikelyIPArgument(arg))
		})
	}
}

func TestInjectionScanMatchesKeywordsButNotOrdinaryWords(t *testing.T) {
	tests := map[string]bool{
		"exec rm":   true,
		"system(x)": true,
		"EVAL(x)":   true,
		"executive": false,
		"evaluate":  false,
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, want, containsCommandInjectionPatterns(input))
		})
	}
}
