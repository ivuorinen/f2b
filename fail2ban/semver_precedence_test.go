package fail2ban

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompareVersionsFollowsSemverPrecedence pins the ordering the minimum
// fail2ban version check depends on. Expected values come from the SemVer 2.0
// precedence rules.
func TestCompareVersionsFollowsSemverPrecedence(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.2", "1.2.1", -1},
		{"1.2.1", "1.2", 1},
		{"1.2", "1.2.0", 0},
		{"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0-rc.1.1", "1.0.0-rc.1.2", -1},
		{"1.0.0-rc.1", "1.0.0-rc.1.1", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-alpha", 1},
		{"1.0.0-alpha", "1.0.0-1", 1},
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"", "1.0", -1},
		{"1.0", "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.a+" against "+tt.b, func(t *testing.T) {
			assert.Equal(t, tt.want, CompareVersions(tt.a, tt.b))
		})
	}
}

func TestExtractFail2BanVersionRejectsEmptyOutput(t *testing.T) {
	for _, output := range []string{"", "  \n"} {
		_, err := ExtractFail2BanVersion(output)
		require.Error(t, err)
	}
}
