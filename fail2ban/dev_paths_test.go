package fail2ban

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAllowDevPathsIsABoolean pins that the switch means what it says:
// ALLOW_DEV_PATHS=0 used to add /tmp to the trees root may be made to read.
func TestAllowDevPathsIsABoolean(t *testing.T) {
	tests := map[string]bool{"1": true, "true": true, "0": false, "false": false, "": false, "yes": false}
	for value, want := range tests {
		t.Run("value="+value, func(t *testing.T) {
			t.Setenv("ALLOW_DEV_PATHS", value)

			assert.Equal(t, want, slices.Contains(GetLogAllowedPaths(), "/tmp"), "log allowlist")
			assert.Equal(t, want, slices.Contains(GetFilterAllowedPaths(), "/tmp"), "filter allowlist")
		})
	}
}
