package fail2ban

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCanUseSudoProbesOncePerProcess pins that privilege detection does not
// spawn sudo for every fail2ban-client call. A least-privilege user paid up to
// two extra processes per command, and `banned all` issues one per jail.
func TestCanUseSudoProbesOncePerProcess(t *testing.T) {
	probes := 0
	checker := &RealSudoChecker{runSudoProbe: func(context.Context) error {
		probes++
		return nil
	}}

	assert.True(t, checker.CanUseSudo())
	assert.True(t, checker.CanUseSudo())
	assert.Equal(t, 1, probes)
}
