package fail2ban

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ivuorinen/f2b/constants"
)

// TestLogContextDropsBlankAndInvalidValues pins that context values, which are
// stamped on every later log line, never carry a blank or unvalidated string.
func TestLogContextDropsBlankAndInvalidValues(t *testing.T) {
	tests := map[string]struct {
		apply func(context.Context) context.Context
		key   any
	}{
		"blank request id": {
			func(ctx context.Context) context.Context { return WithRequestID(ctx, "  ") },
			constants.ContextKeyRequestID,
		},
		"blank operation": {
			func(ctx context.Context) context.Context { return WithOperation(ctx, "  ") },
			constants.ContextKeyOperation,
		},
		"invalid jail": {
			func(ctx context.Context) context.Context { return WithJail(ctx, "bad;jail") },
			constants.ContextKeyJail,
		},
		"invalid ip": {
			func(ctx context.Context) context.Context { return WithIP(ctx, "not-an-ip") },
			constants.ContextKeyIP,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Nil(t, tt.apply(context.Background()).Value(tt.key))
		})
	}
}
