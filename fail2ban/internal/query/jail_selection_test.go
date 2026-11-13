package query

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRequestsAllJails pins which requests expand to every jail. `f2b banned
// all` depends on it: a list naming "all" must not query a jail called all.
func TestRequestsAllJails(t *testing.T) {
	tests := map[string]struct {
		jails []string
		want  bool
	}{
		"nil list":        {nil, true},
		"empty list":      {[]string{}, true},
		"all":             {[]string{"all"}, true},
		"blank":           {[]string{""}, true},
		"all among named": {[]string{"sshd", "all"}, true},
		"one named jail":  {[]string{"sshd"}, false},
		"two named jails": {[]string{"nginx", "sshd"}, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, RequestsAllJails(tt.jails))
		})
	}
}
