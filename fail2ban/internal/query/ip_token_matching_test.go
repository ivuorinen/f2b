package query

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestContainsIPTokenRespectsAddressBoundaries pins that an IP filter matches
// whole addresses: a substring match shows bans for 192.0.2.10 when the user
// asked about 192.0.2.1.
func TestContainsIPTokenRespectsAddressBoundaries(t *testing.T) {
	const (
		ipv4 = "192.0.2.1"
		ipv6 = "2001:db8::1"
	)
	tests := []struct {
		name, line, ip string
		want           bool
	}{
		{"plain match", "Ban 192.0.2.1 now", ipv4, true},
		{"digit after", "Ban 192.0.2.10", ipv4, false},
		{"digit before", "Ban 1192.0.2.1", ipv4, false},
		{"lowercase hex before", "Ban a192.0.2.1", ipv4, false},
		{"uppercase hex before", "Ban F192.0.2.1", ipv4, false},
		{"dot after", "Ban 192.0.2.1.5", ipv4, false},
		{"other letter before", "Ban x192.0.2.1", ipv4, true},
		{"IPv4-mapped", "Ban ::ffff:192.0.2.1", ipv4, true},
		{"with a port", "Ban 192.0.2.1:22", ipv4, true},
		{"second occurrence", "Ban 192.0.2.10 then 192.0.2.1", ipv4, true},
		{"IPv6 match", "Ban 2001:db8::1 now", ipv6, true},
		{"IPv6 continues with colon", "Ban 2001:db8::1:2", ipv6, false},
		{"IPv6 continues with hex", "Ban 2001:db8::1f", ipv6, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ContainsIPToken(tt.line, tt.ip))
		})
	}
}

// TestContainsIPToken covers whole-token matching including IPv4-mapped IPv6
// and IP:port forms, which a strict "no adjacent ':'" boundary would miss.
func TestContainsIPToken(t *testing.T) {
	tests := []struct {
		name string
		line string
		ip   string
		want bool
	}{
		{"exact token", "Ban 192.168.1.100", "192.168.1.100", true},
		{"longer address suffix", "Ban 192.168.1.100", "192.168.1.10", false},
		{"longer address prefix", "Ban 1192.168.1.100", "192.168.1.100", false},
		{"ipv4-mapped ipv6", "Ban ::ffff:192.168.1.100", "192.168.1.100", true},
		{"ipv4 with port", "connection from 192.168.1.100:2222", "192.168.1.100", true},
		{"ipv4-mapped longer address", "Ban ::ffff:192.168.1.100", "92.168.1.100", false},
		{"ipv6 token", "Ban 2001:db8::1", "2001:db8::1", true},
		{"ipv6 inside longer address", "Ban 2001:db8::12", "2001:db8::1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsIPToken(tt.line, tt.ip); got != tt.want {
				t.Errorf("ContainsIPToken(%q, %q) = %v, want %v", tt.line, tt.ip, got, tt.want)
			}
		})
	}
}

func TestCanonicalizeIPFilter(t *testing.T) {
	tests := map[string]string{
		"2001:DB8::0001": "2001:db8::1",
		"192.0.2.1":      "192.0.2.1",
		"not-an-ip":      "not-an-ip",
		"all":            "all",
		"":               "",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			assert.Equal(t, want, canonicalIP(input))
		})
	}
}
