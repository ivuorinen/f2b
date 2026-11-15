// Package query holds the request semantics that RealClient and the
// fail2bantest doubles share: which jails a ban-record request selects and
// which log lines a jail/IP filter matches. Keeping one implementation means
// a test passing against a double also passes against the real client.
package query

import (
	"net"
	"strings"

	"github.com/ivuorinen/f2b/constants"
)

// RequestsAllJails reports whether the requested jail list should expand to
// every configured jail: an empty list, or a list containing "all" or "".
func RequestsAllJails(jails []string) bool {
	if len(jails) == 0 {
		return true
	}
	for _, j := range jails {
		if j == constants.AllFilter || j == "" {
			return true
		}
	}
	return false
}

// LogFilter is the per-read state of a jail/IP log filter: the bracketed jail
// pattern and the canonical IP. It is built once per read so that matching a
// line does no formatting or allocation.
type LogFilter struct {
	jailPattern string // "[jail]", or "" when no jail filter applies
	ip          string // canonical IP, or ""/"all" when no IP filter applies
}

// NewLogFilter prepares the filter for a jail and an IP. An empty value or
// "all" disables that half of the filter.
func NewLogFilter(jail, ip string) LogFilter {
	var f LogFilter
	if jail != "" && jail != constants.AllFilter {
		f.jailPattern = "[" + jail + "]"
	}
	f.ip = canonicalIP(ip)
	return f
}

// Matches reports whether line passes the filter: it names the jail in
// brackets and holds the IP as a whole token.
func (f LogFilter) Matches(line string) bool {
	if f.jailPattern != "" && !strings.Contains(line, f.jailPattern) {
		return false
	}
	if f.ip != "" && f.ip != constants.AllFilter && !ContainsIPToken(line, f.ip) {
		return false
	}
	return true
}

// canonicalIP normalizes an IP filter via net.ParseIP so that e.g. the IPv6
// query "2001:DB8::1" matches the lowercase canonical form fail2ban writes to
// its logs. Non-IP values pass through untouched (they are rejected by
// validation upstream).
func canonicalIP(ip string) string {
	if ip == "" || ip == constants.AllFilter {
		return ip
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	return ip
}

// ContainsIPToken reports whether ip appears in line as a whole token, i.e. not
// as a substring of a longer address. A plain substring match for "10.0.0.1"
// wrongly matches "10.0.0.100" (and "110.0.0.1"), attributing other hosts'
// events to the requested IP.
//
// For an IPv4 query, ':' is treated as a separator rather than an address
// byte, so IPv4-mapped IPv6 forms ("::ffff:10.0.0.1") and "IP:port" forms
// still match the plain IPv4 address.
func ContainsIPToken(line, ip string) bool {
	ipv4 := strings.Contains(ip, ".") && !strings.Contains(ip, ":")
	isIPByte := func(b byte) bool {
		switch {
		case b >= '0' && b <= '9',
			b >= 'a' && b <= 'f',
			b >= 'A' && b <= 'F',
			b == '.':
			return true
		case b == ':':
			return !ipv4
		default:
			return false
		}
	}
	for idx := 0; ; {
		i := strings.Index(line[idx:], ip)
		if i < 0 {
			return false
		}
		start := idx + i
		end := start + len(ip)
		beforeOK := start == 0 || !isIPByte(line[start-1])
		afterOK := end == len(line) || !isIPByte(line[end])
		if beforeOK && afterOK {
			return true
		}
		idx = start + 1
	}
}
