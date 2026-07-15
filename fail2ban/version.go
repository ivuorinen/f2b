package fail2ban

import (
	"cmp"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	fail2banVersionPattern = regexp.MustCompile(`(?i)fail2ban(?:-client)?[\s-]*v?([0-9]+(?:\.[0-9]+)*)(?:[-+].*)?`)
	versionNumberPattern   = regexp.MustCompile(`^v?([0-9]+(?:\.[0-9]+)*)(?:[-+].*)?$`)
)

// CompareVersions compares two dotted-numeric version strings, returning -1, 0,
// or 1. fail2ban versions are simple (e.g. 0.11.2, 1.0.1), so a small SemVer
// comparator replaces the go-version dependency: numeric components are compared
// left to right (missing trailing parts count as 0), a prerelease sorts before
// its release, and build metadata is ignored. Unparseable input falls back to
// lexical comparison.
func CompareVersions(v1, v2 string) int {
	n1, pre1, ok1 := parseVersion(v1)
	n2, pre2, ok2 := parseVersion(v2)
	if !ok1 || !ok2 {
		return strings.Compare(v1, v2)
	}

	for i := 0; i < len(n1) || i < len(n2); i++ {
		var a, b int
		if i < len(n1) {
			a = n1[i]
		}
		if i < len(n2) {
			b = n2[i]
		}
		switch {
		case a < b:
			return -1
		case a > b:
			return 1
		}
	}

	// Equal core versions: a prerelease sorts before the release (SemVer).
	switch {
	case pre1 == "" && pre2 == "":
		return 0
	case pre1 == "":
		return 1
	case pre2 == "":
		return -1
	default:
		return comparePrerelease(pre1, pre2)
	}
}

// comparePrerelease orders dot-separated prerelease identifiers per SemVer:
// numeric identifiers compare numerically and sort before alphanumeric ones
// (so rc.9 < rc.10 < rc.a); with all shared identifiers equal, the shorter
// list sorts first.
func comparePrerelease(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aErr := strconv.Atoi(as[i])
		bn, bErr := strconv.Atoi(bs[i])
		switch {
		case aErr == nil && bErr == nil:
			if an != bn {
				return cmp.Compare(an, bn)
			}
		case aErr == nil:
			return -1
		case bErr == nil:
			return 1
		default:
			if c := strings.Compare(as[i], bs[i]); c != 0 {
				return c
			}
		}
	}
	return cmp.Compare(len(as), len(bs))
}

// parseVersion splits "v1.2.3-pre+build" into numeric parts and the prerelease
// label (build metadata after '+' is ignored). ok is false when the numeric
// part is not a dotted list of integers.
func parseVersion(v string) (parts []int, prerelease string, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if plus := strings.IndexByte(v, '+'); plus >= 0 {
		v = v[:plus]
	}
	if dash := strings.IndexByte(v, '-'); dash >= 0 {
		prerelease = v[dash+1:]
		v = v[:dash]
	}
	if v == "" {
		return nil, "", false
	}
	for f := range strings.SplitSeq(v, ".") {
		n, err := strconv.Atoi(f)
		if err != nil {
			return nil, "", false
		}
		parts = append(parts, n)
	}
	return parts, prerelease, true
}

// ExtractFail2BanVersion extracts the semantic version from fail2ban-client -V output
func ExtractFail2BanVersion(output string) (string, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return "", fmt.Errorf("empty version output")
	}
	if match := fail2banVersionPattern.FindStringSubmatch(trimmed); len(match) == 2 {
		return match[1], nil
	}
	if match := versionNumberPattern.FindStringSubmatch(trimmed); len(match) == 2 {
		return match[1], nil
	}
	return "", fmt.Errorf("unable to parse version from %q", trimmed)
}
