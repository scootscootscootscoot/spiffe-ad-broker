package mapping

import (
	"fmt"
	"strconv"
	"strings"
)

const maxSubAuthorities = 15

// ValidateSIDString checks that s is a canonical Windows SID string:
// "S-1-<identifier-authority>-<subauth>[-<subauth>...]" with revision 1,
// a decimal identifier authority below 2^48, and 1–15 uint32 decimal
// sub-authorities with no leading zeros. Anything else is rejected —
// malformed mapping data must never reach DER encoding.
func ValidateSIDString(s string) error {
	parts := strings.Split(s, "-")
	if len(parts) < 4 {
		return fmt.Errorf("SID %q: need at least S-1-<authority>-<subauthority>", s)
	}
	if parts[0] != "S" {
		return fmt.Errorf("SID %q: must start with %q", s, "S-")
	}
	if parts[1] != "1" {
		return fmt.Errorf("SID %q: unsupported revision %q", s, parts[1])
	}
	if _, err := parseCanonicalUint(parts[2], 1<<48-1); err != nil {
		return fmt.Errorf("SID %q: identifier authority: %w", s, err)
	}
	subAuths := parts[3:]
	if len(subAuths) > maxSubAuthorities {
		return fmt.Errorf("SID %q: %d sub-authorities exceeds maximum %d", s, len(subAuths), maxSubAuthorities)
	}
	for _, sub := range subAuths {
		if _, err := parseCanonicalUint(sub, 1<<32-1); err != nil {
			return fmt.Errorf("SID %q: sub-authority %q: %w", s, sub, err)
		}
	}
	return nil
}

// parseCanonicalUint parses a decimal integer in [0, max] and rejects
// non-canonical forms (empty, leading zeros, signs, hex).
func parseCanonicalUint(s string, max uint64) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("leading zero")
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("not a decimal integer")
	}
	if v > max {
		return 0, fmt.Errorf("value %d exceeds maximum %d", v, max)
	}
	return v, nil
}
