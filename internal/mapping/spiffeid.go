package mapping

import (
	"fmt"
	"strings"
)

const (
	spiffeScheme = "spiffe://"

	// maxSPIFFEIDLength is the SPIFFE specification's ceiling on the total
	// length of an ID in bytes.
	maxSPIFFEIDLength = 2048
)

// ValidateSPIFFEID checks that id is a SPIFFE ID in canonical form:
// "spiffe://<trust-domain>/<path>", where the trust domain is lowercase and
// the path has at least one non-empty segment.
//
// Validation is deliberately strict rather than normalizing. A snapshot is
// keyed by exact string, so accepting two spellings of the same identity —
// a trailing slash, an uppercase trust domain, a percent-encoded segment,
// a "." or ".." segment — would let a lookup miss a mapping that a human
// reviewer believed was present. Producers must emit canonical IDs; the
// broker refuses anything else instead of guessing.
func ValidateSPIFFEID(id string) error {
	if len(id) > maxSPIFFEIDLength {
		return fmt.Errorf("SPIFFE ID is %d bytes, exceeds maximum %d", len(id), maxSPIFFEIDLength)
	}
	rest, ok := strings.CutPrefix(id, spiffeScheme)
	if !ok {
		return fmt.Errorf("SPIFFE ID %q: must begin with %q", id, spiffeScheme)
	}

	trustDomain, path, hasPath := strings.Cut(rest, "/")
	if trustDomain == "" {
		return fmt.Errorf("SPIFFE ID %q: empty trust domain", id)
	}
	for _, r := range trustDomain {
		if !isTrustDomainRune(r) {
			// Also what rejects userinfo ("@") and a port (":").
			return fmt.Errorf("SPIFFE ID %q: invalid character %q in trust domain", id, r)
		}
	}

	if !hasPath || path == "" {
		return fmt.Errorf("SPIFFE ID %q: path is required", id)
	}
	for _, segment := range strings.Split(path, "/") {
		switch segment {
		case "":
			// Catches both a trailing slash and an empty "//" segment.
			return fmt.Errorf("SPIFFE ID %q: empty path segment", id)
		case ".", "..":
			return fmt.Errorf("SPIFFE ID %q: dot segment %q is not allowed", id, segment)
		}
		for _, r := range segment {
			if !isPathRune(r) {
				return fmt.Errorf("SPIFFE ID %q: invalid character %q in path", id, r)
			}
		}
	}
	return nil
}

// isTrustDomainRune reports whether r is allowed in a trust domain name:
// lowercase letters, digits, and ".", "-", "_".
func isTrustDomainRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '.' || r == '-' || r == '_':
		return true
	}
	return false
}

// isPathRune reports whether r is allowed in a path segment: letters,
// digits, and ".", "-", "_". Percent-encoding is rejected by omission.
func isPathRune(r rune) bool {
	if r >= 'A' && r <= 'Z' {
		return true
	}
	return isTrustDomainRune(r)
}
