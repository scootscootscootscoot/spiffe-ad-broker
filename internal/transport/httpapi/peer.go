package httpapi

import (
	"crypto/tls"
	"errors"
	"fmt"
)

// spiffeScheme is the only URI scheme a SPIFFE ID may use.
const spiffeScheme = "spiffe"

// SPIFFEIDFromPeer extracts the caller's SPIFFE ID from a completed TLS
// handshake. This function is the authentication; everything downstream trusts
// what it returns.
//
// Three properties make it that rather than a hint:
//
//   - It reads VerifiedChains, not PeerCertificates. A certificate only appears
//     in VerifiedChains after chain verification against the configured trust
//     bundle succeeded. PeerCertificates is populated either way, so a server
//     misconfigured below tls.RequireAndVerifyClientCert would hand out
//     credentials on an unverified identity — reading VerifiedChains turns that
//     misconfiguration into a refusal instead of a silent authentication bypass.
//
//   - It requires exactly one URI SAN. The SPIFFE X.509-SVID specification says
//     an SVID carries exactly one. Accepting several would leave the broker
//     picking which identity a caller gets to be, and a caller that can
//     influence that pick has chosen its own AD account.
//
//   - It returns the value verbatim. Canonical-form checking belongs to the
//     mapping package and runs in the broker; nothing here lowercases, trims, or
//     normalises, because a tolerated spelling is a lookup that quietly misses a
//     mapping a human reviewer believed was in force.
func SPIFFEIDFromPeer(state *tls.ConnectionState) (string, error) {
	if state == nil {
		return "", errors.New("request did not arrive over TLS")
	}
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", errors.New("peer certificate was not verified against the trust bundle")
	}
	leaf := state.VerifiedChains[0][0]

	switch len(leaf.URIs) {
	case 1:
	case 0:
		return "", errors.New("peer certificate carries no URI SAN, so it is not an SVID")
	default:
		return "", fmt.Errorf("peer certificate carries %d URI SANs; an SVID has exactly one", len(leaf.URIs))
	}

	uri := leaf.URIs[0]
	if uri.Scheme != spiffeScheme {
		return "", fmt.Errorf("peer certificate URI SAN has scheme %q, want %q", uri.Scheme, spiffeScheme)
	}
	return uri.String(), nil
}
