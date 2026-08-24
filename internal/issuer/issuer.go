// Package issuer defines the contract between the broker and whatever
// actually mints the AD-authentication certificate.
//
// The two supported shapes differ only behind this interface:
//
//   - adcs: the broker acts as an ADCS enrollment agent and requests the
//     certificate on behalf of the target account. ADCS is already in
//     NTAuthCertificates, already emits szOID_NTDS_CA_SECURITY_EXT, and
//     already runs CRL infrastructure, so neither of this project's two
//     original certificate-shape gaps applies.
//
//   - subordinate: the broker issues from a dedicated CA it controls,
//     subordinate to the corporate PKI and published to NTAuth on its own.
//     Here the broker owns the SID extension and the CDP/CRL, so both gaps
//     come back — but they are solvable, because the broker holds the key.
//
// Everything above this interface — authenticating the caller, resolving
// the mapping, refusing to proceed — is identical for both.
package issuer

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/mapping"
)

// ErrNotImplemented is returned by a backend that is not built yet. It is a
// refusal, never a fallback: no caller may interpret it as permission to
// issue by some other route.
var ErrNotImplemented = errors.New("issuer backend not implemented")

// Request is one authenticated ask for an AD-authentication certificate.
//
// The security model of this struct is the whole point of the design, so it
// is stated here rather than left to the backends:
//
//   - CSR is workload-controlled. Only two things in it are trusted: the
//     public key, and the proof-of-possession signature over it. The
//     subject, the SANs, any requested extensions, and any attributes are
//     ignored entirely. A backend that copies any of them into the issued
//     certificate has reintroduced workload-controlled identity.
//
//   - SPIFFEID is not taken from the request body. It is the identity the
//     caller proved by presenting a valid SVID over mTLS.
//
//   - ADSID comes from the authoritative mapping and nowhere else. It is
//     never derived from the SPIFFE ID path, the CSR, or any other
//     workload-reachable input. A certificate carrying a SID authenticates
//     as that account, so a derived SID is an account-takeover primitive.
//
// The broker never generates or holds the workload's private key. The
// workload keeps it and proves possession through the CSR.
type Request struct {
	// CSR is the workload's PKCS#10 request.
	CSR *x509.CertificateRequest

	// SPIFFEID is the caller's proven identity, in canonical form.
	SPIFFEID string

	// ADSID is the target account's SID in canonical string form
	// ("S-1-5-21-...-1105"), resolved from the mapping snapshot.
	ADSID string

	// ADAccount is the same account in DOMAIN\samAccountName form, also
	// from the mapping snapshot and never from anywhere else.
	//
	// It is empty unless the snapshot carries one. Only the adcs backend
	// needs it — an enrollment agent names the target account by name, so
	// under that backend this field *is* the authorization statement the CA
	// acts on, and the SID is what has to be checked on the way back.
	ADAccount string
}

// Validate checks everything that must hold before any backend is called.
// It fails closed: a request that does not fully validate is refused, never
// partially honoured.
//
// Backends may add their own checks but must not skip these, so the
// guarantees hold no matter which backend is configured.
func (r Request) Validate() error {
	if r.CSR == nil {
		return errors.New("request has no CSR")
	}
	// Proof of possession. Without this the caller could present a public
	// key it does not hold, and the broker would mint an AD credential
	// usable by whoever does hold the matching private key.
	if err := r.CSR.CheckSignature(); err != nil {
		return fmt.Errorf("CSR proof-of-possession failed: %w", err)
	}
	if err := mapping.ValidateSPIFFEID(r.SPIFFEID); err != nil {
		return fmt.Errorf("caller SPIFFE ID: %w", err)
	}
	if err := mapping.ValidateSIDString(r.ADSID); err != nil {
		return fmt.Errorf("target AD SID: %w", err)
	}
	// Absent is a backend's problem — subordinate never needs it. Present
	// and malformed is everyone's, so it is refused here rather than at
	// whichever backend happens to read it.
	if r.ADAccount != "" {
		if err := mapping.ValidateAccountName(r.ADAccount); err != nil {
			return fmt.Errorf("target AD account: %w", err)
		}
	}
	return nil
}

// Credential is the issued certificate and the chain needed to present it.
// The private key is absent by construction — it never left the workload.
type Credential struct {
	// Certificate is the leaf issued for the target AD account.
	Certificate *x509.Certificate

	// Chain is the intermediates between Certificate and a trusted root,
	// leaf-first, excluding the leaf itself. The KDC needs to build the
	// chain to a CA in NTAuthCertificates, and per the phase-4 lab result
	// it is the leaf's *immediate* issuer that must be published there.
	Chain []*x509.Certificate
}

// An Issuer mints an AD-authentication certificate for an already
// authenticated, already mapped request.
//
// An Issuer is responsible only for producing the certificate. It does not
// authenticate the caller, resolve the mapping, or decide policy — those
// happen once, above this interface, so they cannot diverge between
// backends.
type Issuer interface {
	// Name identifies the backend in logs and issuance records.
	Name() string

	// Issue returns a credential for req, or an error. An error is always a
	// refusal to issue; there is no partial or best-effort result.
	Issue(ctx context.Context, req Request) (*Credential, error)
}
