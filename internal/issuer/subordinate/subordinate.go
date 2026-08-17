// Package subordinate implements the own-CA issuance shape: the broker
// issues from a dedicated CA it controls, subordinate to the corporate PKI
// and published to NTAuthCertificates in its own right.
//
// Choose this over the adcs backend when the issuance path has to be owned
// rather than delegated. The trade is explicit:
//
//   - It brings back both certificate-shape problems. This backend emits
//     szOID_NTDS_CA_SECURITY_EXT itself, so it needs the exact encoding —
//     which must come from a real ADCS-issued certificate or an
//     authoritative Microsoft vector, never from documentation. And it
//     needs a CDP pointing at a CRL, which means signing and publishing
//     one.
//   - Both are solvable here, unlike under a SPIRE CA, because this backend
//     holds its own signing key. That is the entire reason this shape
//     exists.
//   - The CA is in NTAuthCertificates, so it is a forest-wide client
//     authentication authority. Keeping it single-purpose, small, and
//     narrowly scoped is not tidiness — it is the only thing bounding what
//     a compromise of it can assert.
package subordinate

import (
	"context"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer"
)

// Issuer mints certificates from a broker-controlled subordinate CA.
type Issuer struct{}

// New returns a subordinate-CA issuer. It takes no configuration yet.
func New() *Issuer { return &Issuer{} }

// Name identifies this backend.
func (i *Issuer) Name() string { return "subordinate" }

// Issue is not implemented yet.
//
// It is blocked on the same fixture the composer work was blocked on: the
// AD SID security extension's exact bytes. Until those are pinned by a
// golden test against a real ADCS-issued certificate, this must not
// approximate them — a wrong guess produces a certificate that looks
// correct and maps to the wrong account, or to none.
func (i *Issuer) Issue(_ context.Context, req issuer.Request) (*issuer.Credential, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return nil, issuer.ErrNotImplemented
}
