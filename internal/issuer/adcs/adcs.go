// Package adcs implements the enrollment-agent issuance shape: the broker
// holds a Certificate Request Agent credential and asks ADCS to issue on
// behalf of the target account.
//
// This is the shape that makes the enterprise case work, because the parts
// that were blocking elsewhere are already solved by ADCS:
//
//   - ADCS's issuing CA is already in NTAuthCertificates, and it is the
//     leaf's immediate issuer — which the phase-4 lab proved is the thing
//     that actually has to be published.
//   - ADCS emits szOID_NTDS_CA_SECURITY_EXT natively, so the exact bytes
//     never have to be inferred and no fixture is needed to proceed.
//   - ADCS runs CDP/CRL infrastructure, so revocation works without
//     weakening revocation checking on the KDC.
//
// What this package must get right is narrower, and it is all authorization:
// the enrollment agent can request certificates for other accounts, so its
// credential is a high-value target and its use has to be constrained by
// template ACLs and enrollment-agent restrictions on the CA side, not by
// this code alone.
package adcs

import (
	"context"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer"
)

// Issuer requests certificates from ADCS as an enrollment agent.
type Issuer struct{}

// New returns an ADCS issuer. It takes no configuration yet.
func New() *Issuer { return &Issuer{} }

// Name identifies this backend.
func (i *Issuer) Name() string { return "adcs" }

// Issue is not implemented yet.
//
// Building it needs, in order: the MS-WCCE request path (or certreq/CMC
// equivalent), an enrollment-agent credential to sign on-behalf-of
// requests, and a certificate template configured for the target accounts.
// None of those are decided, so this refuses rather than approximating.
func (i *Issuer) Issue(_ context.Context, req issuer.Request) (*issuer.Credential, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return nil, issuer.ErrNotImplemented
}
