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
// The request path is settled and built: MS-WSTEP over the CES HTTPS
// endpoint, in wstep.go, pinned to real captures in testdata/. What is still
// missing is authorization, not transport — an enrollment-agent credential
// and the CMC signed-request shape that uses it to enrol *on behalf of* the
// target account, plus a certificate template configured for those accounts.
//
// Until those exist this backend can only enrol as itself, which is not what
// the broker is for, so it refuses rather than approximating.
func (i *Issuer) Issue(_ context.Context, req issuer.Request) (*issuer.Credential, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return nil, issuer.ErrNotImplemented
}
