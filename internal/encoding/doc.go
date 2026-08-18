// Package encoding holds the phase-1 DER builders for the two target
// extensions.
//
// # Verification standard
//
// A builder may only be wired into an issuer once its exact output bytes
// are pinned by a golden test against an authority independent of this
// package, and it carries malformed-input and fuzz tests. The two
// extensions have different authorities available, so they are at
// different stages:
//
//   - CRL Distribution Points is specified by RFC 5280 §4.2.1.13 and is
//     already implemented by crypto/x509. The golden test builds a real
//     certificate with x509.CreateCertificate and compares byte-for-byte
//     against the extension the standard library emits, so the encoding is
//     verified against a working implementation rather than against prose.
//
//   - The AD SID security extension has no such reference implementation.
//     Its encoding must NOT be inferred from documentation, from the OID,
//     or from a description of the structure. The bytes must come from a
//     real ADCS-issued certificate or an authoritative Microsoft test
//     vector, and a golden test must pin them.
//
//     That fixture now exists. It was captured on 2026-08-17 from a
//     certificate issued by an ADCS Enterprise CA in the phase-4 lab; see
//     testdata/README.md for its provenance and what it settles.
//     BuildNTDSCASecurityExt is pinned to it byte for byte.
//
// The fixture answered a question this package had deliberately left open:
// the extension carries the SID as its *textual* S-1-… rendering, not as
// the MS-DTYP binary layout. Guessing the other way would have produced a
// well-formed extension naming the wrong account, which is precisely the
// failure the no-inferred-encodings rule exists to prevent.
//
// The SID codec in this package is therefore not the extension's payload
// format. It remains the canonical binary SID representation in its own
// right — it is what AD stores in objectSid — so the mapping-snapshot
// producer still needs it, and BuildNTDSCASecurityExt uses it to validate
// that a SID parses before letting it into a certificate.
package encoding

import "encoding/asn1"

var (
	// OIDCRLDistributionPoints is id-ce-cRLDistributionPoints (RFC 5280 §4.2.1.13).
	OIDCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}

	// OIDNTDSCASecurityExt is szOID_NTDS_CA_SECURITY_EXT, the AD SID
	// security extension consumed by KDC strong certificate mapping.
	OIDNTDSCASecurityExt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2}

	// OIDNTDSObjectSID is szOID_NTDS_OBJECTSID, the inner OtherName type
	// carrying the account SID inside the security extension.
	OIDNTDSObjectSID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 25, 2, 1}
)
