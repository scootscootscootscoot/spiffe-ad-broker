package encoding

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/url"
)

// maxCDPURILength bounds a single distribution point URI. RFC 5280 sets no
// limit, but an unbounded URI in a certificate is a denial-of-service
// surface for every relying party that fetches it, and a legitimate CDP is
// far shorter than this.
const maxCDPURILength = 1024

// ASN.1 shapes from RFC 5280 §4.2.1.13:
//
//	CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
//
//	DistributionPoint ::= SEQUENCE {
//	     distributionPoint       [0]     DistributionPointName OPTIONAL,
//	     reasons                 [1]     ReasonFlags OPTIONAL,
//	     cRLIssuer               [2]     GeneralNames OPTIONAL }
//
//	DistributionPointName ::= CHOICE {
//	     fullName                [0]     GeneralNames,
//	     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
//
// These mirror the unexported types in crypto/x509 so that the golden test
// can compare our output byte-for-byte with the standard library's.
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
	Reason            asn1.BitString        `asn1:"optional,tag:1"`
	CRLIssuer         asn1.RawValue         `asn1:"optional,tag:2"`
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

// generalNameURITag is the context-specific tag for the
// uniformResourceIdentifier alternative of GeneralName.
const generalNameURITag = 6

// CRLDistributionPoints builds the id-ce-cRLDistributionPoints extension
// (Gate 1) carrying one distribution point per URI.
//
// The extension is non-critical, matching RFC 5280's guidance and what
// crypto/x509 emits. Marking it critical would cause any relying party that
// does not process the extension to reject the certificate outright, which
// is a much larger blast radius than the revocation check it enables.
//
// Shape note for phase 4: this emits N DistributionPoint entries of one
// name each, which is what crypto/x509 and common CA practice produce. RFC
// 5280 also permits a single DistributionPoint holding N names, which more
// precisely means "the same CRL, reachable several ways". If a KDC is ever
// observed treating the two differently, that finding belongs in the lab
// report before this is changed.
func CRLDistributionPoints(uris []string) (pkix.Extension, error) {
	if len(uris) == 0 {
		return pkix.Extension{}, errors.New("cdp: at least one URI is required")
	}

	seen := make(map[string]struct{}, len(uris))
	points := make([]distributionPoint, 0, len(uris))
	for i, uri := range uris {
		if err := validateCDPURI(uri); err != nil {
			return pkix.Extension{}, fmt.Errorf("cdp: uri[%d]: %w", i, err)
		}
		if _, dup := seen[uri]; dup {
			// Emitting the same distribution point twice is meaningless and
			// makes the extension's bytes depend on caller sloppiness rather
			// than on policy. Extension output must be deterministic.
			return pkix.Extension{}, fmt.Errorf("cdp: uri[%d]: duplicate URI %q", i, uri)
		}
		seen[uri] = struct{}{}

		points = append(points, distributionPoint{
			DistributionPoint: distributionPointName{
				FullName: []asn1.RawValue{{
					Class: asn1.ClassContextSpecific,
					Tag:   generalNameURITag,
					Bytes: []byte(uri),
				}},
			},
		})
	}

	der, err := asn1.Marshal(points)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("cdp: marshal: %w", err)
	}
	return pkix.Extension{
		Id:       OIDCRLDistributionPoints,
		Critical: false,
		Value:    der,
	}, nil
}

// validateCDPURI checks that uri is encodable as an IA5String GeneralName
// and is a usable absolute URI.
//
// Which schemes are acceptable is deployment policy and is enforced by the
// broker's configuration validation, not here. This function's job is to
// guarantee that whatever reaches DER is well-formed: a relative reference
// or a non-ASCII byte in a certificate extension is a defect no policy
// makes acceptable.
func validateCDPURI(uri string) error {
	if uri == "" {
		return errors.New("empty URI")
	}
	if len(uri) > maxCDPURILength {
		return fmt.Errorf("URI is %d bytes, exceeds maximum %d", len(uri), maxCDPURILength)
	}
	for i := 0; i < len(uri); i++ {
		// IA5String is 7-bit, and a URI additionally contains no spaces or
		// control characters. Restrict to printable ASCII minus space.
		if c := uri[i]; c <= 0x20 || c > 0x7e {
			return fmt.Errorf("byte 0x%02x at offset %d is not printable ASCII (IA5String)", c, i)
		}
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("not a valid URI: %w", err)
	}
	if parsed.Scheme == "" {
		return fmt.Errorf("URI %q is a relative reference; an absolute URI is required", uri)
	}
	return nil
}
