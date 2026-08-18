package encoding

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// BuildNTDSCASecurityExt builds the AD SID security extension
// (szOID_NTDS_CA_SECURITY_EXT) for the account named by sid.
//
// The KDC maps a certificate to an account on this extension, so its bytes
// decide *which account authenticates*. They are therefore pinned to a
// fixture taken from a real ADCS-issued certificate rather than derived from
// documentation — see testdata/README.md for the provenance and
// TestNTDSCASecurityExtMatchesADCS for the pin.
//
// The structure ADCS emits is:
//
//	SEQUENCE {
//	  [0] {
//	    OBJECT IDENTIFIER 1.3.6.1.4.1.311.25.2.1
//	    [0] { OCTET STRING "S-1-5-21-…-1104" }
//	  }
//	}
//
// Note the SID is the *textual* rendering, not the MS-DTYP binary layout
// that MarshalSID produces. That was genuinely open until the fixture
// settled it, and the two are not interchangeable: the binary form here
// would be a well-formed extension naming the wrong account.
//
// The extension is not critical, matching ADCS.
func BuildNTDSCASecurityExt(sid string) (pkix.Extension, error) {
	// Validate by parsing. A malformed SID must never reach a certificate:
	// the whole point of this extension is that it names an account, so a
	// SID this package cannot parse is a refusal, not something to pass
	// through as an opaque string.
	if _, err := MarshalSID(sid); err != nil {
		return pkix.Extension{}, fmt.Errorf("ntds security extension: %w", err)
	}

	// Each layer is built and then wrapped by the next. asn1's "tag:0"
	// parameter is ignored for a RawValue — it encodes the Class and Tag
	// the value carries — so the wrapping has to be explicit.
	octets, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagOctetString,
		IsCompound: false,
		Bytes:      []byte(sid),
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("ntds security extension: encoding sid: %w", err)
	}

	// [0] { OCTET STRING } — the OtherName value.
	value, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      octets,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("ntds security extension: encoding value: %w", err)
	}

	oid, err := asn1.Marshal(OIDNTDSObjectSID)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("ntds security extension: encoding oid: %w", err)
	}

	// [0] { OID, [0] { OCTET STRING } } — the OtherName itself.
	otherName, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      append(oid, value...),
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("ntds security extension: encoding othername: %w", err)
	}

	outer, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      otherName,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("ntds security extension: encoding sequence: %w", err)
	}

	return pkix.Extension{
		Id:       OIDNTDSCASecurityExt,
		Critical: false,
		Value:    outer,
	}, nil
}

// ErrNoSID is returned when a certificate carries no AD SID security
// extension. It is distinct from a malformed one: absent and wrong are
// different failures and callers act on them differently.
var ErrNoSID = errors.New("certificate carries no AD SID security extension")

// SIDFromCertificateExtensions returns the SID named by the AD SID security
// extension among exts.
//
// This exists so an issued certificate can be checked against the SID that
// was asked for. A backend that delegates issuance (adcs) does not control
// what comes back, so verifying the returned certificate names the intended
// account — rather than trusting that it must — is the difference between
// delegating issuance and delegating the security decision.
func SIDFromCertificateExtensions(exts []pkix.Extension) (string, error) {
	for _, ext := range exts {
		if !ext.Id.Equal(OIDNTDSCASecurityExt) {
			continue
		}
		return parseNTDSCASecurityExt(ext.Value)
	}
	return "", ErrNoSID
}

func parseNTDSCASecurityExt(der []byte) (string, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(der, &seq)
	if err != nil {
		return "", fmt.Errorf("ntds security extension: %w", err)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("ntds security extension: %d trailing bytes", len(rest))
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return "", errors.New("ntds security extension: outer value is not a SEQUENCE")
	}

	var otherName asn1.RawValue
	if rest, err = asn1.Unmarshal(seq.Bytes, &otherName); err != nil {
		return "", fmt.Errorf("ntds security extension: othername: %w", err)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("ntds security extension: %d trailing bytes after othername", len(rest))
	}
	if otherName.Class != asn1.ClassContextSpecific || otherName.Tag != 0 || !otherName.IsCompound {
		return "", errors.New("ntds security extension: othername is not [0] constructed")
	}

	var oid asn1.ObjectIdentifier
	body, err := asn1.Unmarshal(otherName.Bytes, &oid)
	if err != nil {
		return "", fmt.Errorf("ntds security extension: type oid: %w", err)
	}
	if !oid.Equal(OIDNTDSObjectSID) {
		return "", fmt.Errorf("ntds security extension: unexpected type oid %v", oid)
	}

	var wrapper asn1.RawValue
	if rest, err = asn1.Unmarshal(body, &wrapper); err != nil {
		return "", fmt.Errorf("ntds security extension: value wrapper: %w", err)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("ntds security extension: %d trailing bytes after value", len(rest))
	}
	if wrapper.Class != asn1.ClassContextSpecific || wrapper.Tag != 0 || !wrapper.IsCompound {
		return "", errors.New("ntds security extension: value is not [0] constructed")
	}

	var octets asn1.RawValue
	if rest, err = asn1.Unmarshal(wrapper.Bytes, &octets); err != nil {
		return "", fmt.Errorf("ntds security extension: sid octets: %w", err)
	}
	if len(rest) != 0 {
		return "", fmt.Errorf("ntds security extension: %d trailing bytes after sid", len(rest))
	}
	if octets.Class != asn1.ClassUniversal || octets.Tag != asn1.TagOctetString || octets.IsCompound {
		return "", errors.New("ntds security extension: sid is not a primitive OCTET STRING")
	}

	sid := string(octets.Bytes)
	// Parse it rather than returning whatever was in there: a caller
	// comparing this against a mapping entry must be comparing a SID, not
	// an arbitrary string that happened to be in a certificate.
	if _, err := MarshalSID(sid); err != nil {
		return "", fmt.Errorf("ntds security extension: %w", err)
	}
	return sid, nil
}
