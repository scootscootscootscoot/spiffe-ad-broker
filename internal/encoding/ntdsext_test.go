package encoding

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"testing"
)

// The account named by the fixture certificate. Synthetic: a throwaway
// account in a disposable lab forest.
const fixtureSID = "S-1-5-21-3734714977-4168152908-3762407930-1104"

// TestNTDSCASecurityExtMatchesADCS is the golden test the package doc
// requires before this builder may be wired into an issuer: the bytes are
// compared against an extension taken from a certificate ADCS actually
// issued, not against a description of one.
func TestNTDSCASecurityExtMatchesADCS(t *testing.T) {
	want, err := os.ReadFile("testdata/ntds-ca-security-ext.der")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	ext, err := BuildNTDSCASecurityExt(fixtureSID)
	if err != nil {
		t.Fatalf("BuildNTDSCASecurityExt(%q) = %v", fixtureSID, err)
	}
	if !ext.Id.Equal(OIDNTDSCASecurityExt) {
		t.Errorf("extension OID = %v, want %v", ext.Id, OIDNTDSCASecurityExt)
	}
	// ADCS does not mark it critical. A critical extension an old KDC did
	// not understand would fail the whole certificate.
	if ext.Critical {
		t.Error("extension is critical; ADCS emits it non-critical")
	}
	if !bytes.Equal(ext.Value, want) {
		t.Errorf("extension bytes differ from the ADCS fixture\n got: %x\nwant: %x", ext.Value, want)
	}
}

// TestFixtureCertificateCarriesTheExtension checks the fixture is what it
// claims to be, so the golden test above cannot be silently pinned to a
// file that stopped being an ADCS extension.
func TestFixtureCertificateCarriesTheExtension(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/adcs-user-cert.pem")
	if err != nil {
		t.Fatalf("reading fixture certificate: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("fixture certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing fixture certificate: %v", err)
	}

	got, err := SIDFromCertificateExtensions(cert.Extensions)
	if err != nil {
		t.Fatalf("SIDFromCertificateExtensions: %v", err)
	}
	if got != fixtureSID {
		t.Errorf("SID from fixture certificate = %q, want %q", got, fixtureSID)
	}

	// And the extension's own bytes must match the extracted fixture.
	want, err := os.ReadFile("testdata/ntds-ca-security-ext.der")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	var found bool
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDNTDSCASecurityExt) {
			found = true
			if !bytes.Equal(ext.Value, want) {
				t.Error("extension in the certificate differs from the extracted .der fixture")
			}
		}
	}
	if !found {
		t.Error("fixture certificate carries no AD SID security extension")
	}
}

// TestNTDSCASecurityExtRoundTrip pins that what we build parses back to the
// SID we asked for. A builder and a parser that are wrong in the same way
// would still round-trip, which is why the golden test above exists too —
// this one only guards the pair against drifting apart.
func TestNTDSCASecurityExtRoundTrip(t *testing.T) {
	for _, sid := range []string{
		fixtureSID,
		"S-1-5-21-1-2-3-1105",
		"S-1-5-18",
	} {
		ext, err := BuildNTDSCASecurityExt(sid)
		if err != nil {
			t.Errorf("BuildNTDSCASecurityExt(%q) = %v", sid, err)
			continue
		}
		got, err := SIDFromCertificateExtensions([]pkix.Extension{ext})
		if err != nil {
			t.Errorf("SIDFromCertificateExtensions(%q) = %v", sid, err)
			continue
		}
		if got != sid {
			t.Errorf("round trip of %q = %q", sid, got)
		}
	}
}

// TestNTDSCASecurityExtRejectsMalformedSID keeps a SID this package cannot
// parse out of a certificate. The extension decides which account
// authenticates, so "pass it through and let AD sort it out" is not
// available.
func TestNTDSCASecurityExtRejectsMalformedSID(t *testing.T) {
	for _, sid := range []string{
		"",
		"S-1-5-21-notanumber-1105",
		"1-5-21-1-2-3-1105",
		"S-1",
		"S-1-5-21-1-2-3-1105 ",
	} {
		if _, err := BuildNTDSCASecurityExt(sid); err == nil {
			t.Errorf("BuildNTDSCASecurityExt(%q) succeeded; want refusal", sid)
		}
	}
}

// TestSIDFromCertificateExtensionsAbsent distinguishes absent from
// malformed: callers act on them differently.
func TestSIDFromCertificateExtensionsAbsent(t *testing.T) {
	if _, err := SIDFromCertificateExtensions(nil); err != ErrNoSID {
		t.Errorf("SIDFromCertificateExtensions(nil) = %v, want %v", err, ErrNoSID)
	}
}
