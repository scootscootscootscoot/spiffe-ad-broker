package encoding

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// TestCRLDistributionPointsMatchesStdlib is the golden test that authorises
// this builder: it compares our bytes with the extension crypto/x509 puts
// in a real certificate for the same URIs. The reference is a working
// implementation, not a reading of the RFC.
func TestCRLDistributionPointsMatchesStdlib(t *testing.T) {
	cases := [][]string{
		{"http://crl.example.org/svid.crl"},
		{"http://crl.example.org/svid.crl", "http://crl-2.example.org/svid.crl"},
		{"https://crl.example.org/a.crl", "http://crl.example.org/b.crl", "ldap://dc.example.org/CN=CRL,DC=example,DC=org?certificateRevocationList"},
	}

	for _, uris := range cases {
		t.Run(strings.Join(uris, ","), func(t *testing.T) {
			ours, err := CRLDistributionPoints(uris)
			if err != nil {
				t.Fatalf("CRLDistributionPoints() = %v, want nil", err)
			}
			theirs := stdlibCDPExtension(t, uris)

			if !ours.Id.Equal(theirs.Id) {
				t.Errorf("OID = %v, stdlib emits %v", ours.Id, theirs.Id)
			}
			if ours.Critical != theirs.Critical {
				t.Errorf("Critical = %v, stdlib emits %v", ours.Critical, theirs.Critical)
			}
			if !bytes.Equal(ours.Value, theirs.Value) {
				t.Errorf("extension value mismatch\n ours: %s\nstdlib: %s",
					hex.EncodeToString(ours.Value), hex.EncodeToString(theirs.Value))
			}
		})
	}
}

// stdlibCDPExtension issues a throwaway self-signed certificate carrying the
// given distribution points and returns the extension the standard library
// encoded for them.
func stdlibCDPExtension(t *testing.T, uris []string) pkix.Extension {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cdp-golden"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<31-1, 0),
		BasicConstraintsValid: true,
		CRLDistributionPoints: uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDCRLDistributionPoints) {
			return ext
		}
	}
	t.Fatal("stdlib certificate has no CRL distribution points extension")
	return pkix.Extension{}
}

// TestCRLDistributionPointsGoldenBytes pins the exact TLV nesting, so a
// future refactor cannot silently change the shape even if the standard
// library's own encoding were to change underneath the comparison above.
//
//	30 27          SEQUENCE OF DistributionPoint, 39 bytes
//	  30 25        DistributionPoint, 37 bytes
//	    A0 23      [0] distributionPoint, 35 bytes
//	      A0 21    [0] fullName (GeneralNames), 33 bytes
//	        86 1F  [6] uniformResourceIdentifier, 31 bytes
func TestCRLDistributionPointsGoldenBytes(t *testing.T) {
	const uri = "http://crl.example.org/svid.crl"
	const wantHeader = "30273025a023a021861f"

	ext, err := CRLDistributionPoints([]string{uri})
	if err != nil {
		t.Fatalf("CRLDistributionPoints() = %v, want nil", err)
	}
	want := wantHeader + hex.EncodeToString([]byte(uri))
	if got := hex.EncodeToString(ext.Value); got != want {
		t.Errorf("extension value = %s, want %s", got, want)
	}
	if got, want := len(ext.Value), 41; got != want {
		t.Errorf("extension value length = %d, want %d", got, want)
	}
	if ext.Critical {
		t.Error("Critical = true, want false: a critical CDP breaks relying parties that ignore the extension")
	}
}

func TestCRLDistributionPointsRoundTrip(t *testing.T) {
	uris := []string{"http://crl.example.org/a.crl", "https://crl-2.example.org/b.crl"}
	ext, err := CRLDistributionPoints(uris)
	if err != nil {
		t.Fatalf("CRLDistributionPoints() = %v, want nil", err)
	}
	got := parseCDPURIs(t, ext.Value)
	if len(got) != len(uris) {
		t.Fatalf("decoded %d URIs, want %d", len(got), len(uris))
	}
	for i := range uris {
		if got[i] != uris[i] {
			t.Errorf("URI[%d] = %q, want %q", i, got[i], uris[i])
		}
	}
}

func parseCDPURIs(t *testing.T, der []byte) []string {
	t.Helper()
	var points []distributionPoint
	rest, err := asn1.Unmarshal(der, &points)
	if err != nil {
		t.Fatalf("unmarshal extension value: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("extension value has %d trailing bytes", len(rest))
	}
	uris := make([]string, 0, len(points))
	for _, p := range points {
		for _, name := range p.DistributionPoint.FullName {
			uris = append(uris, string(name.Bytes))
		}
	}
	return uris
}

func TestCRLDistributionPointsRejects(t *testing.T) {
	tests := []struct {
		name    string
		uris    []string
		wantErr string
	}{
		{name: "nil", uris: nil, wantErr: "at least one URI"},
		{name: "empty slice", uris: []string{}, wantErr: "at least one URI"},
		{name: "empty uri", uris: []string{""}, wantErr: "empty URI"},
		{name: "relative reference", uris: []string{"crl.example.org/svid.crl"}, wantErr: "relative reference"},
		{name: "non-ascii", uris: []string{"http://crl.exämple.org/svid.crl"}, wantErr: "printable ASCII"},
		{name: "control character", uris: []string{"http://crl.example.org/\x01.crl"}, wantErr: "printable ASCII"},
		{name: "embedded space", uris: []string{"http://crl.example.org/svid .crl"}, wantErr: "printable ASCII"},
		{name: "embedded newline", uris: []string{"http://crl.example.org/a.crl\nhttp://evil/"}, wantErr: "printable ASCII"},
		{name: "duplicate", uris: []string{"http://crl.example.org/a.crl", "http://crl.example.org/a.crl"}, wantErr: "duplicate URI"},
		{name: "over length", uris: []string{"http://crl.example.org/" + strings.Repeat("a", maxCDPURILength)}, wantErr: "exceeds maximum"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := CRLDistributionPoints(tt.uris)
			if err == nil {
				t.Fatalf("CRLDistributionPoints() = nil error, want one containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want containing %q", err, tt.wantErr)
			}
			if ext.Value != nil || ext.Id != nil {
				t.Error("returned a populated extension alongside an error; must be zero")
			}
		})
	}
}

func FuzzCRLDistributionPoints(f *testing.F) {
	f.Add("http://crl.example.org/svid.crl")
	f.Add("ldap://dc.example.org/CN=CRL?certificateRevocationList")
	f.Add("")
	f.Add("crl.example.org/x.crl")
	f.Add("http://crl.example.org/\x00.crl")

	// Anything the builder accepts must encode to well-formed DER with no
	// trailing bytes that decodes back to exactly the URI supplied. That is
	// the property the plugin relies on when it hands the value to SPIRE as
	// an opaque blob.
	f.Fuzz(func(t *testing.T, uri string) {
		ext, err := CRLDistributionPoints([]string{uri})
		if err != nil {
			return
		}
		var points []distributionPoint
		rest, err := asn1.Unmarshal(ext.Value, &points)
		if err != nil {
			t.Fatalf("accepted %q but its DER does not parse: %v", uri, err)
		}
		if len(rest) != 0 {
			t.Fatalf("accepted %q but its DER has %d trailing bytes", uri, len(rest))
		}
		if len(points) != 1 {
			t.Fatalf("accepted %q but decoded %d distribution points, want 1", uri, len(points))
		}
		names := points[0].DistributionPoint.FullName
		if len(names) != 1 {
			t.Fatalf("accepted %q but decoded %d names, want 1", uri, len(names))
		}
		if got := string(names[0].Bytes); got != uri {
			t.Fatalf("round-trip of %q produced %q", uri, got)
		}
		if names[0].Class != asn1.ClassContextSpecific || names[0].Tag != generalNameURITag {
			t.Fatalf("name for %q has class %d tag %d, want context-specific [6]", uri, names[0].Class, names[0].Tag)
		}
	})
}
