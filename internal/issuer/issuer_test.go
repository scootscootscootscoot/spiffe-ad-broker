package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

// newCSR builds a valid PKCS#10 with a fresh key. The subject is
// deliberately something a workload might try to smuggle identity through —
// nothing may ever read it.
func newCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "Administrator"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}

func validRequest(t *testing.T) Request {
	t.Helper()
	return Request{
		CSR:      newCSR(t),
		SPIFFEID: "spiffe://example.org/workload/db",
		ADSID:    "S-1-5-21-3734714977-4168152908-3762407930-1103",
	}
}

func TestValidateAcceptsWellFormedRequest(t *testing.T) {
	if err := validRequest(t).Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

func TestValidateRejectsMissingCSR(t *testing.T) {
	req := validRequest(t)
	req.CSR = nil
	if err := req.Validate(); err == nil {
		t.Fatal("accepted a request with no CSR")
	}
}

// The proof-of-possession check is the reason a caller cannot get a
// credential minted for a key it does not hold.
func TestValidateRejectsBrokenProofOfPossession(t *testing.T) {
	req := validRequest(t)
	tampered := *req.CSR
	tampered.Signature = append([]byte(nil), req.CSR.Signature...)
	tampered.Signature[len(tampered.Signature)-1] ^= 0xff
	req.CSR = &tampered

	err := req.Validate()
	if err == nil {
		t.Fatal("accepted a CSR whose signature does not verify")
	}
	if !strings.Contains(err.Error(), "proof-of-possession") {
		t.Fatalf("error does not name the failure: %v", err)
	}
}

func TestValidateRejectsBadSPIFFEID(t *testing.T) {
	for _, id := range []string{
		"",
		"example.org/workload/db",
		"https://example.org/workload/db",
		"spiffe://example.org",
	} {
		req := validRequest(t)
		req.SPIFFEID = id
		if err := req.Validate(); err == nil {
			t.Errorf("accepted SPIFFE ID %q", id)
		}
	}
}

// A malformed SID must never reach a backend. Every one of these would
// otherwise be encoded into a certificate that authenticates as something.
func TestValidateRejectsBadSID(t *testing.T) {
	for _, sid := range []string{
		"",
		"S-1-5",
		"S-2-5-21-1-2-3-1103",
		"S-1-5-21-1-2-3-01103",
		"S-1-5-21-1-2-3-4294967296",
		"not-a-sid",
	} {
		req := validRequest(t)
		req.ADSID = sid
		if err := req.Validate(); err == nil {
			t.Errorf("accepted SID %q", sid)
		}
	}
}
