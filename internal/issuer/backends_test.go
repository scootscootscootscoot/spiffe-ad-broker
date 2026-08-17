// External test package: the backends import issuer, so testing them from
// inside it would be an import cycle.
package issuer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer/adcs"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer/subordinate"
)

func request(t *testing.T) issuer.Request {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "workload"},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return issuer.Request{
		CSR:      csr,
		SPIFFEID: "spiffe://example.org/workload/db",
		ADSID:    "S-1-5-21-3734714977-4168152908-3762407930-1103",
	}
}

func backends() []issuer.Issuer {
	return []issuer.Issuer{adcs.New(), subordinate.New()}
}

// Neither backend may approximate an unbuilt issuance path. Both must
// refuse explicitly, so an unfinished backend can never be mistaken at a
// call site for one that issued something.
func TestBackendsRefuseUntilImplemented(t *testing.T) {
	for _, b := range backends() {
		cred, err := b.Issue(t.Context(), request(t))
		if !errors.Is(err, issuer.ErrNotImplemented) {
			t.Errorf("%s: want ErrNotImplemented, got %v", b.Name(), err)
		}
		if cred != nil {
			t.Errorf("%s: returned a credential alongside an error", b.Name())
		}
	}
}

// Validation has to run before the backend does anything else, so the
// shared guarantees hold regardless of which backend is configured. A
// backend that refused first and validated second would let a malformed
// request through the day it starts issuing.
func TestBackendsValidateBeforeRefusing(t *testing.T) {
	for _, b := range backends() {
		bad := request(t)
		bad.ADSID = "nonsense"
		_, err := b.Issue(t.Context(), bad)
		if err == nil {
			t.Errorf("%s: accepted a malformed SID", b.Name())
			continue
		}
		if errors.Is(err, issuer.ErrNotImplemented) {
			t.Errorf("%s: refused before validating; a malformed SID must be rejected on its own terms", b.Name())
		}
	}
}

func TestBackendNamesAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range backends() {
		if b.Name() == "" {
			t.Error("backend has an empty name")
		}
		if seen[b.Name()] {
			t.Errorf("duplicate backend name %q", b.Name())
		}
		seen[b.Name()] = true
	}
}
