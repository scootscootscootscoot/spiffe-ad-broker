// External test package: the backends import issuer, so testing them from
// inside it would be an import cycle.
package issuer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

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
		CSR:       csr,
		SPIFFEID:  "spiffe://example.org/workload/db",
		ADSID:     "S-1-5-21-3734714977-4168152908-3762407930-1103",
		ADAccount: `EXAMPLE\svc-db`,
	}
}

// unreachable is a transport that fails every round trip, so a backend built
// on it can be exercised for everything that happens before the network.
type unreachable struct{}

func (unreachable) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no CES endpoint in tests")
}

func backends(t *testing.T) []issuer.Issuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("agent key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "enrollment agent"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 311, 20, 2, 1}},
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "enrollment agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("agent certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse agent certificate: %v", err)
	}
	a, err := adcs.New(adcs.Config{
		CESURL:   "https://ca.example.org/CA_CES_Certificate/service.svc/CES",
		Template: "WorkloadPKINIT",
		Agent:    &adcs.Agent{Certificate: cert, Key: key},
		Client:   &http.Client{Transport: unreachable{}},
	})
	if err != nil {
		t.Fatalf("adcs.New: %v", err)
	}
	return []issuer.Issuer{a, subordinate.New()}
}

// An unbuilt issuance path must never be approximated. subordinate refuses
// explicitly, so it can never be mistaken at a call site for one that issued
// something.
func TestUnimplementedBackendRefuses(t *testing.T) {
	b := subordinate.New()
	cred, err := b.Issue(t.Context(), request(t))
	if !errors.Is(err, issuer.ErrNotImplemented) {
		t.Errorf("%s: want ErrNotImplemented, got %v", b.Name(), err)
	}
	if cred != nil {
		t.Errorf("%s: returned a credential alongside an error", b.Name())
	}
}

// Validation has to run before the backend does anything else, so the
// shared guarantees hold regardless of which backend is configured. A
// backend that refused first and validated second would let a malformed
// request through the day it starts issuing.
func TestBackendsValidateBeforeRefusing(t *testing.T) {
	for _, b := range backends(t) {
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
	for _, b := range backends(t) {
		if b.Name() == "" {
			t.Error("backend has an empty name")
		}
		if seen[b.Name()] {
			t.Errorf("duplicate backend name %q", b.Name())
		}
		seen[b.Name()] = true
	}
}
