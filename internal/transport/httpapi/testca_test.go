package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// testCA is a throwaway certificate authority for the transport tests. It
// exists so the tests exercise a real TLS handshake with real chain
// verification — the whole authentication story is "the peer certificate
// verified", and a test that stubs the handshake would not test it.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "spiffe-ad-broker test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{
		cert: cert,
		key:  key,
		pool: pool,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// leafOpts describes a leaf the CA should mint.
type leafOpts struct {
	uris  []string
	dns   []string
	ips   []net.IP
	usage []x509.ExtKeyUsage
}

func (ca *testCA) leaf(t *testing.T, opts leafOpts) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	uris := make([]*url.URL, 0, len(opts.uris))
	for _, raw := range opts.uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse URI SAN %q: %v", raw, err)
		}
		uris = append(uris, u)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  opts.usage,
		URIs:         uris,
		DNSNames:     opts.dns,
		IPAddresses:  opts.ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// serverCert is the broker's own identity, valid for the loopback address
// httptest binds to.
func (ca *testCA) serverCert(t *testing.T) tls.Certificate {
	t.Helper()
	return ca.leaf(t, leafOpts{
		uris:  []string{"spiffe://example.org/broker"},
		ips:   []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		dns:   []string{"localhost"},
		usage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
}

// workloadCert is a caller's SVID: one URI SAN and nothing else to go on.
func (ca *testCA) workloadCert(t *testing.T, spiffeID string) tls.Certificate {
	t.Helper()
	return ca.leaf(t, leafOpts{
		uris:  []string{spiffeID},
		usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
}
