package httpapi

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"strings"
	"testing"
)

func uris(t *testing.T, raw ...string) []*url.URL {
	t.Helper()
	out := make([]*url.URL, 0, len(raw))
	for _, s := range raw {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		out = append(out, u)
	}
	return out
}

func stateWith(certs ...*x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{certs}}
}

func TestSPIFFEIDFromPeerAcceptsAnSVID(t *testing.T) {
	const want = "spiffe://example.org/workload/db"
	got, err := SPIFFEIDFromPeer(stateWith(&x509.Certificate{URIs: uris(t, want)}))
	if err != nil {
		t.Fatalf("SPIFFEIDFromPeer: %v", err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSPIFFEIDFromPeerRejectsPlaintext(t *testing.T) {
	if _, err := SPIFFEIDFromPeer(nil); err == nil {
		t.Fatal("accepted a request that did not arrive over TLS")
	}
}

// The single most important test in this package. PeerCertificates is
// populated whether or not the chain verified; VerifiedChains is not. If this
// function ever starts reading the former, a server misconfigured below
// RequireAndVerifyClientCert would hand out AD credentials to anyone holding
// any certificate at all.
func TestSPIFFEIDFromPeerRejectsUnverifiedPeer(t *testing.T) {
	svid := &x509.Certificate{URIs: uris(t, "spiffe://example.org/workload/db")}

	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{svid},
		// VerifiedChains deliberately empty: the peer presented a certificate
		// that was never checked against the trust bundle.
	}
	_, err := SPIFFEIDFromPeer(state)
	if err == nil {
		t.Fatal("accepted a peer certificate that was never verified")
	}
	if !strings.Contains(err.Error(), "not verified") {
		t.Fatalf("error does not name the failure: %v", err)
	}
}

func TestSPIFFEIDFromPeerRejectsEmptyChain(t *testing.T) {
	state := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}
	if _, err := SPIFFEIDFromPeer(state); err == nil {
		t.Fatal("accepted an empty verified chain")
	}
}

func TestSPIFFEIDFromPeerRejectsCertificateWithNoURISAN(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"db.example.org"}}
	if _, err := SPIFFEIDFromPeer(stateWith(cert)); err == nil {
		t.Fatal("accepted a certificate with no URI SAN")
	}
}

// An SVID carries exactly one URI SAN. Accepting several would leave the
// broker picking which identity the caller gets to be.
func TestSPIFFEIDFromPeerRejectsMultipleURISANs(t *testing.T) {
	cert := &x509.Certificate{URIs: uris(t,
		"spiffe://example.org/workload/db",
		"spiffe://example.org/workload/admin",
	)}
	if _, err := SPIFFEIDFromPeer(stateWith(cert)); err == nil {
		t.Fatal("accepted a certificate with two URI SANs")
	}
}

func TestSPIFFEIDFromPeerRejectsNonSPIFFEScheme(t *testing.T) {
	cert := &x509.Certificate{URIs: uris(t, "https://example.org/workload/db")}
	if _, err := SPIFFEIDFromPeer(stateWith(cert)); err == nil {
		t.Fatal("accepted a non-spiffe URI SAN")
	}
}

// Nothing here normalises. A non-canonical spelling is passed through so the
// mapping package can refuse it, rather than being quietly repaired into a
// lookup that hits an entry no reviewer approved for that spelling.
func TestSPIFFEIDFromPeerDoesNotNormalise(t *testing.T) {
	const raw = "spiffe://EXAMPLE.org/workload/db"
	got, err := SPIFFEIDFromPeer(stateWith(&x509.Certificate{URIs: uris(t, raw)}))
	if err != nil {
		t.Fatalf("SPIFFEIDFromPeer: %v", err)
	}
	if got != raw {
		t.Fatalf("got %q, want it returned verbatim as %q", got, raw)
	}
}
