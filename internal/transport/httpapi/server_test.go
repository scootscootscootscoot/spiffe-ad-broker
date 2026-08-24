package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/broker"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer/subordinate"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/mapping"
)

const (
	mappedCaller   = "spiffe://example.org/workload/db"
	unmappedCaller = "spiffe://example.org/workload/nobody"
	mappedSID      = "S-1-5-21-3734714977-4168152908-3762407930-1103"
)

// fakeIssuer stands in for a backend that works, so the success path can be
// exercised before either real backend exists.
type fakeIssuer struct {
	cred *issuer.Credential
	got  *issuer.Request
}

func (f *fakeIssuer) Name() string { return "fake" }

func (f *fakeIssuer) Issue(_ context.Context, req issuer.Request) (*issuer.Credential, error) {
	got := req
	f.got = &got
	return f.cred, nil
}

func newTestBroker(t *testing.T, backend issuer.Issuer) *broker.Broker {
	t.Helper()
	doc := fmt.Sprintf(`{
	  "version": "test-1",
	  "generated_at": %q,
	  "entries": [{"spiffe_id": %q, "ad_sid": %q}]
	}`, time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), mappedCaller, mappedSID)
	registry, err := mapping.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse snapshot: %v", err)
	}
	b, err := broker.New(broker.Config{
		Registry: registry,
		Backend:  backend,
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("broker.New: %v", err)
	}
	return b
}

// newTestServer stands up the real handler behind a real mutual-TLS listener,
// so requests go through actual chain verification rather than a stubbed
// ConnectionState.
func newTestServer(t *testing.T, backend issuer.Issuer) (*httptest.Server, *testCA) {
	t.Helper()
	ca := newTestCA(t)

	s, err := NewServer(newTestBroker(t, backend), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	srv := httptest.NewUnstartedServer(s.Handler())
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{ca.serverCert(t)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool,
	}
	// Handshake failures are expected in some tests; keep them off the test log.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, ca
}

func clientWith(ca *testCA, certs ...tls.Certificate) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			RootCAs:      ca.pool,
			Certificates: certs,
		}},
	}
}

// csrPEM is what a workload would actually send: a PKCS#10 over a key it
// holds, with a subject it has no business choosing.
func csrPEM(t *testing.T) string {
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
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func postIssue(t *testing.T, c *http.Client, url, contentType, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+IssuePath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", IssuePath, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func issueBody(t *testing.T) string {
	t.Helper()
	b, err := json.Marshal(issueRequest{CSR: csrPEM(t)})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return string(b)
}

func wantStatusAndReason(t *testing.T, resp *http.Response, status int, reason broker.Reason) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d", resp.StatusCode, status)
	}
	var body errorResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body.Error.Reason != string(reason) {
		t.Fatalf("reason = %q, want %q (message: %s)", body.Error.Reason, reason, body.Error.Message)
	}
}

// The headline test: every step real except the final issuance. A workload
// authenticates with its SVID, is resolved to an AD account, its CSR is
// validated, and the backend refuses because it does not exist yet. That
// 501 is the whole authenticate-and-map path working.
func TestMappedCallerReachesTheBackend(t *testing.T) {
	srv, ca := newTestServer(t, subordinate.New())
	c := clientWith(ca, ca.workloadCert(t, mappedCaller))

	resp := postIssue(t, c, srv.URL, "application/json", issueBody(t))
	wantStatusAndReason(t, resp, http.StatusNotImplemented, broker.ReasonNotImplemented)
}

// Fail closed: authenticated, but mapped to nothing.
func TestUnmappedCallerIsForbidden(t *testing.T) {
	srv, ca := newTestServer(t, subordinate.New())
	c := clientWith(ca, ca.workloadCert(t, unmappedCaller))

	resp := postIssue(t, c, srv.URL, "application/json", issueBody(t))
	wantStatusAndReason(t, resp, http.StatusForbidden, broker.ReasonNoMapping)
}

// No client certificate means no identity, and the refusal happens in the
// handshake — the handler is never reached and no body is ever read.
func TestCallerWithoutCertificateNeverReachesTheHandler(t *testing.T) {
	srv, ca := newTestServer(t, subordinate.New())
	c := clientWith(ca) // no client certificate

	req, err := http.NewRequest(http.MethodPost, srv.URL+IssuePath, strings.NewReader(issueBody(t)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("server accepted a connection with no client certificate (status %d)", resp.StatusCode)
	}
}

// A certificate that verifies but is not an SVID authenticates nobody.
func TestVerifiedCertificateWithoutSPIFFEIDIsUnauthenticated(t *testing.T) {
	srv, ca := newTestServer(t, subordinate.New())
	notAnSVID := ca.leaf(t, leafOpts{
		dns:   []string{"db.example.org"},
		usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	c := clientWith(ca, notAnSVID)

	resp := postIssue(t, c, srv.URL, "application/json", issueBody(t))
	wantStatusAndReason(t, resp, http.StatusUnauthorized, broker.ReasonUnauthenticated)
}

func TestSuccessReturnsCertificateAndChain(t *testing.T) {
	ca := newTestCA(t)
	issued := ca.leaf(t, leafOpts{usage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	backend := &fakeIssuer{cred: &issuer.Credential{
		Certificate: issued.Leaf,
		Chain:       []*x509.Certificate{ca.cert},
	}}

	srv, srvCA := newTestServer(t, backend)
	c := clientWith(srvCA, srvCA.workloadCert(t, mappedCaller))

	resp := postIssue(t, c, srv.URL, "application/json", issueBody(t))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body issueResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	block, _ := pem.Decode([]byte(body.Certificate))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("response certificate is not a CERTIFICATE PEM block: %q", body.Certificate)
	}
	if got, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("response certificate does not parse: %v", err)
	} else if got.SerialNumber.Cmp(issued.Leaf.SerialNumber) != 0 {
		t.Fatalf("response carried the wrong certificate")
	}
	if len(body.Chain) != 1 {
		t.Fatalf("chain has %d entries, want 1", len(body.Chain))
	}
	if body.Backend != "fake" {
		t.Fatalf("backend = %q, want %q", body.Backend, "fake")
	}

	// The identity handed to the backend is the one proven by mTLS, and the
	// SID is the one the snapshot named — neither came from the request.
	if backend.got.SPIFFEID != mappedCaller {
		t.Errorf("backend saw SPIFFEID %q, want %q", backend.got.SPIFFEID, mappedCaller)
	}
	if backend.got.ADSID != mappedSID {
		t.Errorf("backend saw ADSID %q, want %q", backend.got.ADSID, mappedSID)
	}
}

func TestWrongMethodIsNotAllowed(t *testing.T) {
	srv, ca := newTestServer(t, subordinate.New())
	c := clientWith(ca, ca.workloadCert(t, mappedCaller))

	resp, err := c.Get(srv.URL + IssuePath)
	if err != nil {
		t.Fatalf("GET %s: %v", IssuePath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != http.MethodPost {
		t.Fatalf("Allow = %q, want %q", got, http.MethodPost)
	}
}

func TestUnknownRouteIsNotFound(t *testing.T) {
	srv, ca := newTestServer(t, subordinate.New())
	c := clientWith(ca, ca.workloadCert(t, mappedCaller))

	resp, err := c.Get(srv.URL + "/debug/pprof/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestBadRequestsAreRefused(t *testing.T) {
	srv, ca := newTestServer(t, subordinate.New())
	c := clientWith(ca, ca.workloadCert(t, mappedCaller))

	cases := []struct {
		name        string
		contentType string
		body        string
		status      int
	}{
		{"no content type", "", issueBody(t), http.StatusUnsupportedMediaType},
		{"wrong content type", "text/plain", issueBody(t), http.StatusUnsupportedMediaType},
		{"charset parameter is fine", "application/json; charset=utf-8", issueBody(t), http.StatusNotImplemented},
		{"not json", "application/json", "{", http.StatusBadRequest},
		{"unknown field", "application/json", `{"csr":"x","ad_sid":"S-1-5-21-1-2-3-500"}`, http.StatusBadRequest},
		{"trailing document", "application/json", `{"csr":"x"}{"csr":"y"}`, http.StatusBadRequest},
		{"empty csr", "application/json", `{"csr":""}`, http.StatusBadRequest},
		{"csr is not pem", "application/json", `{"csr":"not pem at all"}`, http.StatusBadRequest},
		{"wrong pem type", "application/json", `{"csr":"-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postIssue(t, c, srv.URL, tc.contentType, tc.body)
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

// A well-formed PEM block that is not a PKCS#10 request must be refused as a
// bad request, not treated as an internal failure.
func TestNonCSRDERIsRefused(t *testing.T) {
	srv, ca := newTestServer(t, subordinate.New())
	c := clientWith(ca, ca.workloadCert(t, mappedCaller))

	garbage := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00},
	}))
	body, err := json.Marshal(issueRequest{CSR: garbage})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := postIssue(t, c, srv.URL, "application/json", string(body))
	wantStatusAndReason(t, resp, http.StatusBadRequest, broker.ReasonInvalidRequest)
}

func TestOversizedBodyIsRefused(t *testing.T) {
	srv, ca := newTestServer(t, subordinate.New())
	c := clientWith(ca, ca.workloadCert(t, mappedCaller))

	body := `{"csr":"` + strings.Repeat("A", maxRequestBytes+1) + `"}`
	resp := postIssue(t, c, srv.URL, "application/json", body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}
