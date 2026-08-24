package broker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer/subordinate"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/mapping"
)

const (
	mappedCaller   = "spiffe://example.org/workload/db"
	unmappedCaller = "spiffe://example.org/workload/nobody"
	mappedSID      = "S-1-5-21-3734714977-4168152908-3762407930-1103"
)

// recordingIssuer captures what the broker handed it, so tests can assert on
// the request the backend would have acted on rather than only on the result.
type recordingIssuer struct {
	got  *issuer.Request
	cred *issuer.Credential
	err  error
}

func (r *recordingIssuer) Name() string { return "recording" }

func (r *recordingIssuer) Issue(_ context.Context, req issuer.Request) (*issuer.Credential, error) {
	got := req
	r.got = &got
	return r.cred, r.err
}

func snapshot(t *testing.T, generatedAt time.Time) *mapping.Registry {
	t.Helper()
	doc := fmt.Sprintf(`{
	  "version": "test-1",
	  "generated_at": %q,
	  "entries": [{"spiffe_id": %q, "ad_sid": %q}]
	}`, generatedAt.UTC().Format(time.RFC3339), mappedCaller, mappedSID)
	r, err := mapping.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse snapshot: %v", err)
	}
	return r
}

// newCSR returns a valid PKCS#10 in DER. The subject is deliberately an
// account the caller must never be able to become by asking.
func newCSR(t *testing.T) []byte {
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
	return der
}

// tamperedCSR returns a syntactically valid PKCS#10 whose signature does not
// verify, which is what a caller asking for a key it does not hold produces.
func tamperedCSR(t *testing.T) []byte {
	t.Helper()
	der := newCSR(t)
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	// Flip a bit inside the signature as it sits in the DER.
	sig := csr.Signature
	idx := bytes.LastIndex(der, sig)
	if idx < 0 {
		t.Fatal("could not locate signature within CSR DER")
	}
	der[idx+len(sig)-1] ^= 0xff
	return der
}

func newBroker(t *testing.T, backend issuer.Issuer, mutate func(*Config)) *Broker {
	t.Helper()
	cfg := Config{
		Registry: snapshot(t, time.Now().Add(-time.Hour)),
		Backend:  backend,
		Logger:   slog.New(slog.DiscardHandler),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

func wantRefusal(t *testing.T, err error, reason Reason) *Error {
	t.Helper()
	if err == nil {
		t.Fatalf("expected refusal with reason %q, got success", reason)
	}
	var bErr *Error
	if !errors.As(err, &bErr) {
		t.Fatalf("error is not a *broker.Error: %v", err)
	}
	if bErr.Reason != reason {
		t.Fatalf("reason = %q, want %q (%v)", bErr.Reason, reason, err)
	}
	return bErr
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	if _, err := New(Config{Backend: subordinate.New()}); err == nil {
		t.Error("accepted a config with no registry")
	}
	if _, err := New(Config{Registry: snapshot(t, time.Now())}); err == nil {
		t.Error("accepted a config with no backend")
	}
}

// A future-dated snapshot means a broken producer clock or a tampered
// artifact, and it makes every freshness bound meaningless. The process must
// not come up on one.
func TestNewRefusesFutureDatedSnapshot(t *testing.T) {
	_, err := New(Config{
		Registry: snapshot(t, time.Now().Add(2*time.Hour)),
		Backend:  subordinate.New(),
		Logger:   slog.New(slog.DiscardHandler),
	})
	if err == nil {
		t.Fatal("accepted a future-dated snapshot")
	}
	if !errors.Is(err, mapping.ErrFutureDated) {
		t.Fatalf("error does not wrap ErrFutureDated: %v", err)
	}
}

// Staleness is the opposite call: mappings change rarely and issuance must not
// flap with a producer outage, so a stale snapshot keeps serving — loudly.
func TestStaleSnapshotStillServesAndIsReported(t *testing.T) {
	var logged bytes.Buffer
	backend := &recordingIssuer{err: issuer.ErrNotImplemented}
	b := newBroker(t, backend, func(cfg *Config) {
		cfg.Registry = snapshot(t, time.Now().Add(-48*time.Hour))
		cfg.MaxSnapshotAge = time.Hour
		cfg.Logger = slog.New(slog.NewTextHandler(&logged, nil))
	})

	// Reaching the backend at all is the point: staleness did not short-circuit.
	wantRefusal(t, mustIssue(t, b, mappedCaller, newCSR(t)), ReasonNotImplemented)
	if backend.got == nil {
		t.Fatal("stale snapshot prevented the request from reaching the backend")
	}
	if !bytes.Contains(logged.Bytes(), []byte("stale mapping snapshot")) {
		t.Fatalf("staleness was not reported; log was:\n%s", logged.String())
	}
}

func mustIssue(t *testing.T, b *Broker, caller string, csrDER []byte) error {
	t.Helper()
	cred, err := b.Issue(context.Background(), caller, csrDER)
	if err == nil {
		t.Fatalf("expected a refusal, got credential %v", cred)
	}
	return err
}

// The fail-closed default, and the single most important refusal in the
// service: authenticated, but not mapped to any account.
func TestUnmappedCallerIsRefused(t *testing.T) {
	b := newBroker(t, &recordingIssuer{}, nil)
	err := mustIssue(t, b, unmappedCaller, newCSR(t))
	bErr := wantRefusal(t, err, ReasonNoMapping)
	if !errors.Is(bErr, mapping.ErrNoMapping) {
		t.Errorf("refusal does not wrap mapping.ErrNoMapping: %v", bErr)
	}
}

// The mapping lookup runs before the CSR is parsed, so an unmapped caller
// cannot reach the X.509 parser at all. A malformed CSR from an unmapped
// caller must therefore be reported as no_mapping, not invalid_request.
func TestUnmappedCallerNeverReachesTheCSRParser(t *testing.T) {
	b := newBroker(t, &recordingIssuer{}, nil)
	err := mustIssue(t, b, unmappedCaller, []byte("this is not DER"))
	wantRefusal(t, err, ReasonNoMapping)
}

func TestMalformedCallerIDIsRefused(t *testing.T) {
	b := newBroker(t, &recordingIssuer{}, nil)
	for _, id := range []string{
		"",
		"example.org/workload/db",
		"https://example.org/workload/db",
		"spiffe://example.org",
		"spiffe://EXAMPLE.org/workload/db",
		"spiffe://example.org/workload/db/",
	} {
		err := mustIssue(t, b, id, newCSR(t))
		wantRefusal(t, err, ReasonUnauthenticated)
	}
}

func TestUnparseableCSRIsRefused(t *testing.T) {
	b := newBroker(t, &recordingIssuer{}, nil)
	err := mustIssue(t, b, mappedCaller, []byte{0x30, 0x00, 0xff})
	wantRefusal(t, err, ReasonInvalidRequest)
}

// Without proof of possession the broker would mint an AD credential usable by
// whoever actually holds the private key.
func TestBrokenProofOfPossessionIsRefused(t *testing.T) {
	backend := &recordingIssuer{}
	b := newBroker(t, backend, nil)
	err := mustIssue(t, b, mappedCaller, tamperedCSR(t))
	wantRefusal(t, err, ReasonInvalidRequest)
	if backend.got != nil {
		t.Fatal("a CSR with a bad signature reached the backend")
	}
}

// The request the backend acts on must carry the identity the caller proved
// and the SID the snapshot named — never anything the caller chose.
func TestBackendReceivesProvenIdentityAndMappedSID(t *testing.T) {
	backend := &recordingIssuer{err: issuer.ErrNotImplemented}
	b := newBroker(t, backend, nil)
	wantRefusal(t, mustIssue(t, b, mappedCaller, newCSR(t)), ReasonNotImplemented)

	if backend.got == nil {
		t.Fatal("backend was never called")
	}
	if backend.got.SPIFFEID != mappedCaller {
		t.Errorf("SPIFFEID = %q, want %q", backend.got.SPIFFEID, mappedCaller)
	}
	if backend.got.ADSID != mappedSID {
		t.Errorf("ADSID = %q, want %q", backend.got.ADSID, mappedSID)
	}
	// The CSR asked to be Administrator. It is carried through untouched
	// because the backend needs the public key, and it is the backend's
	// contract — not the broker's stripping — that keeps the subject inert.
	if got := backend.got.CSR.Subject.CommonName; got != "Administrator" {
		t.Errorf("CSR subject CN = %q, want it passed through unmodified", got)
	}
}

// The unimplemented backends must surface as a refusal with its own reason,
// never as an internal error and never as anything a caller could read as
// "try another way".
func TestUnimplementedBackendSurfacesAsNotImplemented(t *testing.T) {
	b := newBroker(t, subordinate.New(), nil)
	err := mustIssue(t, b, mappedCaller, newCSR(t))
	bErr := wantRefusal(t, err, ReasonNotImplemented)
	if !errors.Is(bErr, issuer.ErrNotImplemented) {
		t.Errorf("refusal does not wrap issuer.ErrNotImplemented: %v", bErr)
	}
}

func TestBackendFailureIsInternal(t *testing.T) {
	b := newBroker(t, &recordingIssuer{err: errors.New("CA said no")}, nil)
	err := mustIssue(t, b, mappedCaller, newCSR(t))
	bErr := wantRefusal(t, err, ReasonInternal)
	// The caller is told nothing about the CA; the detail stays in the log.
	if bErr.Message != "issuance failed" {
		t.Errorf("caller-visible message = %q, want it to reveal nothing", bErr.Message)
	}
	if !bytes.Contains([]byte(bErr.Error()), []byte("CA said no")) {
		t.Errorf("full error lost the cause: %v", bErr)
	}
}

// A backend returning (nil, nil) is a contract violation, not a success.
func TestBackendReturningNothingIsRefused(t *testing.T) {
	b := newBroker(t, &recordingIssuer{}, nil)
	err := mustIssue(t, b, mappedCaller, newCSR(t))
	wantRefusal(t, err, ReasonInternal)
}

func TestSuccessfulIssuanceIsReturned(t *testing.T) {
	want := &issuer.Credential{
		Certificate: &x509.Certificate{SerialNumber: big.NewInt(1)},
	}
	b := newBroker(t, &recordingIssuer{cred: want}, nil)
	got, err := b.Issue(context.Background(), mappedCaller, newCSR(t))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got != want {
		t.Fatalf("Issue returned %v, want the backend's credential", got)
	}
}
