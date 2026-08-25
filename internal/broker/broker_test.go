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
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/ratelimit"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/record"
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
		Record:   record.Discard{},
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
	// Not defaulted to a discarding recorder: a broker that keeps no account
	// of what it issued cannot revoke it, and that has to be chosen, not
	// inherited from a zero value.
	if _, err := New(Config{
		Registry: snapshot(t, time.Now()),
		Backend:  subordinate.New(),
	}); err == nil {
		t.Error("accepted a config with no issuance recorder")
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
		Record:   record.Discard{},
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

// --- rate limiting -------------------------------------------------------

// A caller that retries in a tight loop must be cut off, and told when to come
// back rather than left to guess.
func TestPerCallerRateLimitRefusesWithARetryDelay(t *testing.T) {
	backend := &recordingIssuer{err: issuer.ErrNotImplemented}
	b := newBroker(t, backend, func(cfg *Config) {
		// One token, refilling slowly enough that no real time during the
		// test can hand back a second one.
		cfg.CallerLimit = ratelimit.NewKeyed(0.0001, 1, time.Minute)
	})

	wantRefusal(t, mustIssue(t, b, mappedCaller, newCSR(t)), ReasonNotImplemented)
	if backend.got == nil {
		t.Fatal("the first request never reached the backend")
	}

	backend.got = nil
	bErr := wantRefusal(t, mustIssue(t, b, mappedCaller, newCSR(t)), ReasonRateLimited)
	if bErr.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %v, want a positive delay the caller can act on", bErr.RetryAfter)
	}
	if backend.got != nil {
		t.Error("a rate-limited request still reached the backend")
	}
}

// The limit is per caller, not shared. One workload retrying must not deny
// service to every other workload in the trust domain.
func TestPerCallerRateLimitIsNotShared(t *testing.T) {
	b := newBroker(t, &recordingIssuer{err: issuer.ErrNotImplemented}, func(cfg *Config) {
		cfg.CallerLimit = ratelimit.NewKeyed(0.0001, 1, time.Minute)
	})

	wantRefusal(t, mustIssue(t, b, mappedCaller, newCSR(t)), ReasonNotImplemented)
	wantRefusal(t, mustIssue(t, b, mappedCaller, newCSR(t)), ReasonRateLimited)

	// A different caller still gets its own answer — no_mapping, which is a
	// decision about that caller, not the exhausted budget of another one.
	wantRefusal(t, mustIssue(t, b, unmappedCaller, newCSR(t)), ReasonNoMapping)
}

// The global limit exists to bound what this broker asks of the CA. A request
// refused for any other reason never reached the CA, so it must not have spent
// any of that budget.
func TestGlobalRateLimitIsSpentOnlyOnRequestsThatReachTheBackend(t *testing.T) {
	backend := &recordingIssuer{err: issuer.ErrNotImplemented}
	b := newBroker(t, backend, func(cfg *Config) {
		cfg.GlobalLimit = ratelimit.New(0.0001, 1)
	})

	// Three refusals that stop above the backend: no mapping, an unparseable
	// CSR, and a proof-of-possession that does not verify.
	wantRefusal(t, mustIssue(t, b, unmappedCaller, newCSR(t)), ReasonNoMapping)
	wantRefusal(t, mustIssue(t, b, mappedCaller, []byte("not DER")), ReasonInvalidRequest)
	wantRefusal(t, mustIssue(t, b, mappedCaller, tamperedCSR(t)), ReasonInvalidRequest)

	// The single global token is therefore still there.
	wantRefusal(t, mustIssue(t, b, mappedCaller, newCSR(t)), ReasonNotImplemented)
	if backend.got == nil {
		t.Fatal("refused requests consumed the global budget")
	}

	// And now it is spent.
	backend.got = nil
	wantRefusal(t, mustIssue(t, b, mappedCaller, newCSR(t)), ReasonRateLimited)
	if backend.got != nil {
		t.Error("a globally rate-limited request still reached the backend")
	}
}

// --- the issuance record -------------------------------------------------

type fakeRecorder struct {
	got  []record.Issuance
	err  error
	shut bool
}

func (r *fakeRecorder) Record(_ context.Context, iss record.Issuance) error {
	if r.err != nil {
		return r.err
	}
	r.got = append(r.got, iss)
	return nil
}

func (r *fakeRecorder) Close() error { r.shut = true; return nil }

// The record has to carry enough to revoke the certificate later, because the
// CA is not a searchable index of "things this broker asked for".
func TestIssuanceIsRecordedWithWhatRevocationNeeds(t *testing.T) {
	leaf := selfSigned(t)
	rec := &fakeRecorder{}
	b := newBroker(t, &recordingIssuer{cred: &issuer.Credential{Certificate: leaf}}, func(cfg *Config) {
		cfg.Record = rec
	})

	if _, err := b.Issue(context.Background(), mappedCaller, newCSR(t)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(rec.got) != 1 {
		t.Fatalf("recorded %d issuances, want 1", len(rec.got))
	}
	got := rec.got[0]
	if got.Serial != leaf.SerialNumber.String() {
		t.Errorf("Serial = %q, want %q", got.Serial, leaf.SerialNumber.String())
	}
	if got.Issuer != leaf.Issuer.String() {
		t.Errorf("Issuer = %q, want %q", got.Issuer, leaf.Issuer.String())
	}
	if got.Caller != mappedCaller {
		t.Errorf("Caller = %q, want %q", got.Caller, mappedCaller)
	}
	if got.ADSID != mappedSID {
		t.Errorf("ADSID = %q, want %q", got.ADSID, mappedSID)
	}
	if got.SnapshotVersion != "test-1" {
		t.Errorf("SnapshotVersion = %q, want %q", got.SnapshotVersion, "test-1")
	}
	if got.Fingerprint == "" || got.Time.IsZero() {
		t.Errorf("record is missing a fingerprint or a timestamp: %+v", got)
	}
	if !got.NotAfter.Equal(leaf.NotAfter) {
		t.Errorf("NotAfter = %v, want %v", got.NotAfter, leaf.NotAfter)
	}
}

// Nothing is recorded for a refusal. The record answers "what exists", and a
// refusal created nothing — and a durable line per refused request would turn
// a refused flood into disk exhaustion.
func TestRefusalsAreNotRecorded(t *testing.T) {
	rec := &fakeRecorder{}
	b := newBroker(t, &recordingIssuer{err: issuer.ErrNotImplemented}, func(cfg *Config) {
		cfg.Record = rec
	})
	wantRefusal(t, mustIssue(t, b, mappedCaller, newCSR(t)), ReasonNotImplemented)
	wantRefusal(t, mustIssue(t, b, unmappedCaller, newCSR(t)), ReasonNoMapping)
	if len(rec.got) != 0 {
		t.Fatalf("recorded %d refusals, want none: %+v", len(rec.got), rec.got)
	}
}

// A credential that cannot be recorded cannot be revoked, so it is not handed
// over. The certificate still exists at the CA — that is unavoidable by this
// point — but it was never delivered, which leaves it inert.
func TestUnrecordableIssuanceIsRefused(t *testing.T) {
	var logged bytes.Buffer
	leaf := selfSigned(t)
	b := newBroker(t, &recordingIssuer{cred: &issuer.Credential{Certificate: leaf}}, func(cfg *Config) {
		cfg.Record = &fakeRecorder{err: errors.New("disk full")}
		cfg.Logger = slog.New(slog.NewTextHandler(&logged, nil))
	})

	cred, err := b.Issue(context.Background(), mappedCaller, newCSR(t))
	if cred != nil {
		t.Fatal("an unrecordable credential was handed to the caller")
	}
	wantRefusal(t, err, ReasonInternal)

	// The operator has to be able to find and revoke it by hand, so the
	// serial that exists at the CA must be in the log.
	if !bytes.Contains(logged.Bytes(), []byte(leaf.SerialNumber.String())) {
		t.Errorf("the log does not name the serial that exists at the CA:\n%s", logged.String())
	}
}

// selfSigned returns a parsed certificate with a real serial, issuer, and
// validity window, so record fields are asserted against something a CA would
// plausibly have produced rather than a zero value.
func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x5eadbeef),
		Subject:      pkix.Name{CommonName: "pkinittest"},
		Issuer:       pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore:    time.Now().Add(-time.Minute).Truncate(time.Second),
		NotAfter:     time.Now().Add(time.Hour).Truncate(time.Second),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}
