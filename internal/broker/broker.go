// Package broker implements the authenticate-and-map path: everything that
// happens between a caller proving who it is and a backend being asked to
// mint a certificate.
//
// It is deliberately transport-independent. Nothing here knows about HTTP,
// gRPC, sockets, or wire formats — it takes a SPIFFE ID the transport has
// already proven and a DER-encoded PKCS#10 request, and it either returns a
// credential or refuses with a classified Error. That boundary is what makes
// the transport choice reversible, and it means the security properties are
// testable without standing up a server.
//
// The order of operations is part of the design, not an accident of writing:
//
//  1. Re-check the caller's SPIFFE ID is canonical.
//  2. Take a token from the caller's own rate limit.
//  3. Resolve the target AD account from the mapping snapshot. A miss refuses.
//  4. Only then parse the CSR.
//  5. Validate the assembled request as a whole.
//  6. Take a token from the global rate limit.
//  7. Hand it to the backend.
//  8. Durably record the credential before returning it.
//
// Step 3 before step 4 is on purpose: an unmapped caller gets no certificate
// whatever it sent, so it should never reach the X.509 parser at all.
//
// The two limits are taken at different points because they protect different
// things. The per-caller one is taken first, before any parsing, because it
// bounds the CPU one workload can spend — proof-of-possession verification is
// the expensive step and it happens below. The global one is taken last,
// immediately before the backend call, because what it protects is the CA:
// a request refused for any other reason never reached the CA, so it must not
// consume the budget for reaching it.
//
// Step 8 can refuse a credential that already exists at the CA. That is
// deliberate and it is the honest trade — see recordIssuance.
package broker

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/mapping"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/ratelimit"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/record"
)

// DefaultClockSkew is the tolerance applied to a snapshot's generated_at when
// deciding whether it is future-dated.
const DefaultClockSkew = 5 * time.Minute

// Config configures a Broker.
type Config struct {
	// Registry is the loaded mapping snapshot. Required.
	Registry *mapping.Registry

	// Backend mints the certificate. Required.
	Backend issuer.Issuer

	// Logger receives the issuance decision record for every request —
	// refusals included, exactly once each. Defaults to slog.Default().
	Logger *slog.Logger

	// MaxSnapshotAge bounds how old the snapshot may be before staleness is
	// reported. Zero disables the check.
	//
	// Staleness does not refuse issuance. Mappings change rarely and issuance
	// must not flap with a producer outage, so the policy is to keep serving
	// the last known good snapshot and say so loudly on every request. A
	// future-dated snapshot is treated differently — see New.
	MaxSnapshotAge time.Duration

	// ClockSkew is the tolerance for a future-dated snapshot. Zero means
	// DefaultClockSkew.
	ClockSkew time.Duration

	// CallerLimit bounds how often one caller may be served. Nil disables it.
	CallerLimit *ratelimit.Keyed

	// GlobalLimit bounds the broker's aggregate rate of asking the backend to
	// issue — under the adcs backend, its aggregate draw on a CA the rest of
	// the forest also depends on. Nil disables it.
	GlobalLimit *ratelimit.Limiter

	// Record durably accounts for every credential issued. Required: a
	// deployment that cannot record what it issued cannot revoke it either.
	// Use record.Discard explicitly to opt out, which is what a backend that
	// cannot issue does.
	Record record.Recorder

	// now is overridable in tests. Zero value means time.Now.
	now func() time.Time
}

// Broker resolves an authenticated caller to an AD account and asks a backend
// to issue for it.
type Broker struct {
	registry    *mapping.Registry
	backend     issuer.Issuer
	log         *slog.Logger
	maxAge      time.Duration
	skew        time.Duration
	callerLimit *ratelimit.Keyed
	globalLimit *ratelimit.Limiter
	record      record.Recorder
	now         func() time.Time
}

// New validates cfg and returns a Broker.
//
// A future-dated snapshot refuses construction. Unlike staleness that is never
// benign: it means a broken producer clock or a tampered artifact, and it
// makes any freshness bound meaningless, so the process should not start
// rather than serve from it.
func New(cfg Config) (*Broker, error) {
	if cfg.Registry == nil {
		return nil, errors.New("broker: no mapping registry")
	}
	if cfg.Backend == nil {
		return nil, errors.New("broker: no issuer backend")
	}
	// Not defaulted to Discard. A nil Recorder here would be a deployment
	// that silently keeps no account of what it issued, and the whole value
	// of the record is that it is not optional by accident.
	if cfg.Record == nil {
		return nil, errors.New("broker: no issuance recorder")
	}
	b := &Broker{
		registry:    cfg.Registry,
		backend:     cfg.Backend,
		log:         cfg.Logger,
		maxAge:      cfg.MaxSnapshotAge,
		skew:        cfg.ClockSkew,
		callerLimit: cfg.CallerLimit,
		globalLimit: cfg.GlobalLimit,
		record:      cfg.Record,
		now:         cfg.now,
	}
	if b.log == nil {
		b.log = slog.Default()
	}
	if b.skew == 0 {
		b.skew = DefaultClockSkew
	}
	if b.now == nil {
		b.now = time.Now
	}

	// maxAge 0 disables the staleness arm, leaving only the future-dated
	// check. Staleness at startup is legitimate — a broker restarting during
	// a producer outage should come back up on the last known good snapshot.
	if err := b.registry.CheckFreshness(b.now(), 0, b.skew); err != nil {
		return nil, fmt.Errorf("broker: refusing to serve mapping snapshot: %w", err)
	}
	return b, nil
}

// BackendName is the configured issuance shape, for transports that report it
// back to callers and for startup logging.
func (b *Broker) BackendName() string { return b.backend.Name() }

// SnapshotVersion is the content revision of the mapping snapshot in force.
func (b *Broker) SnapshotVersion() string { return b.registry.Version() }

// MappingCount is the number of SPIFFE IDs the snapshot maps.
func (b *Broker) MappingCount() int { return b.registry.Len() }

// Issue resolves callerID to an AD account and asks the configured backend for
// a certificate binding csrDER's public key to it.
//
// callerID must be an identity the transport has already proven — read out of
// a verified peer certificate, never out of a request body. csrDER is the raw
// PKCS#10 DER; nothing in it is trusted but the public key and the
// proof-of-possession signature over it.
//
// Every non-nil error is an *Error carrying a Reason, and has already been
// logged. A transport should map the Reason to its own status vocabulary and
// return Message to the caller, not log it a second time.
func (b *Broker) Issue(ctx context.Context, callerID string, csrDER []byte) (*issuer.Credential, error) {
	log := b.log.With(
		slog.String("caller", callerID),
		slog.String("backend", b.backend.Name()),
		slog.String("snapshot_version", b.registry.Version()),
	)

	// The transport took this out of a verified certificate, but the check
	// runs again here: this package has to hold its guarantees under any
	// transport, including one written later by someone who assumed the
	// broker was checking.
	if err := mapping.ValidateSPIFFEID(callerID); err != nil {
		return nil, b.refused(ctx, log, refuse(ReasonUnauthenticated, err,
			"caller identity is not a canonical SPIFFE ID"))
	}

	// Before the mapping lookup and before any parsing: this limit exists to
	// bound the work one caller can cause, so it has to come before the work.
	if ok, retry := b.callerLimit.Allow(callerID); !ok {
		return nil, b.refused(ctx, log, refuseRetry("too many requests from this caller", retry))
	}

	b.warnIfStale(ctx, log)

	// Before the CSR is even looked at. See the package comment.
	account, err := b.registry.Lookup(callerID)
	if err != nil {
		return nil, b.refused(ctx, log, refuse(ReasonNoMapping, err,
			"no mapping entry for caller"))
	}
	log = log.With(slog.String("ad_sid", account.SID))
	if account.Name != "" {
		log = log.With(slog.String("ad_account", account.Name))
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, b.refused(ctx, log, refuse(ReasonInvalidRequest, err,
			"not a parseable PKCS#10 certificate request"))
	}

	// Assembled from three sources with three different levels of trust: the
	// CSR is workload-controlled, the SPIFFE ID was proven by mTLS, and the
	// SID came from the snapshot. Validate is the one place that guards all
	// of them, and it runs before any backend sees the request.
	req := issuer.Request{CSR: csr, SPIFFEID: callerID, ADSID: account.SID, ADAccount: account.Name}
	if err := req.Validate(); err != nil {
		return nil, b.refused(ctx, log, refuse(ReasonInvalidRequest, err,
			"request failed validation"))
	}

	// Last thing before the CA is touched. Everything above this line can
	// refuse without reaching the CA, so it must not spend the CA's budget.
	if ok, retry := b.globalLimit.Allow(); !ok {
		return nil, b.refused(ctx, log, refuseRetry("the broker is at its issuance rate limit", retry))
	}

	cred, err := b.backend.Issue(ctx, req)
	if err != nil {
		if errors.Is(err, issuer.ErrNotImplemented) {
			return nil, b.refused(ctx, log, refuse(ReasonNotImplemented, err,
				fmt.Sprintf("backend %q cannot issue yet", b.backend.Name())))
		}
		return nil, b.refused(ctx, log, refuse(ReasonInternal, err, "issuance failed"))
	}
	// A backend that returns (nil, nil) would otherwise hand the transport a
	// success with nothing in it. Treat the contract violation as a refusal.
	if cred == nil || cred.Certificate == nil {
		return nil, b.refused(ctx, log, refuse(ReasonInternal,
			errors.New("backend returned no certificate"), "issuance failed"))
	}

	if err := b.recordIssuance(ctx, log, callerID, account, cred); err != nil {
		return nil, err
	}

	log.InfoContext(ctx, "issued credential",
		slog.String("serial", cred.Certificate.SerialNumber.String()),
		slog.Time("not_after", cred.Certificate.NotAfter),
		slog.Int("chain_len", len(cred.Chain)),
	)
	return cred, nil
}

// recordIssuance writes the durable account of cred, and refuses the request
// if it cannot.
//
// By this point the certificate exists — under the adcs backend the CA has
// already issued it and nothing here can take that back. Refusing anyway is
// still the right answer, and the reasoning is worth stating because the
// alternative looks reasonable:
//
// If the credential is returned, a certificate that authenticates as an AD
// account is in circulation with no record of its serial, so nobody can
// revoke it and nobody can find out it exists. If it is refused, the same
// certificate exists at the CA but was never delivered — the workload holds
// the private key and never learned the certificate, which makes it inert.
// One of those is recoverable and the other is not.
//
// What the operator must do about it is not silent: the log line below names
// the serial that exists at the CA and was not handed over, which is enough
// to go and revoke it by hand.
func (b *Broker) recordIssuance(ctx context.Context, log *slog.Logger, callerID string, account mapping.Account, cred *issuer.Credential) error {
	iss := record.FromCertificate(cred.Certificate)
	iss.Time = b.now()
	iss.Caller = callerID
	iss.Backend = b.backend.Name()
	iss.SnapshotVersion = b.registry.Version()
	iss.ADSID = account.SID
	iss.ADAccount = account.Name

	if err := b.record.Record(ctx, iss); err != nil {
		log.ErrorContext(ctx, "issued a credential and could not record it; refusing to return it",
			slog.String("serial", iss.Serial),
			slog.String("issuer", iss.Issuer),
			slog.String("fingerprint", iss.Fingerprint),
			slog.String("detail", err.Error()),
			slog.String("operator_action", "this certificate exists at the CA and was never delivered; revoke it"),
		)
		return b.refused(ctx, log, refuse(ReasonInternal, err,
			"issuance could not be recorded"))
	}
	return nil
}

// refused logs a refusal and returns it, so that every refusal is recorded
// exactly once, at the point it is raised, with the context accumulated so
// far. Transports must not log it again.
func (b *Broker) refused(ctx context.Context, log *slog.Logger, err *Error) *Error {
	log.WarnContext(ctx, "refused to issue",
		slog.String("reason", string(err.Reason)),
		slog.String("detail", err.Error()),
	)
	return err
}

// warnIfStale reports a snapshot past its freshness bound without refusing.
//
// It logs on every affected request rather than once per transition. That is
// deliberate: this is a low-rate service, and "which snapshot was in force"
// belongs in the record of each individual issuance decision, not only in a
// line somebody has to go looking for.
func (b *Broker) warnIfStale(ctx context.Context, log *slog.Logger) {
	if b.maxAge <= 0 {
		return
	}
	now := b.now()
	if err := b.registry.CheckFreshness(now, b.maxAge, b.skew); err != nil {
		log.WarnContext(ctx, "serving a stale mapping snapshot",
			slog.String("detail", err.Error()),
			slog.Duration("age", b.registry.Age(now)),
			slog.Duration("bound", b.maxAge),
		)
	}
}
