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
//  2. Resolve the target AD account from the mapping snapshot. A miss refuses.
//  3. Only then parse the CSR.
//  4. Validate the assembled request as a whole.
//  5. Hand it to the backend.
//
// Step 2 before step 3 is on purpose: an unmapped caller gets no certificate
// whatever it sent, so it should never reach the X.509 parser at all.
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

	// now is overridable in tests. Zero value means time.Now.
	now func() time.Time
}

// Broker resolves an authenticated caller to an AD account and asks a backend
// to issue for it.
type Broker struct {
	registry *mapping.Registry
	backend  issuer.Issuer
	log      *slog.Logger
	maxAge   time.Duration
	skew     time.Duration
	now      func() time.Time
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
	b := &Broker{
		registry: cfg.Registry,
		backend:  cfg.Backend,
		log:      cfg.Logger,
		maxAge:   cfg.MaxSnapshotAge,
		skew:     cfg.ClockSkew,
		now:      cfg.now,
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

	b.warnIfStale(ctx, log)

	// Before the CSR is even looked at. See the package comment.
	sid, err := b.registry.Lookup(callerID)
	if err != nil {
		return nil, b.refused(ctx, log, refuse(ReasonNoMapping, err,
			"no mapping entry for caller"))
	}
	log = log.With(slog.String("ad_sid", sid))

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, b.refused(ctx, log, refuse(ReasonInvalidRequest, err,
			"not a parseable PKCS#10 certificate request"))
	}

	// Assembled from three sources with three different levels of trust: the
	// CSR is workload-controlled, the SPIFFE ID was proven by mTLS, and the
	// SID came from the snapshot. Validate is the one place that guards all
	// of them, and it runs before any backend sees the request.
	req := issuer.Request{CSR: csr, SPIFFEID: callerID, ADSID: sid}
	if err := req.Validate(); err != nil {
		return nil, b.refused(ctx, log, refuse(ReasonInvalidRequest, err,
			"request failed validation"))
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

	log.InfoContext(ctx, "issued credential",
		slog.String("serial", cred.Certificate.SerialNumber.String()),
		slog.Time("not_after", cred.Certificate.NotAfter),
		slog.Int("chain_len", len(cred.Chain)),
	)
	return cred, nil
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
