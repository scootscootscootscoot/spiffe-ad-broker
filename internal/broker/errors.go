package broker

import (
	"fmt"
	"time"
)

// Reason classifies a refusal.
//
// It exists so a transport can decide what to tell the caller without
// inspecting error strings, and so that every path out of Issue that is not a
// credential has to be deliberately categorised at the point it is raised.
// Adding a new failure mode means choosing a Reason for it, which is the
// intent: a refusal that nobody classified is a refusal nobody thought about.
type Reason string

const (
	// ReasonUnauthenticated: the caller's identity is missing or unusable. The
	// transport should already have rejected these during the TLS handshake;
	// reaching one here means the peer certificate verified but did not carry
	// a usable SPIFFE ID.
	ReasonUnauthenticated Reason = "unauthenticated"

	// ReasonInvalidRequest: the caller is known, but what it sent is malformed
	// — an unparseable PKCS#10 request, a proof-of-possession that does not
	// verify.
	ReasonInvalidRequest Reason = "invalid_request"

	// ReasonNoMapping: the caller authenticated but has no mapping entry.
	//
	// This is the fail-closed default and the most important refusal in the
	// service. There is no wildcard, no default account, and no derivation
	// from the SPIFFE ID path — a certificate carrying a SID authenticates as
	// that account, so a guess here would be an account-takeover primitive.
	ReasonNoMapping Reason = "no_mapping"

	// ReasonNotImplemented: the configured backend cannot issue yet. It is a
	// refusal, never a fallback: no caller may read it as permission to obtain
	// the credential by some other route.
	ReasonNotImplemented Reason = "not_implemented"

	// ReasonRateLimited: the caller is known, mapped, and would otherwise
	// have been issued a credential — it simply asked too often, or the
	// broker's aggregate draw on the CA is already at its cap.
	//
	// It is the one refusal that says "try again later" and means it, so it
	// is the one refusal that carries a RetryAfter.
	ReasonRateLimited Reason = "rate_limited"

	// ReasonInternal: the broker failed for a reason the caller cannot act on.
	ReasonInternal Reason = "internal"
)

// Error is a refusal to issue.
//
// It carries two messages on purpose. Message goes back to the caller and says
// only what that caller can act on; cause holds the full detail and stays in
// the log. The split matters most for ReasonInternal, where the detail can
// name backend hosts, file paths, or CA errors that a workload has no business
// seeing.
type Error struct {
	Reason  Reason
	Message string

	// RetryAfter is how long the caller should wait before trying again. It
	// is set only for ReasonRateLimited; every other refusal is a decision
	// that waiting will not change, and offering a delay for one of those
	// would invite a retry loop against a permanent no.
	RetryAfter time.Duration

	cause error
}

func (e *Error) Error() string {
	if e.cause == nil {
		return fmt.Sprintf("%s: %s", e.Reason, e.Message)
	}
	return fmt.Sprintf("%s: %s: %v", e.Reason, e.Message, e.cause)
}

// Unwrap exposes the cause so callers can match on the underlying sentinel —
// mapping.ErrNoMapping, issuer.ErrNotImplemented — with errors.Is.
func (e *Error) Unwrap() error { return e.cause }

// refuse builds an Error. cause may be nil.
func refuse(reason Reason, cause error, message string) *Error {
	return &Error{Reason: reason, Message: message, cause: cause}
}

// refuseRetry builds a ReasonRateLimited Error carrying a retry delay.
func refuseRetry(message string, retryAfter time.Duration) *Error {
	return &Error{Reason: ReasonRateLimited, Message: message, RetryAfter: retryAfter}
}
