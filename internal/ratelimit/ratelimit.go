// Package ratelimit bounds how often the broker will do expensive work on
// behalf of a caller, and how often it will reach the CA at all.
//
// Two things need bounding and they are not the same thing:
//
//   - Per caller. Verifying a proof-of-possession signature is real CPU, and
//     a single workload that retries in a tight loop should not be able to
//     spend all of it.
//
//   - Globally. Under the adcs backend every accepted request becomes an
//     outbound enrolment to a CA that the rest of the forest also depends on.
//     That CA is a shared resource this service does not own, so the broker
//     caps its own aggregate draw on it rather than assuming the CA will
//     defend itself.
//
// The implementation is a token bucket, which is chosen for one property:
// it allows a short burst — a fleet restarting together, a rotation wave —
// while still bounding the sustained rate. A fixed window would refuse the
// wave and a leaky bucket would smear it.
//
// This package has no dependencies. golang.org/x/time/rate does this job
// better in general, but the module's zero-dependency surface is an
// auditability property of a credential-minting process, and a token bucket
// is fifty lines.
package ratelimit

import (
	"sync"
	"time"
)

// DefaultIdle is how long a per-key bucket may sit untouched before it is
// eligible for eviction. See Keyed.
const DefaultIdle = 10 * time.Minute

// A Limiter is one token bucket, safe for concurrent use.
//
// A nil *Limiter is a valid, always-allowing limiter. That is how the limiter
// is switched off: the caller passes nil rather than the code branching on a
// flag at every call site.
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens added per second
	burst  float64 // bucket capacity, in tokens
	tokens float64
	last   time.Time
	now    func() time.Time
}

// New returns a limiter admitting rate requests per second on average, with
// room for burst of them arriving at once.
//
// It returns nil — an always-allowing limiter — when either bound is
// non-positive. A rate of zero with a positive burst would otherwise be the
// worst possible reading of "no limit": the first burst requests succeed and
// every request after that is refused forever, because nothing ever refills.
func New(rate float64, burst int) *Limiter {
	if rate <= 0 || burst <= 0 {
		return nil
	}
	return newAt(rate, burst, time.Now)
}

func newAt(rate float64, burst int, now func() time.Time) *Limiter {
	return &Limiter{
		rate:   rate,
		burst:  float64(burst),
		tokens: float64(burst), // start full: a fresh process must not refuse a legitimate first request
		last:   now(),
		now:    now,
	}
}

// Allow takes one token if one is available.
//
// It reports whether the request may proceed and, when it may not, how long
// until a token will be available. That second value is not advice the caller
// can ignore safely — it is what reaches the client as Retry-After, and a
// caller that retries sooner is refused again.
func (l *Limiter) Allow() (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.advanceLocked(l.now())
	if l.tokens >= 1 {
		l.tokens--
		return true, 0
	}
	// Round up: reporting 0 would invite an immediate retry that is certain
	// to be refused, and a sub-second Retry-After is not representable in the
	// header anyway.
	wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

// advanceLocked refills the bucket for the time that has passed.
func (l *Limiter) advanceLocked(now time.Time) {
	elapsed := now.Sub(l.last)
	if elapsed <= 0 {
		// A clock that went backwards must not mint tokens. Hold the level
		// and re-base, so the next call measures from here.
		l.last = now
		return
	}
	l.last = now
	l.tokens += elapsed.Seconds() * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
}

// fullAt reports whether the bucket would be at capacity at now. A full
// bucket holds no state that a freshly created one would not also hold, which
// is what makes eviction exact rather than approximate.
func (l *Limiter) fullAt(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.advanceLocked(now)
	return l.tokens >= l.burst
}

// Keyed is a set of per-key token buckets — one per caller SPIFFE ID.
//
// A nil *Keyed is a valid, always-allowing limiter, for the same reason as
// Limiter.
//
// # Why eviction is safe
//
// The map would otherwise grow one entry per distinct caller and never
// shrink. Buckets are dropped once they are full and have been untouched for
// the idle period, and a full bucket is by construction indistinguishable
// from a bucket that has never been used: both admit burst requests
// immediately. So eviction cannot hand anyone a limit they had already spent.
// A caller still being throttled has a non-full bucket and is never evicted.
type Keyed struct {
	mu      sync.Mutex
	rate    float64
	burst   int
	idle    time.Duration
	buckets map[string]*Limiter
	swept   time.Time
	now     func() time.Time
}

// NewKeyed returns a per-key limiter. idle bounds how long an unused bucket is
// retained; zero means DefaultIdle. As with New, a non-positive rate or burst
// returns nil.
func NewKeyed(rate float64, burst int, idle time.Duration) *Keyed {
	if rate <= 0 || burst <= 0 {
		return nil
	}
	return newKeyedAt(rate, burst, idle, time.Now)
}

func newKeyedAt(rate float64, burst int, idle time.Duration, now func() time.Time) *Keyed {
	if idle <= 0 {
		idle = DefaultIdle
	}
	return &Keyed{
		rate:    rate,
		burst:   burst,
		idle:    idle,
		buckets: make(map[string]*Limiter),
		swept:   now(),
		now:     now,
	}
}

// Allow takes one token from key's bucket, creating it if this is the first
// time key has been seen.
func (k *Keyed) Allow(key string) (bool, time.Duration) {
	if k == nil {
		return true, 0
	}
	k.mu.Lock()
	now := k.now()
	if now.Sub(k.swept) >= k.idle {
		k.sweepLocked(now)
	}
	b, ok := k.buckets[key]
	if !ok {
		b = newAt(k.rate, k.burst, k.now)
		k.buckets[key] = b
	}
	k.mu.Unlock()

	return b.Allow()
}

// Len is the number of buckets currently held. It exists for tests and for a
// future metric; nothing in the issuance path reads it.
func (k *Keyed) Len() int {
	if k == nil {
		return 0
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.buckets)
}

// sweepLocked drops every bucket that is full and has been idle. Callers hold
// k.mu; the per-bucket lock is taken inside fullAt, so the lock order is
// always Keyed then Limiter.
func (k *Keyed) sweepLocked(now time.Time) {
	k.swept = now
	for key, b := range k.buckets {
		b.mu.Lock()
		stale := now.Sub(b.last) >= k.idle
		b.mu.Unlock()
		if stale && b.fullAt(now) {
			delete(k.buckets, key)
		}
	}
}
