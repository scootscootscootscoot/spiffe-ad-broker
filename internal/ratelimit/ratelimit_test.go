package ratelimit

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock makes refill deterministic. Without it every assertion about
// tokens would be a race against the test's own wall-clock time.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func mustAllow(t *testing.T, l *Limiter, n int) {
	t.Helper()
	for i := range n {
		if ok, _ := l.Allow(); !ok {
			t.Fatalf("request %d of %d was refused, want allowed", i+1, n)
		}
	}
}

func mustRefuse(t *testing.T, l *Limiter) time.Duration {
	t.Helper()
	ok, retry := l.Allow()
	if ok {
		t.Fatal("request was allowed, want refused")
	}
	return retry
}

// The bucket starts full: a fresh process must not refuse a legitimate first
// request just because it has not been running long enough to earn a token.
func TestNewStartsFull(t *testing.T) {
	c := newClock()
	l := newAt(1, 3, c.now)
	mustAllow(t, l, 3)
	mustRefuse(t, l)
}

func TestRefillIsProportionalToElapsedTime(t *testing.T) {
	c := newClock()
	l := newAt(2, 4, c.now) // 2 tokens/second
	mustAllow(t, l, 4)
	mustRefuse(t, l)

	c.advance(1500 * time.Millisecond) // 3 tokens
	mustAllow(t, l, 3)
	mustRefuse(t, l)
}

// Tokens must not accumulate past the burst, or a service idle overnight would
// admit an unbounded flood in the morning.
func TestRefillIsCappedAtBurst(t *testing.T) {
	c := newClock()
	l := newAt(1, 2, c.now)
	mustAllow(t, l, 2)

	c.advance(24 * time.Hour)
	mustAllow(t, l, 2)
	mustRefuse(t, l)
}

// The refusal has to say when to come back, and the answer has to be long
// enough that honouring it actually succeeds.
func TestRetryAfterIsLongEnoughToSucceed(t *testing.T) {
	c := newClock()
	l := newAt(0.5, 1, c.now) // one token every two seconds
	mustAllow(t, l, 1)

	retry := mustRefuse(t, l)
	if retry < 2*time.Second {
		t.Fatalf("RetryAfter = %v, want at least the 2s it takes to earn a token", retry)
	}
	c.advance(retry)
	mustAllow(t, l, 1)
}

// A sub-second wait is not representable in Retry-After, and reporting zero
// would invite an immediate retry that is certain to be refused.
func TestRetryAfterIsNeverBelowASecond(t *testing.T) {
	c := newClock()
	l := newAt(100, 1, c.now) // a token every 10ms
	mustAllow(t, l, 1)
	if retry := mustRefuse(t, l); retry < time.Second {
		t.Fatalf("RetryAfter = %v, want it rounded up to at least 1s", retry)
	}
}

// A clock that jumps backwards — an NTP step, a suspended VM — must not mint
// tokens, or the limit is bypassable by whoever can move the clock.
func TestBackwardsClockDoesNotMintTokens(t *testing.T) {
	c := newClock()
	l := newAt(1, 2, c.now)
	mustAllow(t, l, 2)

	c.advance(-time.Hour)
	mustRefuse(t, l)

	// And it re-bases rather than freezing: time moving forward from the new
	// point still refills.
	c.advance(3 * time.Second)
	mustAllow(t, l, 2)
}

// nil is how the limiter is switched off, so it has to be a working limiter
// rather than a panic waiting at the first call site that forgot to check.
func TestNilLimiterAllowsEverything(t *testing.T) {
	var l *Limiter
	mustAllow(t, l, 1000)

	var k *Keyed
	if ok, _ := k.Allow("anyone"); !ok {
		t.Fatal("nil Keyed refused a request")
	}
	if k.Len() != 0 {
		t.Fatal("nil Keyed reported buckets")
	}
}

// A rate of zero with a positive burst would otherwise be the worst possible
// reading of "no limit": the first burst requests succeed and everything after
// is refused forever, because nothing ever refills.
func TestNonPositiveBoundsDisableTheLimiter(t *testing.T) {
	for _, tc := range []struct {
		rate  float64
		burst int
	}{
		{0, 5}, {-1, 5}, {1, 0}, {1, -1}, {0, 0},
	} {
		t.Run(fmt.Sprintf("rate=%v burst=%d", tc.rate, tc.burst), func(t *testing.T) {
			if l := New(tc.rate, tc.burst); l != nil {
				t.Errorf("New returned a limiter, want nil (disabled)")
			}
			if k := NewKeyed(tc.rate, tc.burst, 0); k != nil {
				t.Errorf("NewKeyed returned a limiter, want nil (disabled)")
			}
		})
	}
}

// The point of the per-caller limit: one workload retrying in a loop must not
// spend anyone else's budget.
func TestKeyedBucketsAreIndependent(t *testing.T) {
	c := newClock()
	k := newKeyedAt(0.01, 2, time.Minute, c.now)

	for range 2 {
		if ok, _ := k.Allow("spiffe://example.org/a"); !ok {
			t.Fatal("caller a was refused within its burst")
		}
	}
	if ok, _ := k.Allow("spiffe://example.org/a"); ok {
		t.Fatal("caller a was allowed past its burst")
	}
	if ok, _ := k.Allow("spiffe://example.org/b"); !ok {
		t.Fatal("caller b was refused because caller a exhausted its own bucket")
	}
}

// Eviction is what keeps the map from growing one entry per caller forever.
// It is exact rather than approximate: a full bucket is indistinguishable from
// one that has never been used, so dropping it cannot hand anyone a limit they
// had already spent.
func TestIdleFullBucketsAreEvicted(t *testing.T) {
	c := newClock()
	k := newKeyedAt(1, 2, 10*time.Minute, c.now)

	k.Allow("spiffe://example.org/idle")
	if k.Len() != 1 {
		t.Fatalf("Len = %d, want 1", k.Len())
	}

	// Long enough to refill to full and to pass the idle bound. The sweep
	// runs on the next call, so a second key is used to trigger it.
	c.advance(11 * time.Minute)
	k.Allow("spiffe://example.org/other")

	if k.Len() != 1 {
		t.Fatalf("Len = %d, want 1 (the idle bucket evicted, the new one kept)", k.Len())
	}
	if ok, _ := k.Allow("spiffe://example.org/idle"); !ok {
		t.Fatal("the evicted caller was refused, so eviction lost state it should not have")
	}
}

// A caller still being throttled has a non-full bucket. Evicting that would
// hand it a fresh burst, which is exactly the limit being bypassed by waiting.
func TestThrottledBucketsSurviveASweep(t *testing.T) {
	c := newClock()
	// Refills one token per hour, so an idle period passes long before the
	// bucket is anywhere near full.
	k := newKeyedAt(1.0/3600, 3, time.Minute, c.now)

	for range 3 {
		k.Allow("spiffe://example.org/noisy")
	}
	if ok, _ := k.Allow("spiffe://example.org/noisy"); ok {
		t.Fatal("allowed past the burst")
	}

	c.advance(2 * time.Minute) // past idle, nowhere near full
	k.Allow("spiffe://example.org/trigger-a-sweep")

	if ok, _ := k.Allow("spiffe://example.org/noisy"); ok {
		t.Fatal("a throttled caller was evicted and handed a fresh burst")
	}
}

// Under contention the count must be exactly the burst, not approximately it.
// Run with -race, which is what CI does.
func TestConcurrentAllowIsExact(t *testing.T) {
	const burst = 50
	l := New(0.0001, burst) // refill is one token per ~3 hours; nothing arrives during the test

	var allowed atomic.Int64
	var wg sync.WaitGroup
	for range 500 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := l.Allow(); ok {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := allowed.Load(); got != burst {
		t.Fatalf("allowed %d requests, want exactly %d", got, burst)
	}
}

func TestConcurrentKeyedAllowIsExactPerKey(t *testing.T) {
	const burst = 10
	k := NewKeyed(0.0001, burst, time.Minute)

	var wg sync.WaitGroup
	counts := make([]atomic.Int64, 4)
	for i := range counts {
		for range 100 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, _ := k.Allow(fmt.Sprintf("spiffe://example.org/w%d", i)); ok {
					counts[i].Add(1)
				}
			}()
		}
	}
	wg.Wait()

	for i := range counts {
		if got := counts[i].Load(); got != burst {
			t.Errorf("key %d allowed %d requests, want exactly %d", i, got, burst)
		}
	}
	if k.Len() != len(counts) {
		t.Errorf("Len = %d, want %d", k.Len(), len(counts))
	}
}
