// Package mapping defines the local SPIFFE-ID→AD-SID snapshot contract.
//
// The broker only ever reads a local, versioned snapshot; producing that
// snapshot from an authoritative registry (GitOps pipeline, AD-attribute
// sync controller) is a separate component's job. This keeps certificate
// issuance decoupled from any remote registry's availability. A SPIFFE ID
// with no entry fails closed — the broker refuses to issue.
package mapping

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

var (
	// ErrNoMapping is returned by Registry.Lookup when a SPIFFE ID has no
	// entry. Callers must treat it as a refusal to issue, never as a
	// reason to fall back to a derived or default SID.
	ErrNoMapping = errors.New("no mapping entry for SPIFFE ID")

	// ErrStale reports that the snapshot is older than the caller's
	// freshness bound. Whether that refuses issuance is the caller's
	// policy decision; mappings change rarely, so the default is to keep
	// serving the last known good snapshot and surface staleness loudly.
	ErrStale = errors.New("snapshot is older than the freshness bound")

	// ErrFutureDated reports a generated_at ahead of the reference clock
	// beyond the allowed skew. Unlike staleness this is never benign: it
	// means a broken producer clock or a tampered artifact, and it would
	// make any freshness bound meaningless.
	ErrFutureDated = errors.New("snapshot generated_at is in the future")
)

// Snapshot is the on-disk wire format. It is unmarshalled, validated, and
// then discarded in favour of a Registry; nothing outside this package
// should consume it directly.
type Snapshot struct {
	// Version identifies the snapshot schema/content revision so issuance
	// decision logs can reference exactly which mapping was in force.
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Entries     []Entry   `json:"entries"`
}

type Entry struct {
	SPIFFEID string `json:"spiffe_id"`
	// ADSID is the target account SID in canonical string form
	// ("S-1-5-21-...-1105"). Validated with ValidateSIDString before use;
	// never derived from the SPIFFE ID.
	ADSID string `json:"ad_sid"`
	// ADAccount is the same account in DOMAIN\samAccountName form.
	//
	// Optional, because only one backend needs it: `subordinate` issues the
	// SID extension itself and never names the account any other way, while
	// `adcs` asks an enrollment agent to enrol *for* the account, and that
	// request names it by name. A backend that needs it and does not have it
	// refuses — it is not derived from the SID, and it is not looked up.
	ADAccount string `json:"ad_account,omitempty"`
}

// Account is one target AD account, as the authoritative snapshot names it.
//
// Both fields identify the same account by different means, and both come
// from the snapshot. Neither is computed from the other: resolving a SID to a
// name (or back) would put a directory lookup on the issuance path and make
// the answer depend on something other than the authoritative mapping.
type Account struct {
	// SID is the canonical string form, always present.
	SID string

	// Name is DOMAIN\samAccountName, or empty if the snapshot does not
	// carry one for this entry.
	Name string
}

// Registry is an immutable, fully validated view of one snapshot. Every
// entry in it has already passed SPIFFE ID and SID validation, so a
// successful Lookup needs no further checks before encoding.
type Registry struct {
	version     string
	generatedAt time.Time
	entries     map[string]Account
}

// Load reads and validates the snapshot at path. Any failure — unreadable
// file, malformed JSON, unknown field, invalid entry, duplicate SPIFFE ID —
// returns an error and no Registry. There is no partially loaded state.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	r, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("snapshot %s: %w", path, err)
	}
	return r, nil
}

// Parse validates a snapshot document and builds a Registry from it.
//
// Unknown JSON fields are rejected. A newer producer that adds a field
// carrying meaning — a revocation flag, a per-entry expiry — must not be
// silently misread by an older broker that ignores it, so the broker
// refuses to load a document it does not fully understand.
func Parse(data []byte) (*Registry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var snapshot Snapshot
	if err := dec.Decode(&snapshot); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	// Reject trailing content: a concatenated or truncated-then-appended
	// file must not parse as though only its first document existed.
	if dec.More() {
		return nil, errors.New("decode: unexpected trailing content after snapshot object")
	}

	if snapshot.Version == "" {
		return nil, errors.New("version is required")
	}
	if snapshot.GeneratedAt.IsZero() {
		return nil, errors.New("generated_at is required")
	}
	if len(snapshot.Entries) == 0 {
		// A snapshot that maps nothing cannot serve any workload. Treating
		// it as valid would turn a truncated or half-written producer
		// artifact into a silent, fleet-wide issuance outage.
		return nil, errors.New("entries is empty")
	}

	entries := make(map[string]Account, len(snapshot.Entries))
	for i, entry := range snapshot.Entries {
		if err := ValidateSPIFFEID(entry.SPIFFEID); err != nil {
			return nil, fmt.Errorf("entries[%d]: %w", i, err)
		}
		if err := ValidateSIDString(entry.ADSID); err != nil {
			return nil, fmt.Errorf("entries[%d]: %w", i, err)
		}
		// Absent is allowed; present and malformed is not. A snapshot that
		// carries a name at all has made a claim about which account this
		// workload authenticates as, and a claim that does not parse must
		// stop the whole snapshot loading rather than be dropped.
		if entry.ADAccount != "" {
			if err := ValidateAccountName(entry.ADAccount); err != nil {
				return nil, fmt.Errorf("entries[%d]: %w", i, err)
			}
		}
		if existing, dup := entries[entry.SPIFFEID]; dup {
			// Rejected even when both entries carry the same SID: a
			// duplicate key means the producer merged sources badly, and
			// last-write-wins would decide which AD account a workload
			// authenticates as.
			return nil, fmt.Errorf("entries[%d]: duplicate spiffe_id %q (already mapped to %s)", i, entry.SPIFFEID, existing.SID)
		}
		entries[entry.SPIFFEID] = Account{SID: entry.ADSID, Name: entry.ADAccount}
	}

	return &Registry{
		version:     snapshot.Version,
		generatedAt: snapshot.GeneratedAt,
		entries:     entries,
	}, nil
}

// Lookup returns the AD account mapped to spiffeID. A miss returns
// ErrNoMapping; there is no default, no wildcard, and no derivation from the
// ID itself.
func (r *Registry) Lookup(spiffeID string) (Account, error) {
	account, ok := r.entries[spiffeID]
	if !ok {
		return Account{}, fmt.Errorf("%w: %s (snapshot version %s)", ErrNoMapping, spiffeID, r.version)
	}
	return account, nil
}

// Version is the snapshot's content revision, for issuance decision logs.
func (r *Registry) Version() string { return r.version }

// GeneratedAt is when the producer built the snapshot.
func (r *Registry) GeneratedAt() time.Time { return r.generatedAt }

// Len is the number of mapped SPIFFE IDs.
func (r *Registry) Len() int { return len(r.entries) }

// Age is how old the snapshot is relative to now. It is negative for a
// future-dated snapshot.
func (r *Registry) Age(now time.Time) time.Duration { return now.Sub(r.generatedAt) }

// CheckFreshness reports whether the snapshot's generated_at is usable at
// now. It returns an error wrapping ErrFutureDated if the snapshot is dated
// more than skew ahead of now, or ErrStale if it is older than maxAge.
// A maxAge of zero disables the staleness check; the future-dated check
// always applies, since it indicates a broken producer rather than a
// tolerable delay.
//
// The caller applies the policy: staleness is expected to be logged loudly
// while issuance continues, whereas a future-dated snapshot should refuse.
func (r *Registry) CheckFreshness(now time.Time, maxAge, skew time.Duration) error {
	age := r.Age(now)
	if age < -skew {
		return fmt.Errorf("%w: generated_at %s is %s ahead of now (allowed skew %s)",
			ErrFutureDated, r.generatedAt.UTC().Format(time.RFC3339), -age, skew)
	}
	if maxAge > 0 && age > maxAge {
		return fmt.Errorf("%w: generated_at %s is %s old (bound %s)",
			ErrStale, r.generatedAt.UTC().Format(time.RFC3339), age, maxAge)
	}
	return nil
}
