package mapping

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// All SIDs below are synthetic. No SID from a real forest belongs in this
// repository, including in fixtures.
const validSnapshot = `{
  "version": "2026-08-12.1",
  "generated_at": "2026-08-12T09:00:00Z",
  "entries": [
    {"spiffe_id": "spiffe://example.org/svc/db/reporting", "ad_sid": "S-1-5-21-1111111111-2222222222-3333333333-1105"},
    {"spiffe_id": "spiffe://example.org/svc/api/orders",   "ad_sid": "S-1-5-21-1111111111-2222222222-3333333333-1106"}
  ]
}`

func TestParseValid(t *testing.T) {
	r, err := Parse([]byte(validSnapshot))
	if err != nil {
		t.Fatalf("Parse() = %v, want nil", err)
	}
	if got, want := r.Version(), "2026-08-12.1"; got != want {
		t.Errorf("Version() = %q, want %q", got, want)
	}
	if got, want := r.Len(), 2; got != want {
		t.Errorf("Len() = %d, want %d", got, want)
	}
	if want := time.Date(2026, 8, 12, 9, 0, 0, 0, time.UTC); !r.GeneratedAt().Equal(want) {
		t.Errorf("GeneratedAt() = %s, want %s", r.GeneratedAt(), want)
	}

	sid, err := r.Lookup("spiffe://example.org/svc/db/reporting")
	if err != nil {
		t.Fatalf("Lookup() = %v, want nil", err)
	}
	if want := "S-1-5-21-1111111111-2222222222-3333333333-1105"; sid != want {
		t.Errorf("Lookup() = %q, want %q", sid, want)
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{
			name:    "not json",
			doc:     `nope`,
			wantErr: "decode",
		},
		{
			name: "unknown field",
			doc: `{"version":"v1","generated_at":"2026-08-12T09:00:00Z","revoked":true,
			       "entries":[{"spiffe_id":"spiffe://example.org/a","ad_sid":"S-1-5-18"}]}`,
			wantErr: "revoked",
		},
		{
			name: "unknown field in entry",
			doc: `{"version":"v1","generated_at":"2026-08-12T09:00:00Z",
			       "entries":[{"spiffe_id":"spiffe://example.org/a","ad_sid":"S-1-5-18","expires_at":"2026-09-01T00:00:00Z"}]}`,
			wantErr: "expires_at",
		},
		{
			name:    "trailing content",
			doc:     validSnapshot + `{"version":"attacker"}`,
			wantErr: "trailing content",
		},
		{
			name: "missing version",
			doc: `{"generated_at":"2026-08-12T09:00:00Z",
			       "entries":[{"spiffe_id":"spiffe://example.org/a","ad_sid":"S-1-5-18"}]}`,
			wantErr: "version is required",
		},
		{
			name: "missing generated_at",
			doc: `{"version":"v1",
			       "entries":[{"spiffe_id":"spiffe://example.org/a","ad_sid":"S-1-5-18"}]}`,
			wantErr: "generated_at is required",
		},
		{
			name:    "no entries key",
			doc:     `{"version":"v1","generated_at":"2026-08-12T09:00:00Z"}`,
			wantErr: "entries is empty",
		},
		{
			name:    "empty entries",
			doc:     `{"version":"v1","generated_at":"2026-08-12T09:00:00Z","entries":[]}`,
			wantErr: "entries is empty",
		},
		{
			name: "invalid spiffe id",
			doc: `{"version":"v1","generated_at":"2026-08-12T09:00:00Z",
			       "entries":[{"spiffe_id":"example.org/a","ad_sid":"S-1-5-18"}]}`,
			wantErr: "entries[0]",
		},
		{
			name: "invalid sid",
			doc: `{"version":"v1","generated_at":"2026-08-12T09:00:00Z",
			       "entries":[{"spiffe_id":"spiffe://example.org/a","ad_sid":"S-1-5"}]}`,
			wantErr: "entries[0]",
		},
		{
			name: "duplicate spiffe id",
			doc: `{"version":"v1","generated_at":"2026-08-12T09:00:00Z","entries":[
			        {"spiffe_id":"spiffe://example.org/a","ad_sid":"S-1-5-21-1-2-3-1105"},
			        {"spiffe_id":"spiffe://example.org/a","ad_sid":"S-1-5-21-1-2-3-1106"}]}`,
			wantErr: "duplicate spiffe_id",
		},
		{
			name: "duplicate spiffe id with identical sid",
			doc: `{"version":"v1","generated_at":"2026-08-12T09:00:00Z","entries":[
			        {"spiffe_id":"spiffe://example.org/a","ad_sid":"S-1-5-21-1-2-3-1105"},
			        {"spiffe_id":"spiffe://example.org/a","ad_sid":"S-1-5-21-1-2-3-1105"}]}`,
			wantErr: "duplicate spiffe_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Parse([]byte(tt.doc))
			if err == nil {
				t.Fatalf("Parse() = nil error, want one containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse() error = %v, want containing %q", err, tt.wantErr)
			}
			if r != nil {
				t.Error("Parse() returned a Registry alongside an error; must be nil")
			}
		})
	}
}

// Two SPIFFE IDs mapping to one AD account is a legitimate producer choice,
// unlike a duplicate key. It must not be rejected here.
func TestParseAllowsSharedSID(t *testing.T) {
	doc := `{"version":"v1","generated_at":"2026-08-12T09:00:00Z","entries":[
	          {"spiffe_id":"spiffe://example.org/a","ad_sid":"S-1-5-21-1-2-3-1105"},
	          {"spiffe_id":"spiffe://example.org/b","ad_sid":"S-1-5-21-1-2-3-1105"}]}`
	if _, err := Parse([]byte(doc)); err != nil {
		t.Errorf("Parse() = %v, want nil", err)
	}
}

func TestLookupMissFailsClosed(t *testing.T) {
	r, err := Parse([]byte(validSnapshot))
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	sid, err := r.Lookup("spiffe://example.org/svc/not/mapped")
	if !errors.Is(err, ErrNoMapping) {
		t.Errorf("Lookup(unmapped) error = %v, want ErrNoMapping", err)
	}
	if sid != "" {
		t.Errorf("Lookup(unmapped) = %q, want empty string", sid)
	}
}

func TestCheckFreshness(t *testing.T) {
	r, err := Parse([]byte(validSnapshot))
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	generated := time.Date(2026, 8, 12, 9, 0, 0, 0, time.UTC)
	const skew = time.Minute

	tests := []struct {
		name    string
		now     time.Time
		maxAge  time.Duration
		wantErr error
	}{
		{name: "fresh", now: generated.Add(time.Hour), maxAge: 24 * time.Hour},
		{name: "exactly at bound", now: generated.Add(24 * time.Hour), maxAge: 24 * time.Hour},
		{name: "past bound", now: generated.Add(25 * time.Hour), maxAge: 24 * time.Hour, wantErr: ErrStale},
		{name: "no bound disables staleness", now: generated.Add(10000 * time.Hour), maxAge: 0},
		{name: "future within skew", now: generated.Add(-30 * time.Second), maxAge: 24 * time.Hour},
		{name: "future beyond skew", now: generated.Add(-2 * time.Minute), maxAge: 24 * time.Hour, wantErr: ErrFutureDated},
		{name: "future beyond skew with no bound", now: generated.Add(-2 * time.Minute), maxAge: 0, wantErr: ErrFutureDated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.CheckFreshness(tt.now, tt.maxAge, skew)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("CheckFreshness() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("CheckFreshness() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mapping.json")
	if err := os.WriteFile(path, []byte(validSnapshot), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	r, err := Load(path)
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if r.Len() != 2 {
		t.Errorf("Load().Len() = %d, want 2", r.Len())
	}

	if _, err := Load(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("Load(missing file) = nil error, want one")
	}

	// A rejected snapshot must name the file it came from: with several
	// snapshots on a host, "version is required" alone is not actionable.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"version":"v1"}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	badRegistry, err := Load(bad)
	if err == nil {
		t.Fatal("Load(invalid snapshot) = nil error, want one")
	}
	if badRegistry != nil {
		t.Error("Load() returned a Registry alongside an error; must be nil")
	}
	if !strings.Contains(err.Error(), bad) {
		t.Errorf("Load() error = %v, want it to name the snapshot path", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(validSnapshot)
	f.Add(`{"version":"v1","generated_at":"2026-08-12T09:00:00Z","entries":[]}`)
	f.Add(`{}`)
	f.Add(``)

	// Parsing untrusted snapshot bytes must never panic, and a Registry must
	// never be returned alongside an error or hold an unvalidated entry.
	f.Fuzz(func(t *testing.T, doc string) {
		r, err := Parse([]byte(doc))
		if err != nil {
			if r != nil {
				t.Fatal("Parse() returned a Registry alongside an error")
			}
			return
		}
		if r == nil {
			t.Fatal("Parse() returned nil Registry and nil error")
		}
		if r.Len() == 0 {
			t.Fatal("Parse() accepted a snapshot with no entries")
		}
		for id, sid := range r.entries {
			if err := ValidateSPIFFEID(id); err != nil {
				t.Fatalf("Registry holds invalid SPIFFE ID %q: %v", id, err)
			}
			if err := ValidateSIDString(sid); err != nil {
				t.Fatalf("Registry holds invalid SID %q: %v", sid, err)
			}
		}
	})
}
