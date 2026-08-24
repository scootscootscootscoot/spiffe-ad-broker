package mapping

import (
	"strings"
	"testing"
)

// All account names below are synthetic. No name from a real forest belongs
// in this repository, including in fixtures.
const accountSnapshot = `{
  "version": "2026-08-24.1",
  "generated_at": "2026-08-24T09:00:00Z",
  "entries": [
    {"spiffe_id": "spiffe://example.org/svc/db/reporting",
     "ad_sid": "S-1-5-21-1111111111-2222222222-3333333333-1105",
     "ad_account": "EXAMPLE\\svc-db-reporting"},
    {"spiffe_id": "spiffe://example.org/svc/api/orders",
     "ad_sid": "S-1-5-21-1111111111-2222222222-3333333333-1106"}
  ]
}`

func TestValidateAccountName(t *testing.T) {
	valid := []string{
		`EXAMPLE\svc-db`,
		`EXAMPLE\host$`,
		`ex-ample.1\a_b.c-d$`,
		`E\a`,
	}
	for _, name := range valid {
		if err := ValidateAccountName(name); err != nil {
			t.Errorf("ValidateAccountName(%q) = %v, want nil", name, err)
		}
	}

	invalid := []struct{ name, why string }{
		{"", "empty"},
		{`svc-db`, "no domain separator"},
		{`\svc-db`, "empty domain"},
		{`EXAMPLE\`, "empty account"},
		{`EXAMPLE\OU\svc-db`, "two separators"},
		{`EXAMPLE/svc-db`, "wrong separator"},
		{`EXAMPLE\svc db`, "space"},
		{`EXAMPLE\svc&db`, "ampersand separates name=value pairs on the wire"},
		{`EXAMPLE\svc=db`, "equals separates a name from its value on the wire"},
		{`EXAMPLE\svc%5Cdb`, "percent is the escape character on the wire"},
		{`EXAMPLE\Ünicode`, "outside the pinned character set"},
		{`EXAMPLE\` + strings.Repeat("a", MaxAccountNameLen), "over the length bound"},
	}
	for _, tc := range invalid {
		if err := ValidateAccountName(tc.name); err == nil {
			t.Errorf("ValidateAccountName(%q) = nil, want an error (%s)", tc.name, tc.why)
		}
	}
}

// The account name is optional per entry, because only the adcs backend needs
// it. A snapshot mixing entries with and without one must load.
func TestSnapshotCarriesOptionalAccountNames(t *testing.T) {
	r, err := Parse([]byte(accountSnapshot))
	if err != nil {
		t.Fatalf("Parse() = %v, want nil", err)
	}

	withName, err := r.Lookup("spiffe://example.org/svc/db/reporting")
	if err != nil {
		t.Fatalf("Lookup() = %v", err)
	}
	if want := `EXAMPLE\svc-db-reporting`; withName.Name != want {
		t.Errorf("Lookup().Name = %q, want %q", withName.Name, want)
	}

	withoutName, err := r.Lookup("spiffe://example.org/svc/api/orders")
	if err != nil {
		t.Fatalf("Lookup() = %v", err)
	}
	if withoutName.Name != "" {
		t.Errorf("Lookup().Name = %q, want empty", withoutName.Name)
	}
	if withoutName.SID == "" {
		t.Error("an entry without an account name lost its SID")
	}
}

// A name that does not parse stops the whole snapshot loading rather than
// being dropped from one entry. The producer made a claim about which account
// a workload authenticates as; a claim nobody can read is not a claim to
// serve around.
func TestSnapshotRejectsAMalformedAccountName(t *testing.T) {
	bad := strings.Replace(accountSnapshot, `EXAMPLE\\svc-db-reporting`, `EXAMPLE\\svc db`, 1)
	if bad == accountSnapshot {
		t.Fatal("test fixture did not substitute; the snapshot changed shape")
	}
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("Parse() accepted a malformed ad_account")
	}
}
