package mapping

import (
	"strings"
	"testing"
)

func TestValidateSIDString(t *testing.T) {
	valid := []string{
		"S-1-5-18",
		"S-1-5-21-3623811015-3361044348-30300820-1013",
		"S-1-5-21-0-0-0-4294967295",
	}
	for _, s := range valid {
		if err := ValidateSIDString(s); err != nil {
			t.Errorf("ValidateSIDString(%q) = %v, want nil", s, err)
		}
	}

	invalid := map[string]string{
		"":                         "empty string",
		"S-1-5":                    "no sub-authority",
		"s-1-5-18":                 "lowercase s",
		"S-2-5-18":                 "revision 2",
		"S-1-5-18-":                "trailing dash",
		"S-1-5--18":                "empty component",
		"S-1-5-018":                "leading zero",
		"S-1-5-4294967296":         "sub-authority overflows uint32",
		"S-1-281474976710656-5-18": "authority overflows 48 bits",
		"S-1-0x5-18":               "hex authority",
		"S-1-5-21-abc":             "non-numeric",
		"S-1-5- 18":                "embedded space",
		"S-1-5-21-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16": "16 sub-authorities",
	}
	for s, why := range invalid {
		if err := ValidateSIDString(s); err == nil {
			t.Errorf("ValidateSIDString(%q) = nil, want error (%s)", s, why)
		}
	}
}

// The 15-sub-authority ceiling is the boundary the DER encoder will rely on,
// so pin both sides of it.
func TestValidateSIDStringSubAuthorityLimit(t *testing.T) {
	const fifteen = "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15"
	if err := ValidateSIDString(fifteen); err != nil {
		t.Errorf("ValidateSIDString(15 sub-authorities) = %v, want nil", err)
	}
	if err := ValidateSIDString(fifteen + "-16"); err == nil {
		t.Error("ValidateSIDString(16 sub-authorities) = nil, want error")
	}
}

func FuzzValidateSIDString(f *testing.F) {
	f.Add("S-1-5-18")
	f.Add("S-1-5-21-3623811015-3361044348-30300820-1013")
	f.Add("S-1-0-0")
	f.Add("")
	f.Add("S-1-5-018")

	// Validation must never panic on hostile input, and anything it accepts
	// must satisfy the invariants the DER encoder depends on.
	f.Fuzz(func(t *testing.T, s string) {
		if err := ValidateSIDString(s); err != nil {
			return
		}
		parts := strings.Split(s, "-")
		if len(parts) < 4 || len(parts) > 3+maxSubAuthorities {
			t.Fatalf("accepted %q with %d components", s, len(parts))
		}
		if parts[0] != "S" || parts[1] != "1" {
			t.Fatalf("accepted %q with bad prefix", s)
		}
		if _, err := parseCanonicalUint(parts[2], 1<<48-1); err != nil {
			t.Fatalf("accepted %q with bad authority: %v", s, err)
		}
		for _, sub := range parts[3:] {
			if _, err := parseCanonicalUint(sub, 1<<32-1); err != nil {
				t.Fatalf("accepted %q with bad sub-authority %q: %v", s, sub, err)
			}
		}
	})
}
