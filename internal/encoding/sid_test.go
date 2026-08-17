package encoding

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/mapping"
)

// Known-value vectors. These are the universally documented well-known SIDs,
// short enough that the byte layout can be checked by eye against MS-DTYP
// §2.4.2.2 — which is the point: they pin the mixed endianness. In
// "S-1-5-18" the identifier authority 5 lands in the *last* byte of its
// 6-byte big-endian field, while sub-authority 18 (0x12) lands in the
// *first* byte of its 4-byte little-endian field.
var sidVectors = []struct {
	name string
	sid  string
	der  string
}{
	{name: "Everyone", sid: "S-1-1-0", der: "010100000000000100000000"},
	{name: "LocalSystem", sid: "S-1-5-18", der: "010100000000000512000000"},
	{name: "BuiltinAdministrators", sid: "S-1-5-32-544", der: "01020000000000052000000020020000"},
}

func TestMarshalSIDKnownValues(t *testing.T) {
	for _, tt := range sidVectors {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MarshalSID(tt.sid)
			if err != nil {
				t.Fatalf("MarshalSID(%q) = %v, want nil", tt.sid, err)
			}
			if hex.EncodeToString(got) != tt.der {
				t.Errorf("MarshalSID(%q) = %s, want %s", tt.sid, hex.EncodeToString(got), tt.der)
			}
		})
	}
}

func TestUnmarshalSIDKnownValues(t *testing.T) {
	for _, tt := range sidVectors {
		t.Run(tt.name, func(t *testing.T) {
			der, err := hex.DecodeString(tt.der)
			if err != nil {
				t.Fatalf("test setup: %v", err)
			}
			got, err := UnmarshalSID(der)
			if err != nil {
				t.Fatalf("UnmarshalSID(%s) = %v, want nil", tt.der, err)
			}
			if got != tt.sid {
				t.Errorf("UnmarshalSID(%s) = %q, want %q", tt.der, got, tt.sid)
			}
		})
	}
}

func TestSIDRoundTrip(t *testing.T) {
	sids := []string{
		"S-1-1-0",
		"S-1-5-18",
		"S-1-5-32-544",
		"S-1-5-21-1111111111-2222222222-3333333333-1105",
		"S-1-5-21-0-0-0-4294967295",
		"S-1-0-0",
		"S-1-281474976710655-1",
		"S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15",
	}
	for _, sid := range sids {
		t.Run(sid, func(t *testing.T) {
			der, err := MarshalSID(sid)
			if err != nil {
				t.Fatalf("MarshalSID() = %v, want nil", err)
			}
			if want := sidHeaderLen + sidSubAuthLen*(strings.Count(sid, "-")-2); len(der) != want {
				t.Errorf("encoded length = %d, want %d", len(der), want)
			}
			got, err := UnmarshalSID(der)
			if err != nil {
				t.Fatalf("UnmarshalSID() = %v, want nil", err)
			}
			if got != sid {
				t.Errorf("round trip = %q, want %q", got, sid)
			}
		})
	}
}

func TestMarshalSIDRejects(t *testing.T) {
	tests := map[string]string{
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
		"S-1-5-+18":                "signed sub-authority",
		"S-1-5-21-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16": "16 sub-authorities",
	}
	for sid, why := range tests {
		if _, err := MarshalSID(sid); err == nil {
			t.Errorf("MarshalSID(%q) = nil error, want one (%s)", sid, why)
		}
	}
}

func TestUnmarshalSIDRejects(t *testing.T) {
	tests := []struct {
		name    string
		der     string
		wantErr string
	}{
		{name: "empty", der: "", wantErr: "shorter than"},
		{name: "header only, truncated", der: "0101000000000005", wantErr: "want exactly"},
		{name: "seven bytes", der: "01010000000000", wantErr: "shorter than"},
		{name: "bad revision", der: "020100000000000512000000", wantErr: "unsupported revision"},
		{name: "zero sub-authorities", der: "0100000000000005", wantErr: "count is zero"},
		{name: "count exceeds maximum", der: "0110000000000005" + strings.Repeat("00000000", 16), wantErr: "exceeds maximum"},
		{name: "trailing bytes", der: "010100000000000512000000ff", wantErr: "want exactly"},
		{name: "count larger than payload", der: "010200000000000512000000", wantErr: "want exactly"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			der, err := hex.DecodeString(tt.der)
			if err != nil {
				t.Fatalf("test setup: %v", err)
			}
			got, err := UnmarshalSID(der)
			if err == nil {
				t.Fatalf("UnmarshalSID(%s) = %q, want an error containing %q", tt.der, got, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want containing %q", err, tt.wantErr)
			}
			if got != "" {
				t.Errorf("returned %q alongside an error; must be empty", got)
			}
		})
	}
}

// TestSIDParsersAgree is the differential check between this package's
// parser and the snapshot validator's. They are separate implementations on
// purpose; if they ever disagree about what a valid SID is, a snapshot could
// pass validation and then fail — or worse, succeed differently — at
// encoding time.
func TestSIDParsersAgree(t *testing.T) {
	corpus := []string{
		"S-1-1-0", "S-1-5-18", "S-1-5-32-544",
		"S-1-5-21-1111111111-2222222222-3333333333-1105",
		"S-1-5-21-0-0-0-4294967295", "S-1-281474976710655-1",
		"", "S-1-5", "s-1-5-18", "S-2-5-18", "S-1-5-18-", "S-1-5--18",
		"S-1-5-018", "S-1-5-4294967296", "S-1-281474976710656-5-18",
		"S-1-0x5-18", "S-1-5-21-abc", "S-1-5- 18",
		"S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15",
		"S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
	}
	for _, sid := range corpus {
		assertSIDParsersAgree(t, sid)
	}
}

func assertSIDParsersAgree(t *testing.T, sid string) {
	t.Helper()
	_, marshalErr := MarshalSID(sid)
	validateErr := mapping.ValidateSIDString(sid)
	if (marshalErr == nil) != (validateErr == nil) {
		t.Errorf("parsers disagree on %q: MarshalSID err = %v, mapping.ValidateSIDString err = %v",
			sid, marshalErr, validateErr)
	}
}

func FuzzMarshalSID(f *testing.F) {
	for _, tt := range sidVectors {
		f.Add(tt.sid)
	}
	f.Add("S-1-5-21-1111111111-2222222222-3333333333-1105")
	f.Add("")
	f.Add("S-1-5-018")

	// Two properties at once: the two SID parsers must agree on acceptance,
	// and anything accepted must survive a binary round trip unchanged.
	f.Fuzz(func(t *testing.T, sid string) {
		assertSIDParsersAgree(t, sid)

		der, err := MarshalSID(sid)
		if err != nil {
			return
		}
		if len(der) < sidHeaderLen || (len(der)-sidHeaderLen)%sidSubAuthLen != 0 {
			t.Fatalf("accepted %q and produced a %d-byte SID", sid, len(der))
		}
		got, err := UnmarshalSID(der)
		if err != nil {
			t.Fatalf("accepted %q but its encoding does not decode: %v", sid, err)
		}
		if got != sid {
			t.Fatalf("round trip of %q produced %q", sid, got)
		}
	})
}

func FuzzUnmarshalSID(f *testing.F) {
	for _, tt := range sidVectors {
		der, err := hex.DecodeString(tt.der)
		if err != nil {
			f.Fatalf("test setup: %v", err)
		}
		f.Add(der)
	}
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x01, 0, 0, 0, 0, 0, 5})

	// Decoding untrusted bytes must never panic, and anything accepted must
	// re-encode to exactly the input — no alternate encoding of one SID.
	f.Fuzz(func(t *testing.T, der []byte) {
		sid, err := UnmarshalSID(der)
		if err != nil {
			return
		}
		if err := mapping.ValidateSIDString(sid); err != nil {
			t.Fatalf("decoded %s into %q, which fails snapshot validation: %v",
				hex.EncodeToString(der), sid, err)
		}
		reencoded, err := MarshalSID(sid)
		if err != nil {
			t.Fatalf("decoded %s into %q, which does not re-encode: %v",
				hex.EncodeToString(der), sid, err)
		}
		if !bytes.Equal(reencoded, der) {
			t.Fatalf("re-encoding %q produced %s, want %s",
				sid, hex.EncodeToString(reencoded), hex.EncodeToString(der))
		}
	})
}
