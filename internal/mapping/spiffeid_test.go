package mapping

import (
	"strings"
	"testing"
)

func TestValidateSPIFFEID(t *testing.T) {
	valid := []string{
		"spiffe://example.org/svc",
		"spiffe://example.org/svc/db/reporting",
		"spiffe://example.org/ns/default/sa/app-1",
		"spiffe://ex-ample_1.org/A/b.c-d_e",
	}
	for _, id := range valid {
		if err := ValidateSPIFFEID(id); err != nil {
			t.Errorf("ValidateSPIFFEID(%q) = %v, want nil", id, err)
		}
	}

	invalid := map[string]string{
		"":                              "empty",
		"example.org/svc":               "no scheme",
		"https://example.org/svc":       "wrong scheme",
		"spiffe://":                     "no trust domain or path",
		"spiffe:///svc":                 "empty trust domain",
		"spiffe://example.org":          "no path",
		"spiffe://example.org/":         "empty path",
		"spiffe://example.org/svc/":     "trailing slash",
		"spiffe://example.org//svc":     "empty segment",
		"spiffe://example.org/./svc":    "dot segment",
		"spiffe://example.org/../svc":   "dot-dot segment",
		"spiffe://EXAMPLE.org/svc":      "uppercase trust domain",
		"spiffe://example.org:8443/svc": "port in trust domain",
		"spiffe://user@example.org/svc": "userinfo",
		"spiffe://example.org/svc%2Fdb": "percent-encoding",
		"spiffe://example.org/svc?q=1":  "query string",
		"spiffe://example.org/svc#frag": "fragment",
		"spiffe://example.org/sv c":     "space in path",
	}
	for id, why := range invalid {
		if err := ValidateSPIFFEID(id); err == nil {
			t.Errorf("ValidateSPIFFEID(%q) = nil, want error (%s)", id, why)
		}
	}
}

func TestValidateSPIFFEIDLengthLimit(t *testing.T) {
	atLimit := "spiffe://example.org/" + strings.Repeat("a", maxSPIFFEIDLength-len("spiffe://example.org/"))
	if len(atLimit) != maxSPIFFEIDLength {
		t.Fatalf("test setup: built ID of %d bytes, want %d", len(atLimit), maxSPIFFEIDLength)
	}
	if err := ValidateSPIFFEID(atLimit); err != nil {
		t.Errorf("ValidateSPIFFEID(ID at limit) = %v, want nil", err)
	}
	if err := ValidateSPIFFEID(atLimit + "a"); err == nil {
		t.Error("ValidateSPIFFEID(ID one byte over limit) = nil, want error")
	}
}

func FuzzValidateSPIFFEID(f *testing.F) {
	f.Add("spiffe://example.org/svc/db")
	f.Add("spiffe://example.org/")
	f.Add("spiffe://")
	f.Add("")
	f.Add("spiffe://example.org/../svc")

	// Anything accepted must be safe to use as an exact map key: canonical,
	// with no traversal segments and no alternate spelling of the same ID.
	f.Fuzz(func(t *testing.T, id string) {
		if err := ValidateSPIFFEID(id); err != nil {
			return
		}
		path := strings.TrimPrefix(id, spiffeScheme)
		_, path, _ = strings.Cut(path, "/")
		for _, segment := range strings.Split(path, "/") {
			if segment == "" || segment == "." || segment == ".." {
				t.Fatalf("accepted %q containing segment %q", id, segment)
			}
		}
		if strings.ContainsAny(id, "%?#@ ") {
			t.Fatalf("accepted %q containing a forbidden character", id)
		}
	})
}
