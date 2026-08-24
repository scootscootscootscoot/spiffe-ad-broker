package mapping

import (
	"errors"
	"fmt"
	"strings"
)

// MaxAccountNameLen bounds a DOMAIN\samAccountName. Active Directory caps
// samAccountName at 20 characters and a NetBIOS domain name at 15; the bound
// here is deliberately loose around both, because its job is to stop a
// pathological snapshot entry, not to re-implement AD's own rules.
const MaxAccountNameLen = 128

// ValidateAccountName checks an AD account name in DOMAIN\samAccountName
// form, the way a snapshot must carry it.
//
// This exists because of what the `adcs` backend actually asks the CA. An
// enrollment agent names the target account by *name*, not by SID: the SID is
// what comes back in the issued certificate, not what goes out in the
// request. So the account name is authorization data in exactly the sense the
// SID is, and it is subject to the same rule — it comes from the authoritative
// mapping and is never derived from the SPIFFE ID, the CSR, or anything else
// the caller reaches.
//
// The accepted character set is narrower than Active Directory's. Widening it
// means first establishing how the extra characters survive the encodings
// between here and the CA, not assuming they pass through: a name that
// encodes wrongly does not fail loudly, it names a different account.
func ValidateAccountName(name string) error {
	if name == "" {
		return errors.New("account name is empty")
	}
	if len(name) > MaxAccountNameLen {
		return fmt.Errorf("account name is %d bytes, over the %d-byte bound", len(name), MaxAccountNameLen)
	}
	domain, account, found := strings.Cut(name, `\`)
	if !found {
		return fmt.Errorf("account name %q is not in DOMAIN\\account form", name)
	}
	if domain == "" {
		return fmt.Errorf("account name %q has an empty domain", name)
	}
	if account == "" {
		return fmt.Errorf("account name %q has an empty account", name)
	}
	if strings.Contains(account, `\`) {
		return fmt.Errorf("account name %q has more than one separator", name)
	}
	for _, r := range domain + account {
		if !isAccountRune(r) {
			return fmt.Errorf("account name %q contains an unsupported character %q", name, r)
		}
	}
	return nil
}

func isAccountRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '-', r == '_', r == '.', r == '$':
		return true
	}
	return false
}
