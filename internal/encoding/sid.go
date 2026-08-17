package encoding

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The binary SID layout (MS-DTYP §2.4.2.2):
//
//	Revision            1 byte,  always 0x01
//	SubAuthorityCount   1 byte,  0–15
//	IdentifierAuthority 6 bytes, big-endian
//	SubAuthority[]      4 bytes each, little-endian
//
// The mixed endianness is not a typo: the identifier authority is
// big-endian and every sub-authority is little-endian. Getting this
// backwards produces a well-formed SID for the wrong account, which is
// exactly the failure a strong-mapping extension must never have, so the
// round-trip and known-value tests pin both.
const (
	sidRevision       = 0x01
	sidHeaderLen      = 8
	sidSubAuthLen     = 4
	sidMaxSubAuthords = 15
	sidMaxAuthority   = 1<<48 - 1
)

// MarshalSID encodes a canonical SID string ("S-1-5-21-…-1105") into its
// MS-DTYP binary form.
//
// Note on scope: whether the AD SID security extension carries the SID in
// this binary form or as its string rendering is NOT settled, and must not
// be guessed — it is one of the specific questions the ADCS fixture answers
// (see docs/FIXTURES.md). This codec is the canonical SID representation in
// its own right: it is what AD stores in the objectSid attribute, so the
// mapping-snapshot producer will need it regardless of how the extension
// turns out to be encoded.
func MarshalSID(s string) ([]byte, error) {
	authority, subAuthorities, err := parseSID(s)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, sidHeaderLen+sidSubAuthLen*len(subAuthorities))
	out = append(out, sidRevision, byte(len(subAuthorities)))
	// Identifier authority: 6 bytes, big-endian, most significant first.
	for shift := 40; shift >= 0; shift -= 8 {
		out = append(out, byte(authority>>shift))
	}
	for _, sub := range subAuthorities {
		out = binary.LittleEndian.AppendUint32(out, sub)
	}
	return out, nil
}

// UnmarshalSID decodes an MS-DTYP binary SID into its canonical string form.
// The input must be exactly one SID: trailing bytes are an error, not
// something to ignore.
func UnmarshalSID(b []byte) (string, error) {
	if len(b) < sidHeaderLen {
		return "", fmt.Errorf("sid: %d bytes is shorter than the %d-byte header", len(b), sidHeaderLen)
	}
	if b[0] != sidRevision {
		return "", fmt.Errorf("sid: unsupported revision 0x%02x, want 0x%02x", b[0], sidRevision)
	}
	count := int(b[1])
	if count == 0 {
		return "", errors.New("sid: sub-authority count is zero")
	}
	if count > sidMaxSubAuthords {
		return "", fmt.Errorf("sid: sub-authority count %d exceeds maximum %d", count, sidMaxSubAuthords)
	}
	want := sidHeaderLen + sidSubAuthLen*count
	if len(b) != want {
		return "", fmt.Errorf("sid: %d bytes for a %d-sub-authority SID, want exactly %d", len(b), count, want)
	}

	var authority uint64
	for _, c := range b[2:sidHeaderLen] {
		authority = authority<<8 | uint64(c)
	}

	var sb strings.Builder
	sb.WriteString("S-1-")
	sb.WriteString(strconv.FormatUint(authority, 10))
	for i := 0; i < count; i++ {
		off := sidHeaderLen + i*sidSubAuthLen
		sb.WriteByte('-')
		sb.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b[off:off+sidSubAuthLen])), 10))
	}
	return sb.String(), nil
}

// parseSID splits a canonical SID string into its identifier authority and
// sub-authorities.
//
// This deliberately duplicates the acceptance rules in
// mapping.ValidateSIDString rather than sharing them: the two are checked
// against each other by a differential fuzz test, so an accidental
// loosening on either side shows up as a disagreement instead of silently
// widening what reaches DER.
func parseSID(s string) (authority uint64, subAuthorities []uint32, err error) {
	parts := strings.Split(s, "-")
	if len(parts) < 4 {
		return 0, nil, fmt.Errorf("sid %q: need at least S-1-<authority>-<subauthority>", s)
	}
	if parts[0] != "S" {
		return 0, nil, fmt.Errorf("sid %q: must start with %q", s, "S-")
	}
	if parts[1] != "1" {
		return 0, nil, fmt.Errorf("sid %q: unsupported revision %q", s, parts[1])
	}

	// The identifier authority is rendered in decimal here. Windows prints
	// authorities that do not fit in 32 bits as "0x%012x" instead; every SID
	// that matters for AD account mapping uses authority 5 (NT Authority),
	// so the hex form is not produced or accepted. If a fixture ever shows a
	// large authority, this is the line to revisit.
	authority, err = parseSIDUint(parts[2], sidMaxAuthority)
	if err != nil {
		return 0, nil, fmt.Errorf("sid %q: identifier authority: %w", s, err)
	}

	subs := parts[3:]
	if len(subs) > sidMaxSubAuthords {
		return 0, nil, fmt.Errorf("sid %q: %d sub-authorities exceeds maximum %d", s, len(subs), sidMaxSubAuthords)
	}
	subAuthorities = make([]uint32, 0, len(subs))
	for _, sub := range subs {
		v, err := parseSIDUint(sub, 1<<32-1)
		if err != nil {
			return 0, nil, fmt.Errorf("sid %q: sub-authority %q: %w", s, sub, err)
		}
		subAuthorities = append(subAuthorities, uint32(v))
	}
	return authority, subAuthorities, nil
}

// parseSIDUint parses a decimal integer in [0, max], rejecting the
// non-canonical spellings (empty, leading zeros, signs, hex) that would let
// one account be written two ways.
func parseSIDUint(s string, max uint64) (uint64, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, errors.New("leading zero")
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, errors.New("not a decimal integer")
	}
	if v > max {
		return 0, fmt.Errorf("value %d exceeds maximum %d", v, max)
	}
	return v, nil
}
