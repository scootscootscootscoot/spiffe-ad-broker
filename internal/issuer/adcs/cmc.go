package adcs

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode/utf16"
)

// Enrolling on behalf of another account.
//
// Everything the transport proves (wstep.go) enrols the broker as *itself*: a
// bare PKCS#10 goes to CES and a certificate for the caller's own account
// comes back. That is not what this service is for. To have ADCS issue for
// the *mapped* account, the request must say whose account it is — and that
// statement has to be inside a signature made by a credential holding the
// Certificate Request Agent application policy, or the CA will not act on it.
//
// The shape below is not derived from documentation. It is pinned to a real
// request built by Microsoft's own client — `certreq -policy -cert <agent>
// -attrib "RequesterName:DOMAIN\user"` — captured on 2026-08-24 and kept in
// testdata/cmc-windows-client.req. Two things about it were load-bearing and
// neither is guessable:
//
//   - The requester name travels in the CMC regInfo control
//     (id-cmc-regInfo), as an ampersand-separated name=value string, with
//     the domain separator percent-encoded: `PKINITLAB%5Cpkinittest`, not a
//     literal backslash.
//
//   - Passing the same name as an unsigned submission attribute — the
//     obvious reading of `certreq -submit -attrib "RequesterName:..."` — is
//     accepted, returns success, and is *silently ignored*: the CA issues
//     for the caller's own account instead. See
//     docs/findings/2026-08-24-enroll-on-behalf-of.md. That is the reason
//     Issue must check the SID that comes back rather than trust that the
//     one it asked for is the one it got.
//
// The structures are RFC 5272 (CMC) carried in an RFC 5652 (CMS) SignedData:
//
//	ContentInfo { signedData, [0] SignedData }
//	SignedData  { 3, {sha256}, {id-cct-PKIData, [0] OCTET STRING pkiData},
//	              [0] agent cert + chain, {SignerInfo} }
//	PKIData     { controlSequence, reqSequence, cmsSequence, otherMsgSequence }

var (
	oidCTPKIData        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 12, 2}
	oidCMCAddExtensions = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 7, 8}
	oidCMCRegInfo       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 7, 18}

	// szOID_ENROLLMENT_CERT_TYPE — the certificate template name, as a
	// BMPString, added to the request through the CMC addExtensions control.
	oidEnrollmentCertType = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}

	// szOID_ENROLLMENT_AGENT — the application policy an enrollment agent
	// credential must carry for the CA to honour a requester name.
	oidCertificateRequestAgent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 1}

	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// Body part identifiers, matching the captured request. They are references
// within one PKIData, so only their consistency matters: the addExtensions
// control names bodyPartRequest as the request its extension applies to.
const (
	bodyPartRequest       = 1
	bodyPartAddExtensions = 2
	bodyPartRegInfo       = 3
)

// An Agent is the enrollment-agent credential: the certificate that carries
// the Certificate Request Agent application policy, and the key that signs
// with it.
//
// This is the highest-value secret in the service. Whatever holds it can ask
// the CA to issue a client-authentication certificate for any account the
// template permits, so what bounds it is the CA's own configuration —
// template ACLs and enrollment-agent restrictions — not this code. What this
// code does is refuse to use a credential that is not one.
type Agent struct {
	// Certificate is the agent's own certificate.
	Certificate *x509.Certificate

	// Key signs the CMS SignedData. The private key never leaves it; only
	// crypto.Signer is required, so an HSM or KMS signer works unchanged.
	Key crypto.Signer

	// Chain is the intermediates between Certificate and a root the CA
	// trusts, excluding Certificate itself. Optional: it is carried in the
	// request so the CA can build a path to the agent without depending on
	// its own store having every intermediate.
	Chain []*x509.Certificate
}

// Validate refuses a credential that cannot do enrol-on-behalf-of.
//
// Discovering at the CA that the agent certificate lacks the Certificate
// Request Agent policy costs a round trip and returns a error that names the
// wrong thing. More importantly, without that policy the CA ignores the
// requester name and issues for the *caller's* account — a success that is
// wrong, which is far worse than a refusal.
func (a *Agent) Validate() error {
	if a == nil {
		return errors.New("no enrollment agent credential")
	}
	if a.Certificate == nil {
		return errors.New("enrollment agent has no certificate")
	}
	if a.Key == nil {
		return errors.New("enrollment agent has no key")
	}
	pub, ok := a.Certificate.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("enrollment agent certificate holds an unsupported key type %T", a.Certificate.PublicKey)
	}
	if !pub.Equal(a.Key.Public()) {
		return errors.New("enrollment agent key does not match its certificate")
	}
	for _, eku := range a.Certificate.UnknownExtKeyUsage {
		if eku.Equal(oidCertificateRequestAgent) {
			return nil
		}
	}
	return fmt.Errorf("enrollment agent certificate does not carry the Certificate Request Agent application policy (%v)",
		oidCertificateRequestAgent)
}

// buildCMC wraps csrDER in a CMC request that asks the CA to issue for
// requester, from template, and signs the whole thing as agent.
//
// csrDER is carried through byte for byte. Nothing in it is read, rewritten
// or copied: the template names the subject from Active Directory, so the
// only thing the workload's PKCS#10 contributes is its public key and the
// proof it holds the matching private one.
func buildCMC(csrDER []byte, template, requester string, agent *Agent) ([]byte, error) {
	if len(csrDER) == 0 {
		return nil, errors.New("cmc: empty CSR")
	}
	if err := agent.Validate(); err != nil {
		return nil, fmt.Errorf("cmc: %w", err)
	}
	if err := validateTemplateName(template); err != nil {
		return nil, fmt.Errorf("cmc: %w", err)
	}
	if err := validateRequesterName(requester); err != nil {
		return nil, fmt.Errorf("cmc: %w", err)
	}

	pkiData, err := buildPKIData(csrDER, template, requester)
	if err != nil {
		return nil, err
	}
	return signPKIData(pkiData, agent)
}

// buildPKIData builds the CMC body: the controls that say what to issue and
// for whom, and the workload's PKCS#10 as the request itself.
func buildPKIData(csrDER []byte, template, requester string) ([]byte, error) {
	b := &derBuilder{}

	// Control 1 — addExtensions: put the template name into the request as
	// szOID_ENROLLMENT_CERT_TYPE, whose value is a BMPString (UTF-16BE).
	templateExt := b.sequence(
		b.oid(oidEnrollmentCertType),
		b.octetString(b.bmpString(template)),
	)
	addExtensions := b.sequence(
		b.integer(0),                           // pkiDataReference: this PKIData
		b.sequence(b.integer(bodyPartRequest)), // certReferences: the request below
		b.sequence(templateExt),
	)
	controlAddExtensions := b.sequence(
		b.integer(bodyPartAddExtensions),
		b.oid(oidCMCAddExtensions),
		b.set(addExtensions),
	)

	// Control 2 — regInfo: the authorization statement. This is the only
	// place the target account is named, and it is inside the signature.
	controlRegInfo := b.sequence(
		b.integer(bodyPartRegInfo),
		b.oid(oidCMCRegInfo),
		b.set(b.octetString([]byte(regInfoString(template, requester)))),
	)

	// The request: [0] IMPLICIT TaggedCertificationRequest. The context tag
	// replaces the SEQUENCE tag rather than wrapping it — the same implicit
	// versus explicit trap the AD SID extension's golden test caught.
	taggedRequest := b.implicit(0, b.integer(bodyPartRequest), csrDER)

	pkiData := b.sequence(
		b.sequence(controlAddExtensions, controlRegInfo),
		b.sequence(taggedRequest),
		b.sequence(), // cmsSequence: empty
		b.sequence(), // otherMsgSequence: empty
	)
	if b.err != nil {
		return nil, fmt.Errorf("cmc: encoding PKIData: %w", b.err)
	}
	return pkiData, nil
}

// regInfoString renders the CMC regInfo payload.
//
// The format is name=value pairs joined and terminated by "&", with the
// domain separator percent-encoded. Both were read off the captured request;
// validateRequesterName has already refused anything whose escaping this has
// not been shown to get right.
func regInfoString(template, requester string) string {
	return "CertificateTemplate=" + template +
		"&RequesterName=" + strings.ReplaceAll(requester, `\`, "%5C") + "&"
}

// signPKIData wraps pkiData in a CMS SignedData signed by agent.
func signPKIData(pkiData []byte, agent *Agent) ([]byte, error) {
	sigAlg, err := signatureAlgorithm(agent.Key.Public())
	if err != nil {
		return nil, fmt.Errorf("cmc: %w", err)
	}

	b := &derBuilder{}
	digestAlg := b.sequence(b.oid(oidSHA256), b.null())

	// The signed attributes. contentType and messageDigest are the two CMS
	// requires once any are present; nothing else is added. Microsoft's
	// client also sends a client-information attribute naming the machine
	// and process, which means nothing here — the same reason the RST omits
	// the ccm context item.
	digest := sha256.Sum256(pkiData)
	//
	// DER sorts a SET OF by its members' encodings, and the two renderings
	// below must agree member for member, so they are sorted once here
	// rather than independently by each.
	attrs := sortDER([][]byte{
		b.sequence(b.oid(oidContentType), b.set(b.oid(oidCTPKIData))),
		b.sequence(b.oid(oidMessageDigest), b.set(b.octetString(digest[:]))),
	})
	if b.err != nil {
		return nil, fmt.Errorf("cmc: encoding signed attributes: %w", b.err)
	}

	// The signature is computed over the attributes tagged as a SET OF, but
	// they are carried in the SignerInfo tagged [0] IMPLICIT. Signing the
	// [0] form produces a signature every verifier rejects.
	signedAttrsSet := b.set(attrs...)
	signedAttrsImplicit := b.implicit(0, attrs...)
	if b.err != nil {
		return nil, fmt.Errorf("cmc: encoding signed attributes: %w", b.err)
	}

	attrsDigest := sha256.Sum256(signedAttrsSet)
	signature, err := agent.Key.Sign(rand.Reader, attrsDigest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("cmc: signing as the enrollment agent: %w", err)
	}

	signerInfo := b.sequence(
		b.integer(1), // version 1: the signer is identified by issuer and serial
		b.sequence(
			b.raw(agent.Certificate.RawIssuer),
			b.bigInteger(agent.Certificate.SerialNumber),
		),
		digestAlg,
		signedAttrsImplicit,
		sigAlg,
		b.octetString(signature),
	)

	certs := [][]byte{b.raw(agent.Certificate.Raw)}
	for _, c := range agent.Chain {
		certs = append(certs, b.raw(c.Raw))
	}

	signedData := b.sequence(
		b.integer(3), // version 3: the encapsulated content is not id-data
		b.set(digestAlg),
		b.sequence(b.oid(oidCTPKIData), b.explicit(0, b.octetString(pkiData))),
		b.implicit(0, certs...), // [0] IMPLICIT CertificateSet
		b.set(signerInfo),
	)
	contentInfo := b.sequence(b.oid(oidSignedData), b.explicit(0, signedData))
	if b.err != nil {
		return nil, fmt.Errorf("cmc: encoding SignedData: %w", b.err)
	}
	return contentInfo, nil
}

// signatureAlgorithm returns the AlgorithmIdentifier for signing with pub.
//
// RSA is named by rsaEncryption with NULL parameters rather than by
// sha256WithRSAEncryption: in CMS the digest is named separately, and that
// is the form Windows produces and expects.
func signatureAlgorithm(pub crypto.PublicKey) ([]byte, error) {
	b := &derBuilder{}
	var out []byte
	switch pub.(type) {
	case *rsa.PublicKey:
		out = b.sequence(b.oid(oidRSAEncryption), b.null())
	case *ecdsa.PublicKey:
		out = b.sequence(b.oid(oidECDSAWithSHA256))
	default:
		return nil, fmt.Errorf("unsupported enrollment agent key type %T", pub)
	}
	return out, b.err
}

// validateTemplateName refuses anything that is not a plain ADCS template
// name. The name is placed in the request twice — once as a BMPString
// extension, once inside the regInfo name=value string — and the second is
// unescaped, so a name containing "&" or "=" could restate the authorization.
func validateTemplateName(name string) error {
	if name == "" {
		return errors.New("no certificate template")
	}
	for _, r := range name {
		if !isAccountRune(r) {
			return fmt.Errorf("certificate template %q contains an unsupported character %q", name, r)
		}
	}
	return nil
}

// validateRequesterName refuses anything that is not DOMAIN\samAccountName in
// the narrow form whose encoding is pinned by the capture.
//
// The only escape this code has been shown to get right is the backslash, so
// a name needing any other one is refused rather than guessed at. A requester
// name that encoded wrongly would not fail loudly: it would name a different
// account, or none, and the certificate would come back for whoever the CA
// resolved instead.
func validateRequesterName(name string) error {
	if name == "" {
		return errors.New("no requester name")
	}
	domain, account, found := strings.Cut(name, `\`)
	if !found {
		return fmt.Errorf("requester name %q is not in DOMAIN\\account form", name)
	}
	if domain == "" || account == "" {
		return fmt.Errorf("requester name %q has an empty domain or account", name)
	}
	if strings.Contains(account, `\`) {
		return fmt.Errorf("requester name %q has more than one separator", name)
	}
	for _, r := range domain + account {
		if !isAccountRune(r) {
			return fmt.Errorf("requester name %q contains an unsupported character %q", name, r)
		}
	}
	return nil
}

// isAccountRune is the allowlist for names that reach the CA unescaped.
// Deliberately narrower than what Active Directory permits: widening it means
// establishing how the extra characters escape, not assuming they pass
// through.
func isAccountRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '-', r == '_', r == '.', r == '$':
		return true
	}
	return false
}

// derBuilder accumulates DER with a sticky error.
//
// Every one of these encodings is a RawValue wrap that can only fail on a tag
// out of range, so checking each call individually would bury the structure
// this file exists to make readable. The error is checked once, before the
// result is used.
type derBuilder struct {
	err error
}

func (b *derBuilder) wrap(class, tag int, compound bool, body []byte) []byte {
	if b.err != nil {
		return nil
	}
	out, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: compound, Bytes: body})
	if err != nil {
		b.err = err
		return nil
	}
	return out
}

func (b *derBuilder) sequence(parts ...[]byte) []byte {
	return b.wrap(asn1.ClassUniversal, asn1.TagSequence, true, concat(parts))
}

// set encodes a SET OF. DER requires the members sorted by their encodings,
// which matters for the signed attributes: a verifier re-encodes them.
func (b *derBuilder) set(parts ...[]byte) []byte {
	return b.wrap(asn1.ClassUniversal, asn1.TagSet, true, concat(sortDER(parts)))
}

// implicit and explicit emit the same bytes — a [tag] constructed wrapper
// around parts. Which one a construction needs is decided by what the caller
// hands over, not by these: implicit takes the *contents* of the element
// whose tag is being replaced, explicit takes the whole element unchanged.
// They are separate names because getting that backwards is the classic
// nested-context-tag mistake, and the call site is where it is visible.
func (b *derBuilder) implicit(tag int, contents ...[]byte) []byte {
	return b.wrap(asn1.ClassContextSpecific, tag, true, concat(contents))
}

func (b *derBuilder) explicit(tag int, elements ...[]byte) []byte {
	return b.wrap(asn1.ClassContextSpecific, tag, true, concat(elements))
}

// sortDER puts encodings into the ascending order DER requires of a SET OF.
func sortDER(parts [][]byte) [][]byte {
	sorted := append([][]byte(nil), parts...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
	return sorted
}

func (b *derBuilder) octetString(v []byte) []byte {
	return b.wrap(asn1.ClassUniversal, asn1.TagOctetString, false, v)
}

func (b *derBuilder) null() []byte {
	return b.wrap(asn1.ClassUniversal, asn1.TagNull, false, nil)
}

func (b *derBuilder) oid(oid asn1.ObjectIdentifier) []byte {
	if b.err != nil {
		return nil
	}
	out, err := asn1.Marshal(oid)
	if err != nil {
		b.err = err
		return nil
	}
	return out
}

func (b *derBuilder) integer(v int) []byte {
	if b.err != nil {
		return nil
	}
	out, err := asn1.Marshal(v)
	if err != nil {
		b.err = err
		return nil
	}
	return out
}

// bigInteger encodes a certificate serial number, which routinely exceeds
// what an int holds.
func (b *derBuilder) bigInteger(v *big.Int) []byte {
	if b.err != nil {
		return nil
	}
	if v == nil {
		b.err = errors.New("nil integer")
		return nil
	}
	out, err := asn1.Marshal(v)
	if err != nil {
		b.err = err
		return nil
	}
	return out
}

// raw passes through bytes that are already a complete DER element.
func (b *derBuilder) raw(v []byte) []byte { return v }

// bmpString encodes s as UTF-16BE inside a BMPString.
func (b *derBuilder) bmpString(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u>>8), byte(u))
	}
	return b.wrap(asn1.ClassUniversal, asn1.TagBMPString, false, out)
}

func concat(parts [][]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
