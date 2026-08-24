package adcs

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/encoding"
)

// The fixture's own values. The capture is of an enrollment agent
// (PKINITLAB\labadm, …-1104) asking for a certificate for a different account
// (PKINITLAB\pkinittest, …-1103) — the distinction the whole backend exists to
// make, so the tests below name both.
const (
	fixtureTemplate  = "WorkloadPKINIT"
	fixtureRequester = `PKINITLAB\pkinittest`
	fixtureTargetSID = "S-1-5-21-3734714977-4168152908-3762407930-1103"
	fixtureAgentSID  = "S-1-5-21-3734714977-4168152908-3762407930-1104"
)

// TestPKIDataMatchesTheWindowsClientByteForByte is the pin.
//
// The CMC body is fully deterministic — no signature, no nonce, no time — so
// the encoder can be held to the exact bytes Microsoft's own client produced
// for the same CSR, template and requester. Anything this file gets wrong
// about nesting, tagging or the regInfo string shows up here.
func TestPKIDataMatchesTheWindowsClientByteForByte(t *testing.T) {
	want, csrDER := fixturePKIData(t)

	got, err := buildPKIData(csrDER, fixtureTemplate, fixtureRequester)
	if err != nil {
		t.Fatalf("buildPKIData: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("PKIData differs from the captured request\n got %d bytes: %x\nwant %d bytes: %x",
			len(got), got, len(want), want)
	}
}

// TestRequesterNameIsPercentEncoded pins the one piece of the authorization
// statement that could not be derived: the domain separator is written %5C,
// not as a backslash. A "correction" to the obvious spelling fails here rather
// than at the CA, which would accept it and issue for some other account.
func TestRequesterNameIsPercentEncoded(t *testing.T) {
	got := regInfoString(fixtureTemplate, fixtureRequester)

	const want = "CertificateTemplate=WorkloadPKINIT&RequesterName=PKINITLAB%5Cpkinittest&"
	if got != want {
		t.Fatalf("regInfo string:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(got, `\`) {
		t.Errorf("regInfo string carries a literal backslash: %q", got)
	}
	if !strings.HasSuffix(got, "&") {
		t.Errorf("regInfo string is not terminated with &: %q", got)
	}
}

// TestCMCCarriesTheCSRVerbatim is a security property, not a serialisation
// detail. The workload's PKCS#10 is passed through untouched: the broker does
// not read its subject, rewrite it, or copy anything out of it, so the only
// thing it can contribute is its public key.
func TestCMCCarriesTheCSRVerbatim(t *testing.T) {
	_, csrDER := fixturePKIData(t)
	agent := testAgent(t, true)

	cmc, err := buildCMC(csrDER, fixtureTemplate, fixtureRequester, agent)
	if err != nil {
		t.Fatalf("buildCMC: %v", err)
	}
	_, embedded := pkiDataFrom(t, cmc)
	if !bytes.Equal(embedded, csrDER) {
		t.Fatal("the CSR embedded in the CMC is not the CSR that went in")
	}
}

// TestSignedAttributesAreSignedInTheirSETForm verifies the produced signature
// the way a CA does. CMS carries the signed attributes tagged [0] IMPLICIT but
// signs them tagged as a SET OF; signing the form that is carried produces a
// request that is well-formed and refused by everything.
func TestSignedAttributesAreSignedInTheirSETForm(t *testing.T) {
	_, csrDER := fixturePKIData(t)
	agent := testAgent(t, true)

	cmc, err := buildCMC(csrDER, fixtureTemplate, fixtureRequester, agent)
	if err != nil {
		t.Fatalf("buildCMC: %v", err)
	}
	attrs, signature := signerInfoFrom(t, cmc)

	// Re-tag the carried [0] IMPLICIT attributes as the SET OF the signature
	// is supposed to cover.
	asSet, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: attrs,
	})
	if err != nil {
		t.Fatalf("re-tagging signed attributes: %v", err)
	}
	digest := sha256.Sum256(asSet)
	pub := agent.Certificate.PublicKey.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("the signature does not verify over the SET OF form: %v", err)
	}
}

// TestBuildCMCRefusesACredentialThatIsNotAnEnrollmentAgent. Without the
// Certificate Request Agent application policy the CA ignores the requester
// name and issues for the caller's own account, so this refusal prevents a
// wrong success rather than a failure.
func TestBuildCMCRefusesACredentialThatIsNotAnEnrollmentAgent(t *testing.T) {
	_, csrDER := fixturePKIData(t)

	if _, err := buildCMC(csrDER, fixtureTemplate, fixtureRequester, testAgent(t, false)); err == nil {
		t.Fatal("built a CMC with a credential carrying no Certificate Request Agent policy")
	}
	if _, err := buildCMC(csrDER, fixtureTemplate, fixtureRequester, nil); err == nil {
		t.Fatal("built a CMC with no agent credential at all")
	}
}

// TestBuildCMCRefusesNamesItCannotEncode. The escaping is pinned for exactly
// one character. A name needing any other one is refused, because encoding it
// wrongly does not fail — it names a different account.
func TestBuildCMCRefusesNamesItCannotEncode(t *testing.T) {
	_, csrDER := fixturePKIData(t)
	agent := testAgent(t, true)

	for _, tc := range []struct{ name, requester, template string }{
		{"no separator", "pkinittest", fixtureTemplate},
		{"empty domain", `\pkinittest`, fixtureTemplate},
		{"empty account", `PKINITLAB\`, fixtureTemplate},
		{"two separators", `PKINITLAB\OU\pkinittest`, fixtureTemplate},
		{"ampersand restates the authorization", `PKINITLAB\a&RequesterName=PKINITLAB%5CAdministrator`, fixtureTemplate},
		{"equals sign", `PKINITLAB\a=b`, fixtureTemplate},
		{"percent", `PKINITLAB\a%5Cb`, fixtureTemplate},
		{"empty requester", "", fixtureTemplate},
		{"empty template", fixtureRequester, ""},
		{"template restates the authorization", fixtureRequester, "T&RequesterName=PKINITLAB%5CAdministrator"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildCMC(csrDER, tc.template, tc.requester, agent); err == nil {
				t.Fatalf("accepted requester %q template %q", tc.requester, tc.template)
			}
		})
	}
}

// TestIssuedCertificateNamesTheTargetNotTheAgent reads the certificate the
// captured request actually produced. It carries the *target's* SID, not the
// enrolling agent's — which is the only evidence that the requester name was
// honoured rather than ignored.
func TestIssuedCertificateNamesTheTargetNotTheAgent(t *testing.T) {
	der, err := os.ReadFile("testdata/eobo-issued-cert.der")
	if err != nil {
		t.Fatalf("reading the issued certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the issued certificate: %v", err)
	}

	sid, err := encoding.SIDFromCertificateExtensions(cert.Extensions)
	if err != nil {
		t.Fatalf("reading the AD SID extension: %v", err)
	}
	if sid != fixtureTargetSID {
		t.Errorf("issued certificate names %s, want the target %s", sid, fixtureTargetSID)
	}
	if sid == fixtureAgentSID {
		t.Error("issued certificate names the enrolling agent — the requester name was ignored")
	}
}

// fixturePKIData returns the captured request's CMC body and the PKCS#10
// embedded in it.
func fixturePKIData(t *testing.T) (pkiData, csrDER []byte) {
	t.Helper()
	der, err := os.ReadFile("testdata/cmc-eobo-windows-client.der")
	if err != nil {
		t.Fatalf("reading the captured CMC: %v", err)
	}
	return pkiDataFrom(t, der)
}

// pkiDataFrom unwraps a CMS SignedData down to the CMC body it encapsulates,
// and pulls the tagged certification request back out of it.
func pkiDataFrom(t *testing.T, der []byte) (pkiData, csrDER []byte) {
	t.Helper()

	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatalf("ContentInfo: %v", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		t.Fatalf("content type is %v, want signedData", ci.ContentType)
	}

	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo struct {
			EContentType asn1.ObjectIdentifier
			EContent     []byte `asn1:"explicit,tag:0"`
		}
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("SignedData: %v", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidCTPKIData) {
		t.Fatalf("encapsulated content is %v, want id-cct-PKIData", sd.EncapContentInfo.EContentType)
	}
	pkiData = sd.EncapContentInfo.EContent

	var body struct {
		ControlSequence asn1.RawValue
		ReqSequence     asn1.RawValue
	}
	if _, err := asn1.Unmarshal(pkiData, &body); err != nil {
		t.Fatalf("PKIData: %v", err)
	}
	var tagged asn1.RawValue
	if _, err := asn1.Unmarshal(body.ReqSequence.Bytes, &tagged); err != nil {
		t.Fatalf("TaggedRequest: %v", err)
	}
	if tagged.Class != asn1.ClassContextSpecific || tagged.Tag != 0 || !tagged.IsCompound {
		t.Fatalf("TaggedRequest is not [0] constructed: class=%d tag=%d", tagged.Class, tagged.Tag)
	}
	var bodyPartID int
	rest, err := asn1.Unmarshal(tagged.Bytes, &bodyPartID)
	if err != nil {
		t.Fatalf("bodyPartID: %v", err)
	}
	return pkiData, rest
}

// signerInfoFrom returns the single SignerInfo's carried signed attributes
// (the contents of the [0] IMPLICIT wrapper) and its signature.
func signerInfoFrom(t *testing.T, der []byte) (attrs, signature []byte) {
	t.Helper()

	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		t.Fatalf("ContentInfo: %v", err)
	}
	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		SignerInfos      asn1.RawValue `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		t.Fatalf("SignedData: %v", err)
	}
	var si struct {
		Version            int
		SID                asn1.RawValue
		DigestAlgorithm    asn1.RawValue
		SignedAttrs        asn1.RawValue `asn1:"tag:0"`
		SignatureAlgorithm asn1.RawValue
		Signature          []byte
	}
	if _, err := asn1.Unmarshal(sd.SignerInfos.Bytes, &si); err != nil {
		t.Fatalf("SignerInfo: %v", err)
	}
	if si.SignedAttrs.Class != asn1.ClassContextSpecific || si.SignedAttrs.Tag != 0 {
		t.Fatalf("signed attributes are not [0]: class=%d tag=%d", si.SignedAttrs.Class, si.SignedAttrs.Tag)
	}
	return si.SignedAttrs.Bytes, si.Signature
}

// testAgent mints a throwaway enrollment agent credential. With agent=false it
// mints one that is a valid certificate but not an enrollment agent.
func testAgent(t *testing.T, agent bool) *Agent {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("agent key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xf00d),
		Subject:      pkix.Name{CommonName: "test enrollment agent"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if agent {
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidCertificateRequestAgent}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("agent certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing agent certificate: %v", err)
	}
	return &Agent{Certificate: cert, Key: key}
}
