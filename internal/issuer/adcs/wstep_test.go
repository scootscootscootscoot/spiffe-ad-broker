package adcs

import (
	"encoding/base64"
	"encoding/xml"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The wire format is pinned to a request captured from a real Windows client
// (certreq) against a real ADCS CES endpoint. It is not derived from the
// MS-WSTEP or WS-Security specifications, and it disagrees with them.
func loadWindowsCapture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/rst-windows-client.xml")
	if err != nil {
		t.Fatalf("reading captured request: %v", err)
	}
	return string(b)
}

// attr pulls one attribute off the captured BinarySecurityToken.
func attr(t *testing.T, doc, name string) string {
	t.Helper()
	re := regexp.MustCompile(`<BinarySecurityToken[^>]*\s` + name + `="([^"]*)"`)
	m := re.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("captured request has no %s attribute", name)
	}
	return m[1]
}

// TestEncodingTypeMatchesWindowsClient is the whole reason this fixture
// exists. The documented WS-Security value is
// ".../oasis-200401-wss-soap-message-security-1.0#Base64Binary"; ADCS rejects
// it with "The EncodingType is invalid." What Microsoft's own client sends is
// the secext schema URI with a lowercase "#base64binary" fragment.
//
// If this test fails because someone made the constant match the
// specification, the specification is not the authority here. The capture is.
func TestEncodingTypeMatchesWindowsClient(t *testing.T) {
	doc := loadWindowsCapture(t)

	if got := attr(t, doc, "EncodingType"); got != encodingTypeBase64 {
		t.Errorf("EncodingType\n got  %q\n want %q (as captured from a Windows client)", encodingTypeBase64, got)
	}
	if got := attr(t, doc, "ValueType"); got != valueTypePKCS10 {
		t.Errorf("ValueType\n got  %q\n want %q", valueTypePKCS10, got)
	}
	if strings.Contains(encodingTypeBase64, "soap-message-security") {
		t.Error("EncodingType was changed to the documented WS-Security value, which ADCS rejects")
	}
}

// TestBuiltRequestMatchesWindowsClient checks the envelope this package
// produces against the captured one, field by field. The two are not
// byte-identical — the Windows client wraps its base64 and adds a "ccm"
// context item naming the client machine — so comparing the parts that carry
// meaning is the honest check.
func TestBuiltRequestMatchesWindowsClient(t *testing.T) {
	captured := loadWindowsCapture(t)

	capturedCSR, err := base64.StdEncoding.DecodeString(unwrapBase64(innerText(t, captured, "BinarySecurityToken")))
	if err != nil {
		t.Fatalf("captured CSR is not base64: %v", err)
	}

	got, err := buildRST(
		innerText(t, captured, "To"),
		innerText(t, captured, "Value"),
		capturedCSR,
		strings.TrimPrefix(innerText(t, captured, "MessageID"), "urn:uuid:"),
	)
	if err != nil {
		t.Fatalf("buildRST: %v", err)
	}
	built := string(got)

	for _, elem := range []string{"Action", "MessageID", "To", "TokenType", "RequestType", "Value"} {
		if a, b := innerText(t, built, elem), innerText(t, captured, elem); a != b {
			t.Errorf("%s\n built    %q\n captured %q", elem, a, b)
		}
	}
	for _, a := range []string{"ValueType", "EncodingType"} {
		if x, y := attr(t, built, a), attr(t, captured, a); x != y {
			t.Errorf("%s\n built    %q\n captured %q", a, x, y)
		}
	}
	if x, y := unwrapBase64(innerText(t, built, "BinarySecurityToken")), unwrapBase64(innerText(t, captured, "BinarySecurityToken")); x != y {
		t.Error("the carried PKCS#10 differs from the captured one")
	}
}

// TestBuiltRequestIsWellFormed guards against the template being edited into
// something that no longer parses.
func TestBuiltRequestIsWellFormed(t *testing.T) {
	got, err := buildRST("https://ca.example/service.svc/CES", "User", []byte{0x30, 0x03, 0x02, 0x01, 0x00}, "11111111-2222-3333-4444-555555555555")
	if err != nil {
		t.Fatalf("buildRST: %v", err)
	}
	var v any
	if err := xml.Unmarshal(got, &v); err != nil {
		t.Fatalf("built request is not well-formed XML: %v", err)
	}
}

// A template name is configuration, but it still reaches the wire, and XML
// injection there would let a badly-set config change the request's shape.
func TestTemplateNameIsEscaped(t *testing.T) {
	got, err := buildRST("https://ca.example/service.svc/CES", `User"><Evil/><Value>`, []byte{0x30, 0x00}, "11111111-2222-3333-4444-555555555555")
	if err != nil {
		t.Fatalf("buildRST: %v", err)
	}
	if strings.Contains(string(got), "<Evil/>") {
		t.Error("template name was not escaped: XML injection into the request")
	}
	var v any
	if err := xml.Unmarshal(got, &v); err != nil {
		t.Fatalf("escaped request is not well-formed: %v", err)
	}
}

// buildRST refuses rather than emitting a request that cannot mean anything.
func TestBuildRSTFailsClosed(t *testing.T) {
	ok := []byte{0x30, 0x00}
	cases := []struct {
		name          string
		to, tmpl, msg string
		csr           []byte
	}{
		{"no endpoint", "", "User", "id", ok},
		{"no template", "https://ca.example/x", "", "id", ok},
		{"no CSR", "https://ca.example/x", "User", "id", nil},
		{"no message ID", "https://ca.example/x", "User", "", ok},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := buildRST(c.to, c.tmpl, c.csr, c.msg); err == nil {
				t.Fatal("expected a refusal, got a request")
			}
		})
	}
}

func TestNewMessageIDIsAVersion4UUID(t *testing.T) {
	seen := map[string]bool{}
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for i := 0; i < 100; i++ {
		id, err := newMessageID()
		if err != nil {
			t.Fatalf("newMessageID: %v", err)
		}
		if !re.MatchString(id) {
			t.Fatalf("not a v4 UUID: %q", id)
		}
		if seen[id] {
			t.Fatalf("repeated message ID %q", id)
		}
		seen[id] = true
	}
}

func loadResponse(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/rstrc-response.xml")
	if err != nil {
		t.Fatalf("reading captured response: %v", err)
	}
	return b
}

// TestParseRSTRCReturnsTheLeafNotTheChain is the trap this fixture pins. The
// first BinarySecurityToken in document order is the PKCS#7 chain; the issued
// certificate is the one nested inside RequestedSecurityToken. A parser that
// takes the first token returns a chain blob and calls it a certificate.
func TestParseRSTRCReturnsTheLeafNotTheChain(t *testing.T) {
	cred, err := parseRSTRC(loadResponse(t))
	if err != nil {
		t.Fatalf("parseRSTRC: %v", err)
	}
	if cred.Certificate == nil {
		t.Fatal("no certificate returned")
	}
	if cred.Certificate.Subject.CommonName != "labadm" {
		t.Errorf("leaf CN = %q, want %q", cred.Certificate.Subject.CommonName, "labadm")
	}
	if cred.Certificate.IsCA {
		t.Error("returned a CA certificate as the leaf: the chain token was read instead of the issued one")
	}
	if len(cred.Chain) == 0 {
		t.Fatal("no chain returned; the KDC needs a path to the CA published in NTAuth")
	}
	for _, c := range cred.Chain {
		if c.Equal(cred.Certificate) {
			t.Error("chain contains the leaf; Chain is documented as excluding it")
		}
	}
	// The leaf's immediate issuer is the thing that must be in NTAuth, so it
	// is the thing the chain has to carry.
	issuerPresent := false
	for _, c := range cred.Chain {
		if c.Subject.String() == cred.Certificate.Issuer.String() {
			issuerPresent = true
		}
	}
	if !issuerPresent {
		t.Error("chain does not include the leaf's immediate issuer")
	}
}

// The issued certificate must carry the AD SID extension, or it will not
// authenticate as the account it names.
func TestIssuedCertificateCarriesTheADSIDExtension(t *testing.T) {
	cred, err := parseRSTRC(loadResponse(t))
	if err != nil {
		t.Fatalf("parseRSTRC: %v", err)
	}
	for _, e := range cred.Certificate.Extensions {
		if e.Id.String() == "1.3.6.1.4.1.311.25.2" {
			return
		}
	}
	t.Error("issued certificate has no szOID_NTDS_CA_SECURITY_EXT")
}

func TestParseRSTRCFailsClosed(t *testing.T) {
	good := string(loadResponse(t))

	cases := []struct {
		name string
		body string
	}{
		{"not XML", "this is not xml at all"},
		{"empty", ""},
		{"soap fault", `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>` +
			`<s:Fault><s:Reason><s:Text>The EncodingType is invalid.</s:Text></s:Reason></s:Fault>` +
			`</s:Body></s:Envelope>`},
		{"wrong action", strings.Replace(good, actionRSTRC, "http://example.invalid/other", 1)},
		{"leaf token mistyped", strings.Replace(good,
			`<BinarySecurityToken ValueType="`+tokenTypeX509+`"`,
			`<BinarySecurityToken ValueType="http://example.invalid/not-a-cert"`, 1)},
		{"leaf not a certificate", replaceLeafPayload(good, "AAAA")},
		{"leaf not base64", replaceLeafPayload(good, "!!!! not base64 !!!!")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cred, err := parseRSTRC([]byte(c.body))
			if err == nil {
				t.Fatalf("expected a refusal, got a credential: %+v", cred)
			}
			if cred != nil {
				t.Error("refused but still returned a credential")
			}
		})
	}
}

// A SOAP fault must surface the server's reason, not be flattened into a
// generic failure: "The EncodingType is invalid." is exactly the message that
// cost a session to diagnose.
func TestSOAPFaultReasonIsReported(t *testing.T) {
	body := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>` +
		`<s:Fault><s:Reason><s:Text>The EncodingType is invalid.</s:Text></s:Reason></s:Fault>` +
		`</s:Body></s:Envelope>`
	_, err := parseRSTRC([]byte(body))
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "The EncodingType is invalid.") {
		t.Errorf("fault reason not surfaced: %v", err)
	}
}

// innerText returns the text of the first <elem>…</elem> in doc.
func innerText(t *testing.T, doc, elem string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)<(?:\w+:)?` + elem + `[^>]*>(.*?)</(?:\w+:)?` + elem + `>`)
	m := re.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("no <%s> in document", elem)
	}
	return m[1]
}

// replaceLeafPayload swaps the issued certificate's base64 for something
// else, leaving the surrounding envelope intact.
func replaceLeafPayload(doc, payload string) string {
	re := regexp.MustCompile(`(?s)(<RequestedSecurityToken><BinarySecurityToken[^>]*>).*?(</BinarySecurityToken>)`)
	return re.ReplaceAllString(doc, "${1}"+payload+"${2}")
}

func unwrapBase64(s string) string {
	s = strings.ReplaceAll(s, "&#xD;", "")
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
}
