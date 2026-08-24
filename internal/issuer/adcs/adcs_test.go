package adcs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer"
)

// The account the captured RSTRC actually names. It is the *agent's* own
// account, because that capture was taken before enrol-on-behalf-of existed —
// which makes it exactly the fixture needed to prove the backend refuses a
// certificate issued for the wrong account.
const capturedSID = "S-1-5-21-3734714977-4168152908-3762407930-1104"

// TestIssueReturnsTheCredentialItAskedFor walks the whole backend: build the
// CMC, put it on the wire, parse what comes back, and check it.
func TestIssueReturnsTheCredentialItAskedFor(t *testing.T) {
	ces := stubCES(t, nil)
	i := testIssuer(t, ces.URL)

	cred, err := i.Issue(t.Context(), testRequest(t, capturedSID))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cred.Certificate == nil {
		t.Fatal("Issue returned no certificate")
	}
	if len(cred.Chain) == 0 {
		t.Error("Issue returned no chain; the KDC needs the leaf's immediate issuer")
	}
}

// TestIssueRefusesACertificateForAnotherAccount is the point of the backend's
// final check, and the thing an ADCS deployment gets wrong silently.
//
// A requester name the CA does not honour — a credential without the
// Certificate Request Agent policy, a template not configured for it, a
// misencoded name — does not produce an error. It produces an issued, valid,
// correctly chained certificate for the wrong principal. Returning that would
// hand the caller a credential authenticating as an account the mapping never
// named.
func TestIssueRefusesACertificateForAnotherAccount(t *testing.T) {
	ces := stubCES(t, nil)
	i := testIssuer(t, ces.URL)

	const wanted = "S-1-5-21-3734714977-4168152908-3762407930-1103"
	_, err := i.Issue(t.Context(), testRequest(t, wanted))
	if err == nil {
		t.Fatal("Issue returned a certificate naming an account the mapping did not")
	}
	if !strings.Contains(err.Error(), capturedSID) || !strings.Contains(err.Error(), wanted) {
		t.Errorf("refusal does not name both SIDs, so an operator cannot act on it: %v", err)
	}
}

// TestIssueRefusesWithoutAnAccountName. The mapping's SID cannot be turned
// into the name an enrollment agent has to use, so an entry carrying only a
// SID cannot be served by this backend — and must not be served approximately.
func TestIssueRefusesWithoutAnAccountName(t *testing.T) {
	ces := stubCES(t, func(w http.ResponseWriter, r *http.Request) bool {
		t.Error("reached CES without an account name to ask for")
		return false
	})
	i := testIssuer(t, ces.URL)

	req := testRequest(t, capturedSID)
	req.ADAccount = ""
	if _, err := i.Issue(t.Context(), req); err == nil {
		t.Fatal("Issue proceeded with no account to enrol for")
	}
}

// TestIssueSendsACMCNotABarePKCS10 pins what actually goes on the wire. A
// bare PKCS#10 would be accepted by CES and would enrol the *broker*, which
// is a success returning the wrong credential rather than a failure.
func TestIssueSendsACMCNotABarePKCS10(t *testing.T) {
	var sent string
	ces := stubCES(t, func(w http.ResponseWriter, r *http.Request) bool {
		body, _ := io.ReadAll(r.Body)
		sent = string(body)
		return true
	})
	i := testIssuer(t, ces.URL)

	if _, err := i.Issue(t.Context(), testRequest(t, capturedSID)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.Contains(sent, `ValueType="`+valueTypePKCS7+`"`) {
		t.Errorf("request does not carry the CMC ValueType %q:\n%s", valueTypePKCS7, sent)
	}
	if strings.Contains(sent, valueTypePKCS10) {
		t.Error("request carries the bare-PKCS#10 ValueType, which enrols the broker as itself")
	}
	// The template is named inside the signed CMC. Naming it again outside
	// would put the same decision somewhere the agent's signature does not
	// cover.
	if strings.Contains(sent, "CertificateTemplate") {
		t.Errorf("request names the template outside the signed CMC:\n%s", sent)
	}
}

// TestCMCRequestMatchesTheWindowsClient pins the envelope against the capture:
// same ValueType, same EncodingType, and no AdditionalContext.
func TestCMCRequestMatchesTheWindowsClient(t *testing.T) {
	captured, err := os.ReadFile("testdata/rst-cmc-windows-client.xml")
	if err != nil {
		t.Fatalf("reading the captured RST: %v", err)
	}
	got, err := buildRSTForCMC("https://ca.example/service.svc/CES",
		[]byte{0x30, 0x03, 0x02, 0x01, 0x00}, "11111111-2222-3333-4444-555555555555")
	if err != nil {
		t.Fatalf("buildRSTForCMC: %v", err)
	}
	for _, want := range []string{
		`ValueType="` + valueTypePKCS7 + `"`,
		`EncodingType="` + encodingTypeBase64 + `"`,
	} {
		if !strings.Contains(string(captured), want) {
			t.Fatalf("the capture does not contain %s; the fixture and the constants have diverged", want)
		}
		if !strings.Contains(string(got), want) {
			t.Errorf("built request does not contain %s", want)
		}
	}
	// The capture's only context item is "ccm", naming the client machine,
	// which means nothing here — so the broker sends no AdditionalContext at
	// all rather than an empty one.
	if strings.Contains(string(captured), "CertificateTemplate") {
		t.Error("the captured CMC request names a certificate template outside the CMC")
	}
	if strings.Contains(string(got), "AdditionalContext") {
		t.Error("built request carries an AdditionalContext element")
	}
}

func TestNewRefusesAnIncompleteConfiguration(t *testing.T) {
	full := func() Config {
		return Config{
			CESURL:   "https://ca.example.org/CA_CES_Certificate/service.svc/CES",
			Template: "WorkloadPKINIT",
			Agent:    testAgent(t, true),
			Client:   http.DefaultClient,
		}
	}
	for _, tc := range []struct {
		name string
		mut  func(*Config)
	}{
		{"no endpoint", func(c *Config) { c.CESURL = "" }},
		{"plaintext endpoint", func(c *Config) { c.CESURL = "http://ca.example.org/service.svc/CES" }},
		{"no host", func(c *Config) { c.CESURL = "https:///service.svc/CES" }},
		{"no template", func(c *Config) { c.Template = "" }},
		{"no agent", func(c *Config) { c.Agent = nil }},
		{"agent is not an enrollment agent", func(c *Config) { c.Agent = testAgent(t, false) }},
		{"no client", func(c *Config) { c.Client = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := full()
			tc.mut(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("accepted the configuration")
			}
		})
	}
}

func TestIssueReportsAFaultFromCES(t *testing.T) {
	ces := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentTypeSOAP)
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>`+
			`<s:Reason><s:Text xml:lang="en-US">Denied by Policy Module</s:Text></s:Reason>`+
			`</s:Fault></s:Body></s:Envelope>`)
	}))
	t.Cleanup(ces.Close)

	i := testIssuer(t, ces.URL)
	_, err := i.Issue(t.Context(), testRequest(t, capturedSID))
	if err == nil {
		t.Fatal("Issue succeeded against a CES fault")
	}
	if !strings.Contains(err.Error(), "Denied by Policy Module") {
		t.Errorf("refusal does not carry the CA's reason: %v", err)
	}
}

// stubCES answers with the captured RSTRC. before, if non-nil, runs first and
// returns whether to answer.
func stubCES(t *testing.T, before func(http.ResponseWriter, *http.Request) bool) *httptest.Server {
	t.Helper()
	response, err := os.ReadFile("testdata/rstrc-response.xml")
	if err != nil {
		t.Fatalf("reading the captured RSTRC: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if before != nil && !before(w, r) {
			return
		}
		w.Header().Set("Content-Type", contentTypeSOAP)
		w.Write(response)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testIssuer builds an Issuer pointed at url. New refuses plaintext endpoints,
// so the field is set directly — the transport is what is under test here, not
// the constructor's policy.
func testIssuer(t *testing.T, url string) *Issuer {
	t.Helper()
	return &Issuer{
		cesURL:   url,
		template: "WorkloadPKINIT",
		agent:    testAgent(t, true),
		client:   http.DefaultClient,
		maxBytes: DefaultMaxResponseBytes,
	}
}

func testRequest(t *testing.T, sid string) issuer.Request {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("workload key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		// On purpose: a CSR asking to be someone else. Nothing in it is read.
		Subject: pkix.Name{CommonName: "Administrator"},
	}, key)
	if err != nil {
		t.Fatalf("workload CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse workload CSR: %v", err)
	}
	return issuer.Request{
		CSR:       csr,
		SPIFFEID:  "spiffe://pkinitlab.internal/workload/db",
		ADSID:     sid,
		ADAccount: `PKINITLAB\pkinittest`,
	}
}
