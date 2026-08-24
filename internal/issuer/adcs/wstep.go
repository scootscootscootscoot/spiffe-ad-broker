package adcs

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer"
)

// MS-WSTEP wire constants.
//
// These are captured from a real Windows client (certreq) talking to a real
// ADCS Certificate Enrollment Web Service, and pinned by a golden test
// against testdata/rst-windows-client.xml. Do not "correct" them against a
// specification: encodingTypeBase64 in particular is *not* the value
// WS-Security defines, and the documented one is rejected. See
// docs/findings/2026-08-17-wstep-request-body.md.
const (
	actionRST   = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"
	actionRSTRC = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"

	tokenTypeX509    = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
	requestTypeIssue = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"

	valueTypePKCS10 = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
	valueTypePKCS7  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7"

	// Note the namespace: this is the wssecurity-secext schema URI with a
	// "#base64binary" fragment, lowercase. WS-Security documents
	// ".../oasis-200401-wss-soap-message-security-1.0#Base64Binary"; ADCS
	// rejects that with "The EncodingType is invalid."
	encodingTypeBase64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"

	// contentTypeSOAP is what CES expects on the POST. SOAP 1.2.
	contentTypeSOAP = "application/soap+xml; charset=utf-8"
)

// rstTemplate is the RequestSecurityToken envelope, laid out to match what a
// Windows client sends. Every substituted value is XML-escaped by buildRSTBody.
//
// The substitutions are, in order: message ID, destination, the token's
// ValueType, the base64 request, and the AdditionalContext element (which is
// omitted entirely for a CMC — see buildRSTForCMC).
const rstTemplate = `<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">` +
	`<s:Header>` +
	`<a:Action s:mustUnderstand="1">` + actionRST + `</a:Action>` +
	`<a:MessageID>urn:uuid:%s</a:MessageID>` +
	`<a:To s:mustUnderstand="1">%s</a:To>` +
	`</s:Header>` +
	`<s:Body>` +
	`<RequestSecurityToken PreferredLanguage="en-US" xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">` +
	`<TokenType>` + tokenTypeX509 + `</TokenType>` +
	`<RequestType>` + requestTypeIssue + `</RequestType>` +
	`<BinarySecurityToken ValueType="%s" EncodingType="` + encodingTypeBase64 + `"` +
	` a:Id="" xmlns:a="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"` +
	` xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">%s</BinarySecurityToken>` +
	`%s` +
	`</RequestSecurityToken>` +
	`</s:Body>` +
	`</s:Envelope>`

// templateContext names the certificate template outside the request. Only
// the PKCS#10 form needs it.
const templateContext = `<AdditionalContext xmlns="http://schemas.xmlsoap.org/ws/2006/12/authorization">` +
	`<ContextItem Name="CertificateTemplate"><Value>%s</Value></ContextItem>` +
	`</AdditionalContext>`

// buildRST renders an enrollment request for csrDER against templateName.
//
// csrDER is the workload's PKCS#10, passed through verbatim. Nothing in it is
// read here, and nothing about the target account is expressed here: this
// function carries bytes, it does not make an authorization decision. It
// enrols whoever the transport authenticated as, which is why the broker uses
// buildRSTForCMC instead.
func buildRST(to, templateName string, csrDER []byte, messageID string) ([]byte, error) {
	if templateName == "" {
		return nil, errors.New("wstep: no certificate template")
	}
	if len(csrDER) == 0 {
		return nil, errors.New("wstep: empty CSR")
	}
	return buildRSTBody(to, valueTypePKCS10, csrDER, messageID,
		fmt.Sprintf(templateContext, escape(templateName)))
}

// buildRSTForCMC renders an enrollment request carrying cmcDER, a CMC that
// names the account to issue for and is signed by the enrollment agent.
//
// Two things differ from the PKCS#10 form, and both were captured from
// Microsoft's own client rather than derived — see
// testdata/rst-cmc-windows-client.xml:
//
//   - The ValueType is the wssecurity-secext "#PKCS7" value, the same one
//     ADCS uses to tag the chain it returns. It is *not* an "#CMC" spelling
//     under the enrollment namespace, which is the obvious guess.
//
//   - There is no CertificateTemplate context item. The template is named
//     inside the CMC, where the agent's signature covers it. Naming it
//     outside as well would put the same decision in two places, one of them
//     unsigned.
func buildRSTForCMC(to string, cmcDER []byte, messageID string) ([]byte, error) {
	if len(cmcDER) == 0 {
		return nil, errors.New("wstep: empty CMC request")
	}
	return buildRSTBody(to, valueTypePKCS7, cmcDER, messageID, "")
}

func buildRSTBody(to, valueType string, der []byte, messageID, context string) ([]byte, error) {
	if to == "" {
		return nil, errors.New("wstep: no CES endpoint")
	}
	if messageID == "" {
		return nil, errors.New("wstep: no message ID")
	}
	body := fmt.Sprintf(rstTemplate,
		escape(messageID),
		escape(to),
		valueType,
		base64.StdEncoding.EncodeToString(der),
		context,
	)
	return []byte(body), nil
}

// escape renders s as XML character data.
func escape(s string) string {
	var b bytes.Buffer
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		// EscapeText only fails if the writer fails, and bytes.Buffer does not.
		panic("wstep: escaping: " + err.Error())
	}
	return b.String()
}

// newMessageID returns a random RFC 4122 version 4 UUID for wsa:MessageID.
func newMessageID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("wstep: message ID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// binarySecurityToken is one base64 blob in an RSTRC, tagged with what it is.
type binarySecurityToken struct {
	ValueType    string `xml:"ValueType,attr"`
	EncodingType string `xml:"EncodingType,attr"`
	Value        string `xml:",chardata"`
}

// der decodes the token's payload. ADCS wraps base64 across lines, so
// whitespace is stripped before decoding.
func (t binarySecurityToken) der() ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, t.Value)
	if clean == "" {
		return nil, errors.New("empty token")
	}
	return base64.StdEncoding.DecodeString(clean)
}

// rstrcEnvelope models only the parts of the response this code acts on.
//
// The nesting matters and is load-bearing: the *leaf* certificate is the
// token inside RequestedSecurityToken. The token that is a direct child of
// RequestSecurityTokenResponse is the PKCS#7 chain. Reading the first
// BinarySecurityToken in document order gets the chain, not the leaf.
type rstrcEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Header  struct {
		Action string `xml:"Action"`
	} `xml:"Header"`
	Body struct {
		Fault *struct {
			Reason string `xml:"Reason>Text"`
			Detail string `xml:"Detail"`
		} `xml:"Fault"`
		Collection struct {
			Responses []struct {
				TokenType   string `xml:"TokenType"`
				Disposition string `xml:"DispositionMessage"`
				RequestID   string `xml:"RequestID"`
				// Direct children only: the PKCS#7 chain.
				Chain []binarySecurityToken `xml:"BinarySecurityToken"`
				// The leaf, nested one level down.
				Requested struct {
					Token binarySecurityToken `xml:"BinarySecurityToken"`
				} `xml:"RequestedSecurityToken"`
			} `xml:"RequestSecurityTokenResponse"`
		} `xml:"RequestSecurityTokenResponseCollection"`
	} `xml:"Body"`
}

// parseRSTRC turns a CES response into a credential.
//
// It fails closed. Anything it does not positively recognise — a SOAP fault,
// a missing leaf, a token tagged as something other than an X.509
// certificate, a certificate that does not parse — is an error, never a
// partial credential.
func parseRSTRC(body []byte) (*issuer.Credential, error) {
	var env rstrcEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("wstep: malformed response: %w", err)
	}
	if f := env.Body.Fault; f != nil {
		reason := strings.TrimSpace(f.Reason)
		if reason == "" {
			reason = "unspecified"
		}
		return nil, fmt.Errorf("wstep: CES refused: %s", reason)
	}
	if got := env.Header.Action; got != actionRSTRC {
		return nil, fmt.Errorf("wstep: unexpected response action %q", got)
	}
	rs := env.Body.Collection.Responses
	if len(rs) != 1 {
		return nil, fmt.Errorf("wstep: expected 1 token response, got %d", len(rs))
	}
	r := rs[0]

	if r.Requested.Token.ValueType != tokenTypeX509 {
		return nil, fmt.Errorf("wstep: issued token is %q, want an X.509 certificate (disposition: %s)",
			r.Requested.Token.ValueType, strings.TrimSpace(r.Disposition))
	}
	leafDER, err := r.Requested.Token.der()
	if err != nil {
		return nil, fmt.Errorf("wstep: issued token: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("wstep: issued certificate: %w", err)
	}

	chain, err := chainFrom(r.Chain, leaf)
	if err != nil {
		return nil, err
	}
	return &issuer.Credential{Certificate: leaf, Chain: chain}, nil
}

// chainFrom extracts the intermediates from the PKCS#7 token, excluding the
// leaf itself. The KDC has to build a path to a CA in NTAuthCertificates, and
// per the phase-4 lab it is the leaf's immediate issuer that must be
// published there — so the chain is not optional decoration.
func chainFrom(tokens []binarySecurityToken, leaf *x509.Certificate) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for _, t := range tokens {
		if t.ValueType != valueTypePKCS7 {
			continue
		}
		der, err := t.der()
		if err != nil {
			return nil, fmt.Errorf("wstep: chain token: %w", err)
		}
		certs, err := certsFromPKCS7(der)
		if err != nil {
			return nil, fmt.Errorf("wstep: chain: %w", err)
		}
		for _, c := range certs {
			if c.Equal(leaf) {
				continue
			}
			chain = append(chain, c)
		}
	}
	return chain, nil
}

// certsFromPKCS7 pulls the certificates out of a degenerate (certificates
// only) PKCS#7 SignedData. Written by hand because the standard library has
// no PKCS#7 and this module takes no dependencies.
func certsFromPKCS7(der []byte) ([]*x509.Certificate, error) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("content type is %v, want signedData", ci.ContentType)
	}
	// SignedData's fields after certificates (crls, signerInfos) are left
	// unconsumed on purpose; encoding/asn1 does not require them here.
	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		EncapContentInfo asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("SignedData: %w", err)
	}
	var certs []*x509.Certificate
	rest := sd.Certificates.Bytes
	for len(rest) > 0 {
		var raw asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &raw)
		if err != nil {
			return nil, fmt.Errorf("certificate: %w", err)
		}
		c, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
