package httpapi

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// csrPEMType is the only PEM block this API accepts on the way in.
const csrPEMType = "CERTIFICATE REQUEST"

// certPEMType is the PEM block type used for everything sent back.
const certPEMType = "CERTIFICATE"

// issueRequest is the body of POST /issue.
//
// It contains only the CSR. There is deliberately no field for the caller's
// identity and none for the target account: the identity comes from the
// verified peer certificate and the account comes from the mapping snapshot,
// so a field for either here would be an invitation to trust the wrong source.
type issueRequest struct {
	// CSR is a PEM-armoured PKCS#10 request. Only its public key and the
	// proof-of-possession signature over it are trusted.
	CSR string `json:"csr"`
}

// issueResponse is returned on success.
type issueResponse struct {
	// Certificate is the issued leaf, PEM-armoured.
	Certificate string `json:"certificate"`

	// Chain is the intermediates between Certificate and a trusted root,
	// leaf-first, excluding the leaf. The KDC has to build a path to a CA in
	// NTAuthCertificates, and it is the leaf's immediate issuer that must be
	// published there, so the chain is not optional decoration.
	Chain []string `json:"chain"`

	// Backend names which issuance shape produced this, so a caller's own logs
	// can be correlated with the broker's.
	Backend string `json:"backend"`
}

// errorResponse is returned for every refusal.
//
// Reason is a stable machine-readable token from the broker's taxonomy; a
// client should branch on it rather than on Message, which exists for a human
// reading a log and may be reworded.
type errorResponse struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// decodeCSRPEM converts the request's PEM text to DER.
//
// It is strict about the envelope for the usual reason: a body that decodes
// two different ways depending on who is looking is a body that can be made to
// mean two different things. Wrong block type, trailing content, and PEM
// headers are all refused rather than ignored.
func decodeCSRPEM(text string) ([]byte, error) {
	if strings.TrimSpace(text) == "" {
		return nil, errors.New("csr field is empty")
	}
	block, rest := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("csr field is not PEM")
	}
	if block.Type != csrPEMType {
		return nil, fmt.Errorf("csr field is a %q block, want %q", block.Type, csrPEMType)
	}
	if len(block.Headers) != 0 {
		return nil, errors.New("csr PEM block carries headers")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("csr field has trailing content after the PEM block")
	}
	return block.Bytes, nil
}

// encodeCertPEM armours a certificate for the response.
func encodeCertPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: certPEMType, Bytes: cert.Raw}))
}
