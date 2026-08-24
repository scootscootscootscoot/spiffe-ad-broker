// Package adcs implements the enrollment-agent issuance shape: the broker
// holds a Certificate Request Agent credential and asks ADCS to issue on
// behalf of the target account.
//
// This is the shape that makes the enterprise case work, because the parts
// that were blocking elsewhere are already solved by ADCS:
//
//   - ADCS's issuing CA is already in NTAuthCertificates, and it is the
//     leaf's immediate issuer — which the phase-4 lab proved is the thing
//     that actually has to be published.
//   - ADCS emits szOID_NTDS_CA_SECURITY_EXT natively, so the exact bytes
//     never have to be inferred and no fixture is needed to proceed.
//   - ADCS runs CDP/CRL infrastructure, so revocation works without
//     weakening revocation checking on the KDC.
//
// What this package must get right is narrower, and it is all authorization:
// the enrollment agent can request certificates for other accounts, so its
// credential is a high-value target and its use has to be constrained by
// template ACLs and enrollment-agent restrictions on the CA side, not by
// this code alone.
//
// The one thing this code can do about that, and does, is refuse to believe
// the CA. Issuance is delegated; the security decision is not. Every issued
// certificate is read back and refused unless it names the SID the mapping
// asked for — because a requester name that is ignored, misspelled, or
// misencoded does not fail, it succeeds for the wrong account.
package adcs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/encoding"
	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/issuer"
)

// DefaultMaxResponseBytes bounds the CES response the broker will read. An
// issued certificate plus its chain is a few kilobytes; this is generous
// enough to never bind in practice and small enough that a misbehaving or
// hostile endpoint cannot exhaust memory here.
const DefaultMaxResponseBytes = 1 << 20

// Config configures the adcs backend. Every field is required: there is no
// default endpoint, template, or credential, because each of those would be
// a guess about which CA may mint credentials for which accounts.
type Config struct {
	// CESURL is the Certificate Enrollment Web Service endpoint, e.g.
	// https://ca.example.com/Contoso%20CA_CES_Certificate/service.svc/CES
	CESURL string

	// Template is the certificate template the CA should issue from. It must
	// be configured to require one authorised signature carrying the
	// Certificate Request Agent application policy — that requirement is what
	// makes the enrollment agent's signature mean anything.
	Template string

	// Agent is the enrollment agent credential that signs the request.
	Agent *Agent

	// Client reaches CES. The broker does not build it, because how it
	// authenticates is a deployment decision: an ADCS endpoint configured for
	// certificate authentication needs a client certificate that maps to an
	// AD account, and that is a *different* credential from Agent — an
	// enrollment agent certificate carries the Certificate Request Agent
	// policy and not Client Authentication, so it cannot serve as both.
	Client *http.Client

	// MaxResponseBytes bounds the response body. Zero means
	// DefaultMaxResponseBytes.
	MaxResponseBytes int64
}

// Issuer requests certificates from ADCS as an enrollment agent.
type Issuer struct {
	cesURL   string
	template string
	agent    *Agent
	client   *http.Client
	maxBytes int64
}

// New validates cfg and returns an ADCS issuer.
//
// Configuration failures are refused here rather than at the first request:
// an endpoint that cannot issue should stop the process from starting, not
// turn every workload's first credential request into an outage that looks
// like a backend fault.
func New(cfg Config) (*Issuer, error) {
	u, err := url.Parse(cfg.CESURL)
	switch {
	case cfg.CESURL == "":
		return nil, errors.New("adcs: no CES endpoint")
	case err != nil:
		return nil, fmt.Errorf("adcs: CES endpoint: %w", err)
	case u.Scheme != "https":
		// The request carries an enrollment agent's signature over an
		// authorization statement. It does not go out in the clear.
		return nil, fmt.Errorf("adcs: CES endpoint %q is not https", cfg.CESURL)
	case u.Host == "":
		return nil, fmt.Errorf("adcs: CES endpoint %q has no host", cfg.CESURL)
	}
	if err := validateTemplateName(cfg.Template); err != nil {
		return nil, fmt.Errorf("adcs: %w", err)
	}
	if err := cfg.Agent.Validate(); err != nil {
		return nil, fmt.Errorf("adcs: %w", err)
	}
	if cfg.Client == nil {
		return nil, errors.New("adcs: no HTTP client for CES")
	}
	maxBytes := cfg.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxResponseBytes
	}
	return &Issuer{
		cesURL:   cfg.CESURL,
		template: cfg.Template,
		agent:    cfg.Agent,
		client:   cfg.Client,
		maxBytes: maxBytes,
	}, nil
}

// Name identifies this backend.
func (i *Issuer) Name() string { return "adcs" }

// Issue asks ADCS to issue for the account the mapping named.
//
// The workload's PKCS#10 is wrapped, unread and unmodified, in a CMC that the
// enrollment agent signs; the CA builds the subject from Active Directory for
// the account the CMC names. So the workload contributes a public key and
// nothing else, and the account comes from the snapshot and nothing else.
func (i *Issuer) Issue(ctx context.Context, req issuer.Request) (*issuer.Credential, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	// The SID alone cannot be asked for: an enrollment agent names the target
	// by account name. Deriving one from the other would mean either a
	// directory lookup on the issuance path or a guess, and both would move
	// the decision out of the authoritative mapping.
	if req.ADAccount == "" {
		return nil, fmt.Errorf(
			"adcs: the mapping entry for %s carries no ad_account, and an enrollment agent names the target account by name",
			req.SPIFFEID)
	}

	cmc, err := buildCMC(req.CSR.Raw, i.template, req.ADAccount, i.agent)
	if err != nil {
		return nil, err
	}
	messageID, err := newMessageID()
	if err != nil {
		return nil, err
	}
	body, err := buildRSTForCMC(i.cesURL, cmc, messageID)
	if err != nil {
		return nil, err
	}

	cred, err := i.submit(ctx, body)
	if err != nil {
		return nil, err
	}
	if err := i.verify(cred, req); err != nil {
		return nil, err
	}
	return cred, nil
}

// submit POSTs an RST to CES and parses what comes back.
func (i *Issuer) submit(ctx context.Context, body []byte) (*issuer.Credential, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, i.cesURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("adcs: building the CES request: %w", err)
	}
	httpReq.Header.Set("Content-Type", contentTypeSOAP)

	resp, err := i.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("adcs: reaching CES: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, i.maxBytes))
	if err != nil {
		return nil, fmt.Errorf("adcs: reading the CES response: %w", err)
	}
	if int64(len(respBody)) >= i.maxBytes {
		return nil, fmt.Errorf("adcs: CES response exceeds %d bytes", i.maxBytes)
	}
	// A SOAP fault arrives with a 500, and parseRSTRC reports it far more
	// usefully than the status line does, so the body is parsed either way
	// and the status only decides what to say when it carries nothing.
	cred, parseErr := parseRSTRC(respBody)
	if parseErr != nil {
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("adcs: CES returned %s: %w", resp.Status, parseErr)
		}
		return nil, parseErr
	}
	return cred, nil
}

// verify refuses a credential that is not the one that was asked for.
//
// This is the whole reason the backend does not simply return what the CA
// sent. Naming the target account is a *request*; whether the CA acted on it
// depends on the enrollment agent's rights, the template's configuration, and
// the exact encoding of the name. When any of those is wrong the CA does not
// refuse — it issues for whoever it resolved instead, which in the observed
// case is the broker's own account. That certificate is valid, chains
// correctly, and authenticates as the wrong principal.
func (i *Issuer) verify(cred *issuer.Credential, req issuer.Request) error {
	if cred == nil || cred.Certificate == nil {
		return errors.New("adcs: CES returned no certificate")
	}
	sid, err := encoding.SIDFromCertificateExtensions(cred.Certificate.Extensions)
	if err != nil {
		return fmt.Errorf("adcs: issued certificate for %s: %w", req.SPIFFEID, err)
	}
	if sid != req.ADSID {
		return fmt.Errorf(
			"adcs: issued certificate names %s, but the mapping for %s says %s — the requester name was not honoured",
			sid, req.SPIFFEID, req.ADSID)
	}
	// Without the immediate issuer the KDC cannot reach a CA in
	// NTAuthCertificates, and per the phase-4 lab chaining to a published
	// root is not enough. A leaf on its own is not a usable credential here,
	// so returning one would be a refusal dressed as a success.
	//
	// The certificates arrive in whatever order the response's PKCS#7 put
	// them in, so the issuer is searched for rather than assumed to be
	// first, and moved to the front to match Credential's leaf-first
	// contract. Signature over name match: two CAs can share a subject.
	issuerAt := -1
	for i, c := range cred.Chain {
		if cred.Certificate.CheckSignatureFrom(c) == nil {
			issuerAt = i
			break
		}
	}
	if issuerAt < 0 {
		return fmt.Errorf("adcs: issued certificate for %s came back without its issuer %q; the KDC needs it in NTAuthCertificates",
			req.SPIFFEID, strings.TrimSpace(cred.Certificate.Issuer.String()))
	}
	cred.Chain[0], cred.Chain[issuerAt] = cred.Chain[issuerAt], cred.Chain[0]
	return nil
}
