# Changelog

Notable changes to `spiffe-ad-broker`. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once there is anything to
release. Nothing has been released yet, so everything sits under Unreleased.

## [Unreleased]

### Added

- **`internal/issuer/adcs` issues.** `Issue` wraps the workload's PKCS#10 — unread and
  unmodified — in a CMC that names the mapped AD account and is signed by an enrollment
  agent credential, POSTs it to CES, and returns the certificate ADCS issues for that
  account. The workload keeps its private key throughout; the broker signs only as the
  agent. Proven against a live Windows Server 2025 CA: request 17, issued for
  `pkinittest` (`…-1103`) from a request the broker built.
- `internal/issuer/adcs/cmc.go` — the CMC (RFC 5272 in RFC 5652 CMS) enrol-on-behalf-of
  encoder, hand-built because this module takes no dependencies. The CMC body is
  deterministic, so it is pinned **byte for byte** to a request captured from
  Microsoft's own client, not merely structurally.
- `adcs.Agent` — the enrollment agent credential, behind `crypto.Signer` so an HSM or
  KMS signer works unchanged. It refuses a certificate that does not carry the
  Certificate Request Agent application policy: without it the CA ignores the requester
  name and issues for the caller's own account, which is a wrong success rather than a
  failure.
- `adcs.Config` / `adcs.New` — CES endpoint, template, agent credential and HTTP client.
  Configuration failures refuse at startup rather than turning every first credential
  request into something that looks like a backend fault. The endpoint must be https.
- `mapping.Entry.ADAccount` (`ad_account`) and `mapping.Account` — the target account's
  `DOMAIN\samAccountName`, alongside its SID. An enrollment agent names its target by
  *name*; the SID is what comes back, not what goes out. Both come from the authoritative
  snapshot and neither is derived from the other, because resolving one to the other
  would put a directory lookup on the issuance path. Optional per entry: `subordinate`
  never needs it, and the `adcs` backend refuses without it.
- `mapping.ValidateAccountName` — `DOMAIN\samAccountName`, one separator, and a
  character set deliberately narrower than Active Directory's. `&`, `=` and `%` are
  refused specifically: unescaped, each could restate the authorization inside the CMC's
  `regInfo` string.
- `issuer.Request.ADAccount`, validated in `Request.Validate` when present, so a
  malformed name is refused in the one place the security model lives rather than at
  whichever backend happens to read it.
- `internal/issuer/adcs/testdata/cmc-eobo-windows-client.der`,
  `eobo-issued-cert.der`, `rst-cmc-windows-client.xml` — three more real captures: the
  CMC Microsoft's client builds, the certificate it produced (carrying the *target's*
  SID, not the agent's), and the CES envelope that carries a CMC. Synthetic lab forest,
  no key material.
- `docs/findings/2026-08-24-enroll-on-behalf-of.md` — the requester name must be inside
  the enrollment agent's signature, in the CMC `regInfo` control, with the domain
  separator percent-encoded as `%5C`. Passing it as an unsigned submission attribute is
  **accepted, ignored, and silent**: the CA returns a valid certificate for the caller's
  own account. Also settles that ADCS accepts a CMC signed by the agent alone — the
  broker can never produce the second signature `certreq` adds, so the whole shape
  depended on it — and that a CMC rides the CES wire tagged `…secext-1.0.xsd#PKCS7`
  with no `CertificateTemplate` context item.
- `-adcs-ces-url`, `-adcs-template`, `-adcs-agent-cert`, `-adcs-agent-key`,
  `-adcs-client-cert`, `-adcs-client-key`, `-adcs-ca-bundle`, `-adcs-timeout`, all
  required with `-backend adcs`. The agent credential and the CES client credential are
  **separate and not interchangeable**: an enrollment agent certificate carries the
  Certificate Request Agent policy and not Client Authentication, so it cannot
  authenticate the TLS connection to a CES endpoint configured for certificate
  authentication.

- `encoding.BuildNTDSCASecurityExt` — the AD SID security extension
  (`szOID_NTDS_CA_SECURITY_EXT`), pinned byte for byte to a fixture taken from a
  certificate a real ADCS Enterprise CA issued. This was the one item on the board that
  was blocked, inherited unsolved from the predecessor; standing up ADCS for the
  request-path work produced the fixture. See
  `docs/findings/2026-08-17-ad-sid-extension-encoding.md`.
- `encoding.SIDFromCertificateExtensions` — reads the SID back out of an issued
  certificate, so a backend that delegates issuance can check that what came back names
  the account that was asked for. Delegating issuance is not the same as delegating the
  security decision.
- `internal/encoding/testdata/` — the ADCS-issued fixture certificate and the extracted
  extension, with their provenance recorded. Synthetic: a throwaway account in a
  disposable lab forest.
- `internal/issuer/adcs/wstep.go` — the MS-WSTEP layer: builds the
  `RequestSecurityToken` that carries a PKCS#10 to a CES endpoint, and parses the
  `RequestSecurityTokenResponseCollection` back into a leaf certificate and its chain,
  including a hand-written certificates-only PKCS#7 reader (the standard library has no
  PKCS#7 and this module takes no dependencies). It fails closed: a SOAP fault, an
  unexpected action, a missing or mistyped token, or a certificate that does not parse
  is an error, never a partial credential.
- `internal/issuer/adcs/testdata/` — two real wire captures, with provenance recorded. A
  `RequestSecurityToken` sent by Microsoft's own client, and a successful ADCS response.
  Synthetic lab forest, no key material.
- `docs/findings/2026-08-17-wstep-request-body.md` — the MS-WSTEP `EncodingType` ADCS
  accepts is **not** the one WS-Security documents. It is the `wssecurity-secext` schema
  URI with a lowercase `#base64binary` fragment; the documented
  `soap-message-security-1.0#Base64Binary` is refused with `The EncodingType is
  invalid.`, as is every other documented spelling. Captured by pointing `certreq` at a
  recording endpoint holding a CA-issued TLS certificate, which is also how the response
  shape was pinned. With the one constant corrected, a stdlib-only Go client submits a
  PKCS#10 to a live CES endpoint and gets an issued certificate back, so the `adcs`
  transport is proven end to end.

- `docs/findings/2026-08-17-adcs-request-path.md` — the `adcs` backend speaks CMC/WSTEP
  over the CES/CEP HTTP endpoints, authenticated with a client certificate, and a
  zero-dependency Go client reaches it. Records the two `http.sys` settings
  (`clientcertnegotiation`, `dsmapperusage`) that the backend will have to document as
  deployment prerequisites, because without them the endpoint works from curl and is
  unusable from Go.

### Changed

- **The `adcs` backend checks what it gets back.** Every issued certificate is read for
  its AD SID extension and refused unless it names the SID the mapping asked for, along
  with a chain to its immediate issuer. This is not defensive decoration: an ADCS
  deployment where the requester name is not honoured does not fail, it issues a valid,
  correctly chained certificate for the wrong principal. Delegating issuance is not
  delegating the security decision.
- `wstep.buildRST` grew a sibling, `buildRSTForCMC`, and the envelope's
  `AdditionalContext` element is now optional rather than always present.
- `mapping.Registry.Lookup` returns a `mapping.Account` rather than a bare SID string.
- `adcs.New` takes a `Config` and returns an error. The startup banner no longer claims
  no backend is implemented; it warns only when `subordinate` is configured.

- `internal/issuer/adcs` no longer describes the request path as undecided. `Issue` still
  refuses, but for a narrower reason: the transport is built and proven, and what is
  missing is authorization — the enrollment-agent credential and the CMC signed-request
  shape that enrols *on behalf of* the target account. Everything proven so far enrols
  the broker as itself.

- `internal/encoding` docs no longer describe the SID extension's encoding as an open
  question. It is settled: the extension carries the SID as its textual `S-1-…`
  rendering, **not** the MS-DTYP binary layout `MarshalSID` produces. `MarshalSID` keeps
  its role as the canonical `objectSid` representation and as the validator that a SID
  parses before it can reach a certificate.

- `internal/broker` — the authenticate-and-map path, and the only place issuance
  decisions are made. Takes a SPIFFE ID the transport has already proven and a DER
  PKCS#10 request; returns a credential or a classified refusal. It knows nothing about
  HTTP, so the security properties are testable without standing up a server and the
  transport choice stays reversible.
- `broker.Reason` — the refusal taxonomy (`unauthenticated`, `invalid_request`,
  `no_mapping`, `not_implemented`, `internal`). Transports map a reason to their own
  status vocabulary rather than parsing error text, and adding a failure mode means
  choosing a reason for it.
- `internal/transport/httpapi` — HTTP over mutual TLS, one route:
  `POST /issue {"csr": "<PEM>"}` returning the certificate, its chain, and the backend
  that produced it. Refusals are `{"error": {"reason", "message"}}`.
- `httpapi.SPIFFEIDFromPeer` — the authentication. Reads the caller's SPIFFE ID out of
  the verified peer certificate.
- `internal/tlsconf` — mutual-TLS configuration built from files on disk and reloaded
  when they change, because the broker's own certificate is an SVID with an hours-long
  life and the trust bundle rotates with the trust domain's CA.
- `cmd/spiffe-ad-broker` — now a real server: flags for the listen address, TLS material,
  mapping snapshot, backend, and snapshot freshness bound; structured logging in text or
  JSON; graceful shutdown on SIGINT/SIGTERM. It logs plainly at startup that no backend
  can issue yet, rather than leaving that to be discovered from a 501.
- Initial scaffold: module `github.com/scootscootscootscoot/spiffe-ad-broker`, Go 1.26.5,
  Apache-2.0.
- `internal/issuer` — the contract every issuance backend implements. `Request` carries
  the workload's CSR, the caller's proven SPIFFE ID, and the mapped AD SID; `Credential`
  carries the issued certificate and its chain; `Issuer` is `Name()` + `Issue()`.
- `Request.Validate()`, enforcing the security model in one place so it cannot diverge
  between backends: CSR proof-of-possession is verified, the SPIFFE ID and the AD SID are
  both validated, and anything malformed is refused rather than partially honoured.
- `internal/issuer/adcs` — backend stub for the ADCS enrollment-agent shape. Refuses with
  `ErrNotImplemented`.
- `internal/issuer/subordinate` — backend stub for the broker-controlled subordinate-CA
  shape. Refuses with `ErrNotImplemented`.
- `internal/mapping` and `internal/encoding`, copied from the predecessor repo
  (`spire-credentialcomposer-adpkinit`): the SPIFFE ID → AD SID snapshot contract with
  fail-closed lookup, SPIFFE ID and SID string validation, the MS-DTYP binary SID codec,
  and the CRL Distribution Point DER builder, all with their golden and fuzz tests.
- `docs/DESIGN.md` — the architecture, the three constraints that force it, why a
  CredentialComposer cannot get there, the two backends and their trade-offs, and seven
  open questions.
- `cmd/spiffe-ad-broker` — entrypoint. Exits non-zero rather than starting a server that
  would accept connections and do nothing useful with them.

### Security

- Caller identity is read from `tls.ConnectionState.VerifiedChains`, never
  `PeerCertificates`. Both are populated when a client presents a certificate; only the
  former requires that the chain verified against the trust bundle. A server accidentally
  configured below `RequireAndVerifyClientCert` therefore refuses rather than issuing AD
  credentials to anyone holding any certificate.
- Exactly one URI SAN is accepted, per the SPIFFE X.509-SVID specification. A caller able
  to influence which of several SANs is picked would be choosing its own AD account.
- The SPIFFE ID from the peer certificate is used verbatim — no lowercasing, trimming, or
  normalising. A tolerated spelling is a lookup that quietly misses a mapping a reviewer
  believed was in force.
- The mapping lookup runs *before* the CSR is parsed, so an unmapped caller never reaches
  the X.509 parser.
- The request body has no field for the caller's identity and none for the target
  account, and unknown JSON fields are rejected. A client that believes it can name
  either is refused rather than silently ignored.
- Refusals separate the caller-visible message from the logged detail, so backend hosts,
  file paths, and CA errors stay out of responses.
- The request body is bounded at 64 KiB, and the server sets read, write, header, and
  idle timeouts: this listener is reachable by every workload in the trust domain.
- A future-dated mapping snapshot refuses startup — it means a broken producer clock or a
  tampered artifact, and it makes any freshness bound meaningless. A merely stale one
  keeps serving, loudly, so a producer outage cannot become a fleet-wide issuance outage.
- The broker never generates or holds a workload's private key. The workload keeps it and
  proves possession through the CSR.
- Nothing in the CSR is trusted except the public key and its proof-of-possession
  signature. Subject, SANs, requested extensions and attributes are ignored entirely —
  honouring any of them would reintroduce workload-controlled identity.
- The AD SID is never derived from workload-reachable input. A certificate carrying a SID
  authenticates *as* that account, so a derived SID would be an account-takeover
  primitive.
- Backend validation runs before refusal, so an unimplemented backend cannot start
  issuing later without the shared guarantees already in force.

### Context

- This project supersedes `spire-credentialcomposer-adpkinit`. That repo's phase-4 lab
  established experimentally, against Windows Server 2025, that `NTAuthCertificates`
  requires the leaf's **direct issuing CA** — a root is neither necessary nor sufficient.
  A CredentialComposer therefore cannot close the gap: of the three constraints that
  bind, only one is certificate shape. The predecessor is parked, not deleted.
