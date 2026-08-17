# Changelog

Notable changes to `spiffe-ad-broker`. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once there is anything to
release. Nothing has been released yet, so everything sits under Unreleased.

## [Unreleased]

### Added

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
