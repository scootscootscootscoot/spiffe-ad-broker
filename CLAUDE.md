# CLAUDE.md — spiffe-ad-broker

## What this is

A service that exchanges a workload's **SPIFFE SVID** for a certificate **Active
Directory will accept for PKINIT**. The workload authenticates with the identity it
already has; the broker returns a credential AD will honour.

It is **not** a SPIRE plugin. SPIRE has no plugin type that issues a second,
differently-shaped credential for a workload — it mints X509-SVIDs and JWT-SVIDs and
that is the whole surface. This is a standalone service that sits beside SPIRE. In PKI
terms it is a **registration authority**; in the ADCS shape it is literally an
enrollment agent, which is Microsoft's own word for one.

Design, and the evidence that forced it: `docs/DESIGN.md`. Read it before proposing
scope changes — the shape of this project is a conclusion, not a preference.

Spare-time personal project, parallel to (not part of) the owner's day job.

## Origin — why this exists instead of the composer

Predecessor: `~/Desktop/spire_credential_helper_plugin`
(`spire-credentialcomposer-adpkinit`), a SPIRE CredentialComposer that shaped SVIDs to
pass PKINIT. Its phase-4 lab answered the open question that decided the approach:

> **`NTAuthCertificates` requires the leaf's direct issuing CA.** A root is neither
> necessary nor sufficient.

Seven-row matrix, both controls behaving. Full result:
`~/Desktop/spire_credential_helper_plugin/docs/findings/2026-08-17-ntauth-requires-direct-issuer.md`.

The consequence is that a composer cannot get there. Of the three constraints that bind,
exactly one is certificate shape; the other two — NTAuth membership at a rotating issuer,
and revocation infrastructure — are outside any composer's reach. The composer repo is
**parked, not deleted**: it holds the lab, the finding, and the encoding work.

## Hard rules (do not relax without explicit owner decision)

**Security invariants:**
- **Fail closed.** No mapping entry, malformed SID, SPIFFE ID outside the allowed
  namespace, failed proof-of-possession, or unavailable backend ⇒ refuse, with a
  structured error. Never a partially issued or best-effort credential.
- **Never derive an AD SID from workload-controlled input.** Not from the SPIFFE ID
  path, not from the CSR, not from anything the caller reaches. A certificate carrying a
  SID authenticates *as that account*, so a derived SID is an account-takeover
  primitive. The mapping is authoritative data, full stop.
- **Nothing in the CSR is trusted except the public key and its proof-of-possession
  signature.** Subject, SANs, requested extensions and attributes are ignored entirely.
  Copying any of them into the issued certificate reintroduces workload-controlled
  identity.
- **The broker never generates or holds a workload's private key.** The workload keeps
  it and proves possession through the CSR.
- **The caller's SPIFFE ID comes from the verified mTLS peer certificate**, never from
  the request body.
- **No inferred encodings.** The AD SID extension's bytes must come from a real
  ADCS-issued certificate or an authoritative Microsoft vector, pinned by a golden test.
  Never from documentation, never from the OID. (Only the `subordinate` backend needs
  this; `adcs` gets it from ADCS.)
- **Treat any CA this broker relies on as forest-wide.** A CA in NTAuth is a
  forest-wide client-authentication authority; AD has no per-CA account scoping, and
  name constraints do not govern the SID extension. Keeping an issuing CA
  single-purpose and small is the only thing bounding a compromise.

**Repo hygiene (pre-public checklist lives here):**
- Repo is **private until the owner completes an employment-IP review**. Do not make it
  public, and do not push content anywhere else.
- No work artifacts: no internal doc names/paths/links, no employer name, no real AD
  exports, SIDs from real forests, production certs, or private keys. Fixtures are
  synthetic or sanitized.
- Commits: sign-off habit (`git commit -s`, DCO style).
- Apache-2.0, carried over from the predecessor along with the copied packages.

## Layout

```
cmd/spiffe-ad-broker/        entrypoint: flags, wiring, graceful shutdown
internal/broker/             the authenticate-and-map path + refusal taxonomy;
                             transport-independent, so the transport stays swappable
internal/transport/httpapi/  HTTP over mTLS: POST /issue, peer-cert identity extraction
internal/tlsconf/            mTLS config from files, reloaded when the SVID or bundle rotates
internal/issuer/             the backend contract — Request, Credential, Issuer
internal/issuer/adcs/        shape C: enrollment agent against ADCS
internal/issuer/subordinate/ shape B: broker-controlled subordinate CA
internal/mapping/            SPIFFE ID → AD SID snapshot contract + validation
internal/encoding/           DER builders (CDP, AD SID ext) + golden/fuzz tests
docs/DESIGN.md               the architecture and the evidence behind it
```

Nothing under `internal/broker` may import a transport package, and nothing in a
transport may re-implement a check the broker makes. That boundary is what keeps the
security properties testable without standing up a server.

`internal/mapping` and `internal/encoding` were **copied** from the composer repo, by
owner decision, over extracting a shared module. They will drift; that was the accepted
trade for moving fast. If they start mattering in both places, extract then.

## Decisions log

| Date | Decision |
|---|---|
| 2026-08-17 | `NTAuthCertificates` requires the direct issuing CA (seven-row lab matrix). A composer cannot close the gap; two of three binding constraints sit outside it. Predecessor parked. |
| 2026-08-17 | Build the broker instead. One codebase, two issuance backends behind one interface — B (own subordinate CA) and C (ADCS enrollment agent) differ only in where the certificate comes from. |
| 2026-08-17 | Named `spiffe-ad-broker`. New repo; `internal/mapping` and `internal/encoding` copied rather than extracted into a shared module. |
| 2026-08-17 | Workload generates its own key and sends a CSR. The broker never handles workload private keys, and trusts nothing in the CSR but the public key and its PoP signature. |
| 2026-08-17 | **Transport: HTTP over mTLS, standard library only.** One operation, no streaming, so gRPC buys nothing here and costs a protobuf/gRPC dependency tree inside a credential-minting process — the module's zero dependencies are an auditability property, not minimalism. Authentication is identical either way (gRPC credentials wrap the same `crypto/tls` handshake). Reversible by construction: `internal/broker` knows nothing about HTTP, so a gRPC transport would be a second thin adapter, not a rewrite. |
| 2026-08-17 | **Refusals are classified, not stringly-typed.** `broker.Reason` is the taxonomy; a transport maps it to its own status vocabulary. Adding a failure mode means choosing a Reason for it — a refusal nobody classified is a refusal nobody thought about. |
| 2026-08-17 | **Refusals are logged once, where they are raised.** `Broker.Issue` logs with caller and snapshot version attached; transports translate and must not re-report. |
| 2026-08-17 | **TLS material reloads from disk; a failed reload keeps last-known-good.** Same call as the mapping snapshot's staleness policy: a half-written file from a rotation tool must not take issuance down. A *successful* reload always takes effect, so de-trusting a CA still works. |

## Verify

```
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

All must pass before any commit.
