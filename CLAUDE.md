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
- **Verify what an external CA returns; never assume it honoured the request.** Under
  the `adcs` backend the target account is *asked for*, by name, inside the enrollment
  agent's signature. When the CA does not honour that ask — wrong agent rights, wrong
  template, misencoded name — it does not refuse: it issues a valid, correctly chained
  certificate for the *caller's own* account. Every issued certificate is read back and
  refused unless its AD SID extension names the SID the mapping asked for.
- **Treat any CA this broker relies on as forest-wide.** A CA in NTAuth is a
  forest-wide client-authentication authority; AD has no per-CA account scoping, and
  name constraints do not govern the SID extension. Keeping an issuing CA
  single-purpose and small is the only thing bounding a compromise.

**Repo hygiene:**
- Repo is **public** as of 2026-08-25, after the employment-IP review completed. The
  rules below are therefore no longer a pre-publication checklist — they are live
  constraints on every commit, and a mistake is immediately public.
- No work artifacts: no internal doc names/paths/links, no employer name, no real AD
  exports, SIDs from real forests, production certs, or private keys. Fixtures are
  synthetic or sanitized.
- The lab forest's SIDs (`pkinitlab.internal`, `…-1103`/`…-1104`) **are** in the tree, in
  tests, fixtures and findings. That is deliberate and allowed: the forest is synthetic
  and disposable. They also cannot be scrubbed without destroying the point of the golden
  tests, which pin real ADCS bytes — changing the SID would mean re-capturing every
  fixture.
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
internal/ratelimit/          token buckets: per caller, and global (the CA's budget)
internal/record/             durable append-only account of every credential issued
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
| 2026-08-24 | **The `adcs` backend issues, by CMC enrol-on-behalf-of.** The workload's PKCS#10 goes verbatim into a CMC naming the mapped account in the `regInfo` control, signed by an enrollment agent credential. ADCS accepts a CMC signed by the agent alone, which is what makes the shape possible at all — the broker never holds the workload's key and so can never produce the second signature `certreq` adds. Pinned byte for byte to a capture. |
| 2026-08-24 | **The mapping snapshot carries the account *name* as well as the SID** (`ad_account`, optional). An enrollment agent names its target by `DOMAIN\samAccountName`; the SID is what comes back. Resolving one to the other would put a directory lookup on the issuance path and move the decision out of the authoritative snapshot, so both come from the snapshot and neither is derived. `subordinate` needs only the SID; `adcs` refuses without the name. |
| 2026-08-24 | **The account name's character set is pinned narrowly** — `[A-Za-z0-9._$-]` plus one separator — in both `internal/mapping` and the CMC builder. Only the backslash's escaping (`%5C`) was established by capture; `&`, `=` and `%` are refused because unescaped each could restate the authorization inside the `regInfo` string. Widening it means establishing an escaping, not assuming one. |
| 2026-08-25 | **Repository made public**, employment-IP review complete. Published after a full-history scan across all commits: no private keys, no credentials, no home paths, no workstation hostname — in the tree or in any blob. The synthetic lab forest's SIDs stay, deliberately; see the hygiene rules. No history rewrite was needed, unlike the predecessor, because nothing sensitive ever landed on `master` — the one Claude Code session checkpoint carrying a working-tree snapshot lives in `refs/claude/`, was verified clean, and is not an ancestor of `master`. |
| 2026-08-25 | **Two rate limits, taken at different points, because they protect different things.** Per caller, before the CSR is parsed, bounding the CPU one workload can spend on proof-of-possession. Globally, immediately before the backend call, bounding this broker's aggregate draw on a CA the rest of the forest depends on — so a request refused for any other reason, having never reached the CA, does not spend the budget for reaching it. Token buckets, so a fleet restarting together still gets through. Hand-written rather than `golang.org/x/time/rate`: the module's zero dependencies are an auditability property of a credential-minting process. |
| 2026-08-25 | **Every issued credential is durably recorded before it is returned, and one that cannot be recorded is not returned.** Logs rotate and go with the container; revocation needs an issuer and serial, and the CA is not a searchable index of what this broker asked for. By the time recording fails the certificate exists and that cannot be undone — but returned it is in circulation and unrevocable, whereas refused it was never delivered and the workload never learned it, which leaves it inert. The log names the serial so an operator can revoke it by hand. **Refusals are not recorded**: the record answers "what exists", and a durable line per refused request turns a refused flood into disk exhaustion. |
| 2026-08-24 | **The `adcs` backend needs two AD-facing credentials and they are not interchangeable.** The enrollment agent certificate carries the Certificate Request Agent application policy and not Client Authentication, so it cannot authenticate the TLS connection to a CES endpoint configured for certificate auth. That is a second certificate, mapping to an AD account — the broker has an AD identity of its own. |

## Verify

```
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

All must pass before any commit.
