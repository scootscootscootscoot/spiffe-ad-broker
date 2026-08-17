# Design

## The problem

A Linux workload holds a SPIFFE SVID. It needs to authenticate to Active Directory —
concretely, to obtain a Kerberos TGT via PKINIT, so it can reach AD-integrated services
as a real AD account.

The obvious approach is to make the SVID itself acceptable to AD: add the certificate
extensions the KDC wants and let SPIRE keep issuing. That was the predecessor project
(`spire-credentialcomposer-adpkinit`), and it does not work. Why not is the reason this
project has the shape it has.

## The three facts that bind

**1. `NTAuthCertificates` requires the leaf's *direct issuing* CA.**

Established experimentally, not from documentation — a seven-row matrix against Windows
Server 2025, both controls behaving. Full result:
`../../spire_credential_helper_plugin/docs/findings/2026-08-17-ntauth-requires-direct-issuer.md`.

A leaf authenticates *iff* its immediate issuer is published to NTAuth. Chaining to a
published root is not enough; the root is neither necessary nor sufficient. The decisive
row — a rotated issuer under an already-published root, which is exactly what a rotating
CA produces — fails.

**2. Anything in NTAuth is a forest-wide client-authentication authority.**

AD has no per-CA scoping. There is no way to say "this CA may only vouch for these
accounts." Name constraints do not help: they govern subject and SANs, not the SID
security extension the KDC actually maps on. So a certificate from any NTAuth CA,
carrying any SID, authenticates as that account.

The consequence is blunt: **whatever holds the key of an NTAuth CA can authenticate as
any account in the forest, including Domain Admin.** That is why the SID must never be
derived from workload-controlled input, and why the choice of what goes into NTAuth is
the single most consequential decision in this design.

**3. The KDC checks revocation by default.**

The lab only got rows passing after setting
`UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors=1` on the DC — which weakens revocation
checking for *all* certificate authentication on that DC, not just the certificates
under test. That is a lab expedient. It is not shippable, and no design should assume it.

## Why not a composer

A CredentialComposer changes certificate *attributes*. Of the three facts above, exactly
one — the SID extension — is certificate shape. The other two are not, and no composer
can reach them:

- Fact 1 means SPIRE's own CA would have to be in NTAuth, and republished on every CA
  rotation, at forest-configuration privilege, with issuance blocked until AD replication
  converges. SPIRE rotates on its own schedule and will not wait for AD.
- Fact 2 then makes the SPIRE server a forest-wide identity authority. Compromise of it
  is compromise of the forest.
- Fact 3 cannot be satisfied at all: the leaf's CDP must point at a CRL signed by the
  issuing CA's key. SPIRE issues no CRLs and does not expose that key, so there is
  nothing that can sign one.

The composer was the right thing to test and the wrong thing to build. It is parked, not
deleted — it holds the lab, the finding, and the encoding work that this project reuses.

## The shape that works

Do not make the SVID acceptable to AD. **Use the SVID to authenticate, and issue a
separate credential from something AD already trusts.**

```
workload ──SVID over mTLS──▶ broker ──▶ issuer backend ──▶ AD-auth certificate
                               │
                               └──▶ mapping snapshot (SPIFFE ID → AD SID)
```

The broker:

1. Authenticates the caller by its SVID, over mTLS. The SPIFFE ID comes from the
   verified peer certificate, never from the request body.
2. Resolves the target AD account from an authoritative mapping snapshot. A miss is a
   refusal — no default, no wildcard, no derivation from the SPIFFE ID path.
3. Asks an issuer backend for a certificate for that account, passing the workload's
   CSR.
4. Returns the certificate and chain. The workload's private key never leaves it.

Steps 1–2 and 4 are identical regardless of backend. Only step 3 differs, which is why
the two shapes are one codebase.

## The two backends

### `adcs` — enrollment agent (shape C)

The broker holds a Certificate Request Agent credential and asks ADCS to issue on behalf
of the target account.

This is the enterprise-native answer, and it is preferred, because the hard parts are
already solved by infrastructure that exists:

| Problem | How ADCS resolves it |
|---|---|
| Fact 1 — direct issuer in NTAuth | ADCS's issuing CA already is, and it is the immediate issuer |
| SID extension bytes | ADCS emits `szOID_NTDS_CA_SECURITY_EXT` natively — **no fixture needed** |
| Fact 3 — revocation | ADCS runs CDP/CRL infrastructure already |
| Authorization | Certificate templates, template ACLs, enrollment-agent restrictions |

Note what that second row means for the predecessor's blocker: the fixture problem was
"we need bytes from a real ADCS-issued certificate." Under this backend, ADCS *is* the
issuer. The blocker dissolves rather than being solved.

What this backend must get right is narrower and is all authorization. An enrollment
agent can request certificates for other accounts, so its credential is a high-value
target. Constraining it is a CA-side configuration job — enrollment agent restrictions,
template ACLs scoped to the accounts in the mapping — not something this code can do
alone.

### `subordinate` — broker-controlled CA (shape B)

The broker issues from a dedicated CA it controls, subordinate to the corporate PKI and
published to NTAuth in its own right.

Choose this when the issuance path must be owned rather than delegated. The trade is
explicit and worse:

- Both certificate-shape problems come back. This backend emits the SID extension
  itself, so it needs the exact encoding — which still must come from a real
  ADCS-issued certificate or an authoritative Microsoft vector, never from
  documentation. And it needs a CDP pointing at a CRL it signs and publishes.
- Both are *solvable* here, unlike under a SPIRE CA, because this backend holds its own
  key. That is the entire reason the shape exists.
- Fact 2 applies in full. The CA is forest-wide. Keeping it single-purpose, small, and
  narrowly scoped is not tidiness — it is the only bound on what its compromise can
  assert.

## Request handling

`internal/issuer.Request` carries the CSR, the caller's proven SPIFFE ID, and the mapped
SID. The security model is enforced there, once, so it cannot diverge between backends:

- The **CSR is workload-controlled**. Only the public key and the proof-of-possession
  signature are trusted. Subject, SANs, requested extensions and attributes are ignored
  entirely — a backend that copies any of them has reintroduced workload-controlled
  identity.
- Proof-of-possession is verified. Without it a caller could present a public key it
  does not hold, and the broker would mint an AD credential usable by whoever does.
- The **SID comes from the mapping and nowhere else.**
- Validation runs *before* the backend does anything, including before an unimplemented
  backend refuses — so the guarantees hold from the day a backend starts issuing.

## Transport

**HTTP over mutual TLS, standard library only.** One route:

```
POST /issue    {"csr": "<PEM>"}
  200  {"certificate": "<PEM>", "chain": ["<PEM>", ...], "backend": "adcs"}
  4xx/5xx  {"error": {"reason": "<token>", "message": "..."}}
```

gRPC was the alternative and it loses on the specifics. The service has exactly one
operation, with no streaming and nothing bidirectional, so gRPC's advantages do not
apply — while its cost is a protobuf and gRPC dependency tree inside a process whose
whole job is minting credentials that authenticate as AD accounts. This module has no
dependencies, and for *this* service that auditability is a security property rather
than minimalism for its own sake.

Nothing about the security model is traded away by the choice: gRPC transport
credentials wrap the same `crypto/tls` handshake, and the SPIFFE ID would come out of
the same verified peer certificate. And the decision is cheap to revisit — everything
above the wire lives in `internal/broker`, which knows nothing about HTTP, so a gRPC
transport would be a second thin adapter beside the first.

### The authentication

`SPIFFEIDFromPeer` reads **`VerifiedChains`, not `PeerCertificates`**. That distinction
is the entire authentication story. `PeerCertificates` is populated whether or not the
chain verified; `VerifiedChains` is populated only after verification against the
configured trust bundle succeeded. A server accidentally configured below
`RequireAndVerifyClientCert` would, reading the former, hand AD credentials to anyone
holding any certificate at all. Reading the latter turns that misconfiguration into a
refusal.

Two further rules: exactly one URI SAN is accepted, because the SPIFFE X.509-SVID
specification says an SVID carries exactly one and a caller that can influence which of
several is picked has chosen its own AD account; and the value is used **verbatim**,
with canonical-form checking left to `internal/mapping`, because a tolerated spelling is
a lookup that quietly misses a mapping a reviewer believed was in force.

### Order of operations

1. Extract the caller's SPIFFE ID from the verified peer certificate.
2. Re-check it is canonical.
3. Report snapshot staleness, if any — without refusing.
4. **Resolve the target AD account. A miss refuses.**
5. Only now parse the CSR.
6. Validate the assembled request.
7. Hand it to the backend.

Step 4 before step 5 is deliberate: an unmapped caller gets no certificate whatever it
sent, so it should never reach the X.509 parser at all.

### Refusal taxonomy

Every non-credential outcome carries a `broker.Reason` — a stable token a client branches
on, rather than prose it parses. A transport maps the reason to its own status
vocabulary; it does not invent categories.

| Reason | HTTP | Meaning |
|---|---|---|
| `unauthenticated` | 401 | No usable SPIFFE ID from a verified peer certificate |
| `invalid_request` | 400 | Malformed body, CSR, or failed proof-of-possession |
| `no_mapping` | 403 | Authenticated, but mapped to no account — the fail-closed default |
| `not_implemented` | 501 | The configured backend cannot issue yet |
| `internal` | 500 | Failed for a reason the caller cannot act on |

`no_mapping` is 403 rather than 404: the caller authenticated and was denied, which is
what 403 means. 404 would frame an authorization decision as a missing resource and
invite a retry as though the mapping might appear.

Each refusal is logged exactly once, where it is raised, with the caller and snapshot
version attached. The caller-visible `message` and the logged detail are separate
fields — that split matters most for `internal`, where the detail can name backend
hosts, file paths, or CA errors a workload has no business seeing.

### TLS material

`internal/tlsconf` loads the broker's own certificate, its key, and the trust bundle
from disk and reloads them when they change. This is not a convenience: the broker's own
certificate is an SVID with a lifetime in hours, and the trust bundle changes whenever
the trust domain's CA rotates. A process that read them once at startup would stop
accepting connections later, for reasons that look nothing like a certificate problem.

A failed reload keeps the last known good material and logs loudly — the same call as
the mapping snapshot's staleness policy, and for the same reason: a truncated file from
a rotation tool must not take issuance down. A reload that *succeeds* always takes
effect, so removing a CA from the bundle does de-trust it.

## Open questions

1. **Delivery.** Does the workload call the broker directly, or does something fetch on
   its behalf and place the credential where the workload expects it?
2. **Renewal.** AD-auth certificates will be much longer-lived than SVIDs. What drives
   renewal, and what happens when the mapping changes underneath an unexpired
   credential?
3. **Revocation on de-mapping.** Removing a mapping entry stops *future* issuance. It
   does nothing to a credential already issued. Something has to revoke.
4. **Enrollment-agent constraint model** (`adcs`). Which templates, scoped to which
   accounts, with which enrollment-agent restrictions. This is the backend's real
   security boundary and it lives on the CA, not here.
5. **Mapping producer.** Inherited unsolved from the predecessor: the broker reads a
   snapshot; something authoritative must write it. GitOps pipeline first, AD-attribute
   sync controller later.
6. **Does the workload need the TGT, or the service?** A TGT is not proof that
   downstream service authorization works. The lab proved PKINIT to a TGT and no further.
7. **Rate limiting and issuance records.** Every refusal and issuance is logged, but
   there is no per-caller rate limit and no durable record of what was issued to whom.
   Both matter before this is anything but a research build.

Resolved: **transport** (was question 1) — HTTP over mTLS, standard library only. See
the Transport section above.
