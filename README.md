# spiffe-ad-broker

Exchange a workload's **SPIFFE SVID** for a certificate **Active Directory will accept
for PKINIT**.

A Linux workload already has a SPIFFE identity. This service lets it use that identity to
obtain an AD-usable credential, so it can get a Kerberos TGT and reach AD-integrated
services as a real AD account — without the workload holding a long-lived AD secret, and
without a per-issuance `altSecurityIdentities` write.

> **Status: early, but it issues.** The `adcs` backend obtains a real certificate for the
> mapped AD account from a live ADCS CA, and refuses anything that comes back naming a
> different account. Proven end to end **through the server binary** against Windows
> Server 2025 — a workload authenticating with its SVID over mutual TLS gets back a
> certificate carrying the target account's UPN and AD SID, bound to a key the broker
> never saw. The refusal path was exercised too, not just the happy one.
> `subordinate` is still a stub that refuses. Nothing here has been run outside a lab.

**No dependencies.** The module imports nothing outside the Go standard library, and CI
fails if that changes. For a process whose whole job is minting credentials that
authenticate as Active Directory accounts, that is a security property rather than
minimalism for its own sake.

## It is not a SPIRE plugin

SPIRE has no plugin type that issues a second, differently-shaped credential for a
workload — it mints X509-SVIDs and JWT-SVIDs, and that is the whole surface. This is a
standalone service beside SPIRE. In PKI terms it is a registration authority; in the ADCS
shape it is literally an enrollment agent, which is Microsoft's own word for one.

## How it works

```
workload ──SVID over mTLS──▶ broker ──▶ issuer backend ──▶ AD-auth certificate
                               │
                               └──▶ mapping snapshot (SPIFFE ID → AD account)
```

1. Authenticate the caller by its SVID. The SPIFFE ID comes from the verified peer
   certificate, never from the request body.
2. Resolve the target AD account from an authoritative mapping snapshot. A miss refuses
   — no default, no wildcard, no derivation from the SPIFFE ID path.
3. Ask an issuer backend for a certificate for that account, passing the workload's CSR.
4. Record the credential durably, then return it with its chain. The workload's private
   key never leaves it.

Two backends, differing only in step 3:

- **`adcs`** — the broker acts as an ADCS enrollment agent and requests on behalf of the
  target account: the workload's CSR goes, unread, into a CMC naming that account, signed
  by the agent credential. Preferred, because ADCS is already in `NTAuthCertificates`,
  already emits the AD SID security extension, and already runs CRL infrastructure.
  Whatever comes back is checked against the SID the mapping asked for — a CA that
  ignores the requested account does not fail, it issues for the wrong one.
- **`subordinate`** — the broker issues from a dedicated CA it controls, subordinate to
  the corporate PKI. For when the issuance path must be owned rather than delegated.

## Run it

The mapping snapshot is the authorization decision, so it is a required input with no
default:

```json
{
  "version": "2026-08-25-1",
  "generated_at": "2026-08-25T22:00:00Z",
  "entries": [
    {
      "spiffe_id": "spiffe://example.org/workload/db",
      "ad_sid": "S-1-5-21-1111111111-2222222222-3333333333-1105",
      "ad_account": "EXAMPLE\\svc-db"
    }
  ]
}
```

```
spiffe-ad-broker \
  -listen :8443 \
  -tls-cert /run/spire/svid.pem -tls-key /run/spire/svid.key \
  -trust-bundle /run/spire/bundle.pem \
  -mapping /etc/spiffe-ad-broker/mapping.json \
  -issuance-record /var/lib/spiffe-ad-broker/issued.jsonl \
  -backend adcs \
  -adcs-ces-url 'https://ca.example.com/Example%20CA_CES_Certificate/service.svc/CES' \
  -adcs-template WorkloadPKINIT \
  -adcs-agent-cert agent.pem  -adcs-agent-key agent.key \
  -adcs-client-cert ces.pem   -adcs-client-key ces.key \
  -adcs-ca-bundle ad-ca.pem
```

The `adcs` backend needs **two** AD-facing credentials and they are not interchangeable:
the enrollment agent certificate carries the Certificate Request Agent application policy
and *not* Client Authentication, so it cannot also authenticate the TLS connection to a
CES endpoint configured for certificate auth.

One route, over mutual TLS:

```
POST /issue   {"csr": "<PEM>"}  →  {"certificate": "<PEM>", "chain": [...], "backend": "adcs"}
```

There is deliberately no field for the caller's identity and none for the target account:
the identity comes from the verified peer certificate and the account comes from the
snapshot, so a field for either would be an invitation to trust the wrong source.

## What it refuses

Every refusal is `{"error": {"reason": ..., "message": ...}}` with a stable token, so a
client branches on `reason` rather than parsing prose.

| Status | `reason` | Meaning |
|---|---|---|
| 401 | `unauthenticated` | No usable SPIFFE ID from a *verified* peer certificate |
| 400 | `invalid_request` | Malformed body or CSR, or failed proof-of-possession |
| 403 | `no_mapping` | Authenticated, but mapped to no account — the fail-closed default |
| 429 | `rate_limited` | Too many requests, or the broker is at its cap on the CA |
| 501 | `not_implemented` | The configured backend cannot issue yet |
| 500 | `internal` | Failed for a reason the caller cannot act on |

Two bounds apply to every request: a per-caller rate limit, taken before the CSR is
parsed because it bounds the CPU one workload can spend on proof-of-possession, and a
global one taken immediately before the backend call because what it protects is a CA the
rest of the forest also depends on. `rate_limited` is the only refusal carrying
`Retry-After`, computed from the limiter rather than guessed — every other refusal is a
decision that waiting will not change.

Every issued credential is appended to `-issuance-record` before it is returned. **A
credential that cannot be recorded is not handed over**, because nobody could revoke it:
the certificate exists at the CA either way, but undelivered it is inert, since the
workload never learned it.

## Why this shape

Making the SVID itself acceptable to AD does not work. Three constraints bind, and only
one of them is certificate shape:

1. **`NTAuthCertificates` requires the leaf's direct issuing CA** — established
   experimentally against Windows Server 2025, not from documentation. Chaining to a
   published root is not enough, so a rotating CA breaks authentication on every
   rotation.
2. **Anything in NTAuth is a forest-wide client-authentication authority.** AD has no
   per-CA account scoping, and name constraints do not govern the SID extension.
3. **The KDC checks revocation by default**, and a CA that cannot sign a CRL cannot
   satisfy it.

Full reasoning and the evidence: [`docs/DESIGN.md`](docs/DESIGN.md).

## Evidence

Nothing here was inferred from documentation. Each of these is a lab result, with the
bytes pinned by golden tests:

- [The AD SID extension's encoding](docs/findings/2026-08-17-ad-sid-extension-encoding.md)
  — the SID travels as its textual `S-1-…` string, not the MS-DTYP binary layout. The
  guess would have been wrong, and wrong here means a well-formed certificate naming the
  wrong account.
- [The ADCS request path](docs/findings/2026-08-17-adcs-request-path.md) and
  [the MS-WSTEP request body](docs/findings/2026-08-17-wstep-request-body.md) — captured
  from Microsoft's own client, because every documented spelling of one constant is
  refused by the server.
- [Enrol on behalf of the mapped account](docs/findings/2026-08-24-enroll-on-behalf-of.md)
  — the requester name must sit *inside* the enrollment agent's signature. Passing it
  unsigned is accepted, ignored, and silent: you get a valid certificate for the caller's
  own account.
- [End to end through the server binary](docs/findings/2026-08-25-end-to-end-through-the-broker.md)
  — and the read-back guard forced to fire, with the CA's own log showing why it cannot
  be optional.

## Predecessor

This supersedes
[`spire-credentialcomposer-adpkinit`](https://github.com/scootscootscootscoot/spire-credentialcomposer-adpkinit),
a SPIRE CredentialComposer that shaped SVIDs directly. Its lab produced the result above,
which is what redirected the work here. That repo is parked, not deleted — it holds the
lab, the finding, and the DER encoding work reused here.

## Build

```
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

CI additionally runs the race detector, a fuzz smoke run over every target, govulncheck,
and a check that the module still has no dependencies.

## Licence

Apache-2.0.

Not affiliated with the SPIFFE project.
