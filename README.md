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

## It is not a SPIRE plugin

SPIRE has no plugin type that issues a second, differently-shaped credential for a
workload — it mints X509-SVIDs and JWT-SVIDs, and that is the whole surface. This is a
standalone service beside SPIRE. In PKI terms it is a registration authority.

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
4. Return the certificate and chain. The workload's private key never leaves it.

Two backends, differing only in step 3:

- **`adcs`** — the broker acts as an ADCS enrollment agent and requests on behalf of the
  target account: the workload's CSR goes, unread, into a CMC naming that account, signed
  by the agent credential. Preferred, because ADCS is already in `NTAuthCertificates`,
  already emits the AD SID security extension, and already runs CRL infrastructure.
  Whatever comes back is checked against the SID the mapping asked for — a CA that
  ignores the requested account does not fail, it issues for the wrong one.
- **`subordinate`** — the broker issues from a dedicated CA it controls, subordinate to
  the corporate PKI. For when the issuance path must be owned rather than delegated.

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

## Predecessor

This supersedes `spire-credentialcomposer-adpkinit`, a SPIRE CredentialComposer that
shaped SVIDs directly. Its lab produced the result above, which is what redirected the
work here. That repo is parked, not deleted — it holds the lab, the finding, and the DER
encoding work reused here.

## Build

```
go build ./...
go vet ./...
go test ./...
```

## Licence

Apache-2.0.

Not affiliated with the SPIFFE project.
