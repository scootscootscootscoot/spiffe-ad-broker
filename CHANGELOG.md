# Changelog

Notable changes to `spiffe-ad-broker`. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once there is anything to
release. Nothing has been released yet, so everything sits under Unreleased.

## [Unreleased]

### Added

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
