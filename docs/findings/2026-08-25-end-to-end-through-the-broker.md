# The broker issues, end to end, through the server binary

**Date:** 2026-08-25
**Lab:** `pkinit-dc01`, Windows Server 2025 `10.0.26100`, ADCS Enterprise Root CA
`PKINIT Lab Issuing CA`, CES with certificate authentication.

Until now the `adcs` backend had been proven by building its CMC and submitting it to
the CA directly. That left the question the previous session recorded as open: does the
*whole service* work — a workload authenticating over mutual TLS with its SVID, and
getting back a certificate Active Directory will honour for the account it is mapped to.

It does.

## The result

```
POST /issue   (mTLS, SVID spiffe://pkinitlab.internal/workload/db)
  -> HTTP 200, backend "adcs", chain length 1
```

The certificate that came back:

| Property | Value |
|---|---|
| Subject | `CN=PKINIT Test User, CN=Users, DC=pkinitlab, DC=internal` |
| SAN | `UPN:pkinittest@pkinitlab.internal` |
| EKU | Microsoft Smartcard Logon, TLS Web Client Authentication |
| AD SID extension | `S-1-5-21-…-1103` — the SID the mapping asked for |
| Issuer | `CN=PKINIT Lab Issuing CA` (in NTAuth, and the leaf's *direct* issuer) |
| CA request | 30 |

**The subject is the target account, not the caller's.** The broker authenticated to CES
as `labadm` and signed the request as an enrollment agent whose own certificate is also
`labadm` — and the certificate that came back is for `pkinittest`. That is the whole
enrol-on-behalf-of shape working through the service rather than by hand.

**The workload's key never left the workload.** The leaf's public key, the CSR's public
key, and `target.key`'s public key are byte-identical
(`sha256 091548ee…adf9`). The broker only ever saw the PKCS#10.

## The security guard, exercised

The property that matters most under this backend is not the happy path. It is that a CA
which does not honour the requester name **does not refuse** — it issues a valid,
correctly chained certificate for the caller's own account. So every response is read
back and checked against the SID the mapping asked for.

Forcing that check to fire, by pointing the snapshot at the right account with a
deliberately wrong SID:

```
POST /issue  -> HTTP 500 {"reason":"internal","message":"issuance failed"}
```

and in the log, the detail the caller never sees:

```
adcs: issued certificate names S-1-5-21-…-1103, but the mapping for
spiffe://pkinitlab.internal/workload/db says S-1-5-21-…-1199
— the requester name was not honoured
```

The CA's own view confirms what this costs and why the check is not optional:

| Request | Template | Disposition |
|---|---|---|
| 28 | `EnrollmentAgent` | Issued — the agent credential |
| 29 | `User` | Issued — the CES client credential |
| 30 | `WorkloadPKINIT` | Issued — **delivered** |
| 31 | `WorkloadPKINIT` | Issued — **refused by the broker, never delivered** |

Request 31 exists at the CA. Nothing could have prevented that: by the time the SID is
readable the certificate has already been issued. What the check prevents is *delivery*,
which is what makes it inert — the workload holds the private key but never learned the
certificate. This is the same asymmetry the issuance record relies on, and it is the
honest limit of the guard: it cannot un-issue, only refuse to hand over.

**Lab hygiene:** request 31 should be revoked. It was left in place rather than revoked
unilaterally, since revocation is irreversible:

```powershell
certutil -config 'dc01.pkinitlab.internal\PKINIT Lab Issuing CA' -revoke 31
```

## The two AD-facing credentials are genuinely not interchangeable

Previously reasoned about; now observed. Both were minted from the same CA, for the same
AD account, in the same session:

| Credential | Template | EKU |
|---|---|---|
| Enrollment agent | `EnrollmentAgent` | `1.3.6.1.4.1.311.20.2.1` (Certificate Request Agent) — **and nothing else** |
| CES client | `User` | EFS, Secure Email, **TLS Web Client Authentication** |

The agent certificate carries no Client Authentication, so it cannot authenticate the
TLS connection to a CES endpoint configured for certificate auth. Two certificates, or
the backend does not start.

## What the record captured

```json
{
  "caller": "spiffe://pkinitlab.internal/workload/db",
  "backend": "adcs",
  "snapshot_version": "e2e-2026-08-25-1",
  "ad_sid": "S-1-5-21-…-1103",
  "ad_account": "PKINITLAB\\pkinittest",
  "serial": "2096270048817883677101023734520334430022664222",
  "issuer": "CN=PKINIT Lab Issuing CA,…",
  "not_after": "2027-08-25T23:13:08Z",
  "fingerprint": "9d05735d…52bac"
}
```

One line, for the one credential delivered. The 403 from an unmapped caller and the 500
from the SID mismatch added nothing — refusals are not recorded, by design.

Note the validity window: **one year**, against an SVID measured in hours. That is
decision 5 (renewal) stated in real numbers rather than in the abstract.

## Rate limiting, against the real listener

With `-burst-per-caller 2` and a refill rate low enough to be irrelevant:

| Request | Result |
|---|---|
| `workload/db` 1st, 2nd | served |
| `workload/db` 3rd | `429 rate_limited`, `Retry-After: 10000` |
| `workload/nobody` | `403 no_mapping` — its own bucket, untouched |

Four decisions, four log lines, each carrying caller and snapshot version, each logged
exactly once.

## Reproducing it

Material is staged in `~/vms/broker-e2e/` (outside the repo — it holds private keys and
lab SIDs). The one host change needed: `dc01.pkinitlab.internal` must resolve, since the
CES server certificate is issued for that name and Go's resolver reads `/etc/hosts`.

```
192.168.122.10 dc01.pkinitlab.internal dc01
```

`DC01$` cannot enrol the `EnrollmentAgent` template — request 27 came back
`CERTSRV_E_TEMPLATE_DENIED`. Minting the agent credential needs `labadm`, via the
scheduled-task route in `docs/CONTEXT.md`. **Do not "fix" this by widening the template
ACL**: that is the exact change the enrollment-agent constraint model exists to measure.
