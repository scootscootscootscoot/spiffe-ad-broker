# Enrol on behalf of: the requester name must be inside the signature, and the result must be checked

**Date:** 2026-08-24
**Lab:** phase-4, `pkinitlab.internal`, Windows Server 2025 build 10.0.26100
**Decides:** the `adcs` backend's issuance path — next action 3 in the previous
session's resume notes ("enrol on behalf of another account")

## Question

The transport was already proven: a stdlib-only Go client submits a PKCS#10 to
a live CES endpoint over MS-WSTEP and gets a certificate back
([finding](2026-08-17-wstep-request-body.md)). But it enrols the broker **as
itself**. The broker's whole purpose is to obtain a credential for the *mapped*
account, which means enrolling on behalf of another account, and that is where
the security boundary actually is.

Two things were open. How is the target account named in the request? And can
the broker — which never holds the workload's private key — produce a request
ADCS will accept?

## Answer, in one line

The requester name travels in the CMC `regInfo` control, inside the enrollment
agent's signature; ADCS accepts a CMC signed **only** by the agent; and a
requester name that is not honoured does not fail — it issues for the wrong
account.

## 1. Passing the name unsigned is accepted, ignored, and silent

The obvious reading of `certreq`'s documentation is that a request attribute
carries it:

```
certreq -submit -config <CA> -attrib "RequesterName:PKINITLAB\pkinittest" eobo.req issued.cer
```

That command **succeeds**. `RequestId: 14`, `Certificate retrieved(Issued)`,
exit code 0. The certificate it returns is for `CN=labadm` — the enrolling
account — carrying `…-1104`, the agent's own SID. The requested account,
`pkinittest` (`…-1103`), appears nowhere.

Nothing in the exchange reports a problem. A broker that trusted this path
would hand a workload a valid, correctly chained certificate that authenticates
as **the broker's own AD account**, and would log it as a success.

This is the reason `Issue` reads the SID back out of every issued certificate
and refuses on a mismatch. Delegating issuance is not delegating the security
decision.

## 2. Where the name actually goes

Signed, in the CMC `regInfo` control (`id-cmc-regInfo`, `1.3.6.1.5.5.7.7.18`),
alongside the template:

```
certreq -policy -cert <agent thumbprint> -attrib "RequesterName:PKINITLAB\pkinittest" \
        target.req policy.inf eobo.req
```

The payload is a single `OCTET STRING`:

```
CertificateTemplate=WorkloadPKINIT&RequesterName=PKINITLAB%5Cpkinittest&
```

Ampersand-separated `name=value` pairs, **terminated** with `&`, and the domain
separator **percent-encoded as `%5C`** rather than written as a backslash. That
escaping could not have been derived; it was read off the capture.

Two spellings that do *not* work, tried first: `RequesterName` under a
`[pkcs7]` section of the policy file (silently unused — `certreq` reports
`Unreferenced INF sections`), and under `[RequestAttributes]` (rejected outright
with `The data is invalid. 0x8007000d`).

The whole request is:

```
ContentInfo { pkcs7-signedData }
└── SignedData, eContentType = id-cct-PKIData (1.3.6.1.5.5.7.12.2)
    └── PKIData
        ├── controlSequence
        │   ├── [2] id-cmc-addExtensions  → szOID_ENROLLMENT_CERT_TYPE, BMPString "WorkloadPKINIT"
        │   └── [3] id-cmc-regInfo        → the name=value string above
        ├── reqSequence
        │   └── [0] TaggedCertificationRequest { 1, <the workload's PKCS#10, verbatim> }
        ├── cmsSequence      (empty)
        └── otherMsgSequence (empty)
```

`internal/issuer/adcs/cmc.go` builds exactly this, and
`TestPKIDataMatchesTheWindowsClientByteForByte` holds it to the captured
bytes — the body is fully deterministic, so the pin is exact rather than
structural.

## 3. One signature is enough — which is what makes the design work

`certreq` produces a CMC with **two** signers: the enrollment agent, and the
request's own key. The broker can only ever produce the first, because the
workload keeps its private key and the broker never sees it. If ADCS required
the second, the whole shape would be dead.

It does not. A CMC carrying one `SignerInfo` — the agent's, over SHA-256, where
`certreq` uses SHA-1 — was built by `internal/issuer/adcs/cmc.go`, submitted to
the live CA, and issued:

```
Signer Count: 1
RequestId: 17   Certificate retrieved(Issued) Issued
Subject: CN=PKINIT Test User, CN=Users, DC=pkinitlab, DC=internal
         Principal Name=pkinittest@pkinitlab.internal
         1.3.6.1.4.1.311.25.2 → S-1-5-21-3734714977-4168152908-3762407930-1103
```

The account is the target's, the key is the workload's, and the broker never
held either.

## 4. On the CES wire, a CMC is tagged `#PKCS7`

Captured the same way the RST body was, and for the same reason — it is not
derivable. Pointing `certreq` at a recording endpoint holding a CA-issued TLS
certificate, with the CMC as input, produces:

```
<BinarySecurityToken
  ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7"
  EncodingType="…secext-1.0.xsd#base64binary">
```

That is the *same* `#PKCS7` value ADCS uses to tag the chain it returns — not
an `…/enrollment#CMC` spelling under the Microsoft namespace, which is the
obvious guess. The `EncodingType` is the same non-standard one as before.

The other difference: **there is no `CertificateTemplate` context item.** The
PKCS#10 form names the template in an `AdditionalContext` element; the CMC form
does not, because the template is named inside the signed request. The broker
follows the capture and sends no `AdditionalContext` at all — naming the
template outside as well would put the same decision somewhere the agent's
signature does not cover.

## What this makes true

`internal/issuer/adcs` issues. The path is: wrap the workload's PKCS#10,
unread, in a CMC naming the mapped account and signed by the enrollment agent;
POST it to CES; parse the response; and refuse unless the certificate that
comes back carries the SID the mapping asked for and a chain to its immediate
issuer.

## Consequences worth carrying

- **The mapping needs the account *name*, not only the SID.** An enrollment
  agent names its target by `DOMAIN\samAccountName`; the SID is what comes
  back, not what goes out. Resolving one to the other would put a directory
  lookup on the issuance path and move the decision out of the authoritative
  snapshot, so the snapshot carries both. `mapping.Entry.ADAccount`, optional
  because `subordinate` never needs it, and the `adcs` backend refuses without
  it.

- **The broker needs two AD-facing credentials, and they are not
  interchangeable.** The enrollment agent certificate carries the Certificate
  Request Agent application policy and *not* Client Authentication, so it
  cannot authenticate the TLS connection to a CES endpoint configured for
  certificate authentication. That needs a second certificate mapping to an AD
  account — which means the broker has an AD identity of its own.

- **The name's character set is pinned narrowly.** Only the backslash's
  escaping was established, so `mapping.ValidateAccountName` and the CMC
  builder both refuse anything outside `[A-Za-z0-9._$-]` plus one separator.
  `&`, `=` and `%` are refused specifically: unescaped, each could restate the
  authorization inside the `regInfo` string.

- **The lab now has an enrol-on-behalf-of configuration.** Template
  `WorkloadPKINIT` (schema 2, `msPKI-RA-Signature = 1`,
  `msPKI-RA-Application-Policies = 1.3.6.1.4.1.311.20.2.1`, subject built from
  AD), the `EnrollmentAgent` template published, and an agent certificate whose
  key is held outside the guest.

## Method note

The capture rig is the one from the previous session and it worked again
unchanged: stop trying to observe the real service, and make a real client talk
to something already under observation. A cross-compiled Go recorder
(`GOOS=windows`), a TLS certificate issued by the lab CA for a name that
already resolves, and `certreq -submit -config https://…:8443/service.svc/CES`.
Using the existing `dc01` name on a spare port avoided touching DNS at all, and
Windows does not firewall a connection from a host to its own address, so no
firewall rule was needed either. The rig — binary, certificate, private key —
was removed afterwards.
