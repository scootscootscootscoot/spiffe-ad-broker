# The MS-WSTEP request body: the EncodingType is not the documented one

**Date:** 2026-08-17
**Lab:** phase-4, `pkinitlab.internal`, Windows Server 2025 build 10.0.26100
**Decides:** next action 1 for `internal/issuer/adcs` ("capture a real MS-WSTEP
`RequestSecurityToken` from a Windows client")

## Question

The request path was already settled — CES over HTTPS with client-certificate
auth ([the previous finding](2026-08-17-adcs-request-path.md)). What remained
was the request *body*. A hand-built `RequestSecurityToken` carrying a PKCS#10
was refused by ADCS with:

```
The EncodingType is invalid.
```

for **every** documented `ValueType`/`EncodingType` combination — six sweeps,
identical response each time. The payload was verified well-formed and
correctly substituted, so ADCS was genuinely rejecting it.

Per this project's own rule, the wire format had to come from a real vector,
not from documentation. This is that capture.

## Answer

The `EncodingType` Microsoft's own client sends is:

```
http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary
```

That is the **secext schema URI** — the same namespace as the
`BinarySecurityToken` element itself — with a lowercase `#base64binary`
fragment. WS-Security defines the value as

```
http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary
```

which is a different namespace *and* different capitalisation, and which ADCS
rejects. No amount of sweeping the documented spellings would have found it;
the working value is not among them.

The `ValueType`, by contrast, is exactly as documented:
`http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10`.

With only the `EncodingType` corrected, the stdlib-only Go client submits a
PKCS#10 to the live CES endpoint and gets back an issued certificate:

```
http=200 bytes=9340
token[1]: CERT subject="CN=labadm,DC=pkinitlab,DC=internal"
                issuer="CN=PKINIT Lab Issuing CA,DC=pkinitlab,DC=internal"
          AD SID ext present (66 bytes)
```

The whole `adcs` transport is therefore proven end to end, from a Go process
with zero dependencies.

## How it was captured

Two approaches had already failed and are recorded so they are not retried:

1. **PSRemoting to `localhost`** running `Get-Certificate` — classic double
   hop. The remote session holds no client certificate, so CES answers
   `WS_E_ENDPOINT_ACCESS_DENIED (0x803d0005)`.
2. **WCF message logging** in the CES `web.config` — trace files were created
   but stayed 0 bytes, despite correct ACLs.

What worked was to stop trying to observe the real service and instead **make
a real client talk to something already under observation**:

- Issue a TLS certificate from the lab's own ADCS CA for a name we control
  (`recorder.pkinitlab.internal`), and add the matching DNS A record.
- Run a small recording endpoint on that name that answers like a CES service
  and logs the full request.
- Point Microsoft's client straight at it:
  `certreq -submit -config https://recorder.pkinitlab.internal:8443/service.svc/CES …`

`certreq` accepts an explicit CES URI, so no policy rewriting was needed. The
client built and sent a genuine `RequestSecurityToken`; it was captured
verbatim, and is now `internal/issuer/adcs/testdata/rst-windows-client.xml`.

Notably, this sidesteps authentication entirely. The RST body was **byte
identical** (bar the `MessageID`) across `-anonymous` and `-kerberos`, so the
request shape does not depend on how the caller authenticates — the auth is
purely transport-level.

## A second thing it settles: which token is the certificate

The successful response was captured too, and it carries a trap. There are
**two** `BinarySecurityToken` elements, and the first in document order is not
the issued certificate:

```
RequestSecurityTokenResponse
├── BinarySecurityToken            ValueType=…secext-1.0.xsd#PKCS7   ← the chain
└── RequestedSecurityToken
    └── BinarySecurityToken        ValueType=…#X509v3               ← the issued leaf
```

A parser that reads the first token it finds returns a PKCS#7 blob and calls
it a certificate. `TestParseRSTRCReturnsTheLeafNotTheChain` pins the
distinction.

The response also confirms the finding from the other direction: ADCS tags its
*own* tokens with the same non-standard `…secext-1.0.xsd#base64binary`.

## Corroboration of the AD SID encoding

The certificate issued through this path carries
`szOID_NTDS_CA_SECURITY_EXT` with bytes that `encoding.SIDFromCertificateExtensions`
parses, and that `encoding.BuildNTDSCASecurityExt` then reproduces **byte for
byte**. That fixture was captured from a certificate obtained by a completely
different route (autoenrollment, `certreq -submit` over RPC), so this is an
independent confirmation of
[the AD SID extension encoding](2026-08-17-ad-sid-extension-encoding.md).

## Consequences

- `internal/issuer/adcs/wstep.go` builds the request and parses the response,
  with the constants pinned to the captures by golden tests. The test asserts
  the `EncodingType` is *not* the documented value, so a well-meaning
  correction against the specification fails the build rather than silently
  breaking issuance.
- The broker's request is deliberately **not** byte-identical to the Windows
  client's: it omits the `ccm` context item (which names the client machine
  and means nothing here) and does not line-wrap its base64. Both were
  verified accepted.
- `Issue` still refuses. Everything proven here enrols the broker **as
  itself**; enrolling *on behalf of* the target account needs the
  enrollment-agent credential and the CMC signed-request shape, which is where
  the actual security boundary lives.
