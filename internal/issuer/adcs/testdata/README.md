# Fixtures

Every file here is a **real wire capture**, not a construction. Neither the
MS-WSTEP request format nor the enrol-on-behalf-of request shape could be
derived from the specifications — see
[the WSTEP finding](../../../../docs/findings/2026-08-17-wstep-request-body.md)
and [the enrol-on-behalf-of finding](../../../../docs/findings/2026-08-24-enroll-on-behalf-of.md)
— so the captures are the authority and the tests treat them that way.

## `rst-windows-client.xml`

A `RequestSecurityToken` sent by **Microsoft's own client**, captured verbatim.

It was produced by pointing `certreq -submit -config <URI>` at a recording
endpoint that presented a CA-issued TLS certificate and answered like a CES
service. The client built and sent a genuine request; nothing was replayed,
proxied, or reconstructed.

| | |
|---|---|
| Client | `certreq.exe`, Windows Server 2025 (build 10.0.26100), `User-Agent: MS-WebServices/1.0` |
| Template requested | `User` |
| Captured | 2026-08-17, phase-4 lab |

### What it settles

The `EncodingType`:

```
http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary
```

That is the **secext schema URI** with a lowercase `#base64binary` fragment.
WS-Security documents
`.../oasis-200401-wss-soap-message-security-1.0#Base64Binary`, and ADCS
rejects it — along with every other documented spelling — with
`The EncodingType is invalid.`

The request the broker builds is **not** byte-identical to this one, and is not
meant to be. The Windows client wraps its base64 across lines and adds a `ccm`
context item naming the client machine; neither changes meaning. The test
compares the parts that carry meaning.

## `rstrc-response.xml`

The `RequestSecurityTokenResponseCollection` that ADCS returned for a
successful issuance, captured from a live CES endpoint.

| | |
|---|---|
| Issued by | `CN=PKINIT Lab Issuing CA, DC=pkinitlab, DC=internal`, an ADCS Enterprise Root CA |
| Template | `User` |
| Captured | 2026-08-17, phase-4 lab |

### What it settles

Which token is the issued certificate. The response carries **two**
`BinarySecurityToken` elements, and the first one in document order is not the
certificate:

```
RequestSecurityTokenResponse
├── BinarySecurityToken              ValueType=…secext-1.0.xsd#PKCS7   ← the chain
└── RequestedSecurityToken
    └── BinarySecurityToken          ValueType=…#X509v3               ← the issued leaf
```

A parser that reads the first `BinarySecurityToken` it finds gets a PKCS#7
blob and calls it a certificate. `TestParseRSTRCReturnsTheLeafNotTheChain`
pins this.

## `cmc-eobo-windows-client.der`

A CMC enrol-on-behalf-of request built by **Microsoft's own client**:

```
certreq -policy -cert <agent thumbprint> -attrib "RequesterName:PKINITLAB\pkinittest" \
        target.req policy.inf eobo.req
```

| | |
|---|---|
| Client | `certreq.exe`, Windows Server 2025 (build 10.0.26100) |
| Agent | `PKINITLAB\labadm`, SID `…-1104`, Certificate Request Agent policy |
| Target | `PKINITLAB\pkinittest`, SID `…-1103` |
| Template | `WorkloadPKINIT` (`msPKI-RA-Signature = 1`) |
| Captured | 2026-08-24, phase-4 lab |

### What it settles

Where the target account is named, and how. It travels in the CMC `regInfo`
control, inside the agent's signature, as:

```
CertificateTemplate=WorkloadPKINIT&RequesterName=PKINITLAB%5Cpkinittest&
```

Note `%5C`, not a backslash, and the trailing `&`. Passing the same name as an
*unsigned* submission attribute is accepted, returns success, and is ignored —
the CA issues for the caller's own account instead.

The CMC body is fully deterministic, so
`TestPKIDataMatchesTheWindowsClientByteForByte` compares the encoder's output
to these bytes exactly rather than structurally. The broker's own request
differs from this one in one respect and one only: it carries a single
`SignerInfo` (the agent's) where `certreq` carries two, because the broker never
holds the workload's private key. The live CA accepts both.

## `eobo-issued-cert.der`

The certificate the request above actually produced.

| | |
|---|---|
| Subject | `CN=PKINIT Test User`, UPN `pkinittest@pkinitlab.internal` |
| AD SID extension | `S-1-5-21-3734714977-4168152908-3762407930-1103` |
| Captured | 2026-08-24, phase-4 lab |

### What it settles

That the requester name was honoured. The SID is the **target's** (`…-1103`),
not the enrolling agent's (`…-1104`) — which is the only evidence that
distinguishes enrol-on-behalf-of from an ordinary enrolment, and the exact
distinction `Issue` checks on every response.

## `rst-cmc-windows-client.xml`

The CES request `certreq` builds when the payload is a CMC rather than a bare
PKCS#10, captured at a recording endpoint the same way as
`rst-windows-client.xml`.

| | |
|---|---|
| Client | `certreq.exe`, Windows Server 2025, `User-Agent: MS-WebServices/1.0` |
| Captured | 2026-08-24, phase-4 lab |

### What it settles

Two differences from the PKCS#10 form, neither guessable:

```
ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7"
```

the same `#PKCS7` value ADCS uses for the chain it returns — *not* an
`…/enrollment#CMC` spelling under the Microsoft namespace. And there is **no
`CertificateTemplate` context item**: the template is named inside the signed
CMC, so naming it outside would put the same decision where the signature does
not cover it. The only context item present is `ccm`, which names the client
machine and means nothing here, so the broker sends no `AdditionalContext` at
all.

## Hygiene

Everything here is synthetic. `pkinitlab.internal` is a disposable lab forest
on an isolated libvirt network; `.internal` is ICANN-reserved for private use.
The accounts, the SIDs, and the CA belong to that forest and to nothing else.
No private keys: the certificates are public, the PKCS#10 carries only a public
key and its proof-of-possession signature, and the CMC carries signatures over
them rather than the keys that made them.
