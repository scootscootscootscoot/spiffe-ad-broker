# Fixtures

Both files are **real wire captures**, not constructions. The MS-WSTEP request
format could not be derived from the specifications — see
[the finding](../../../../docs/findings/2026-08-17-wstep-request-body.md) — so
the capture is the authority and the tests treat it that way.

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

## Hygiene

Everything here is synthetic. `pkinitlab.internal` is a disposable lab forest
on an isolated libvirt network; `.internal` is ICANN-reserved for private use.
The account, the SID, and the CA belong to that forest and to nothing else. No
private keys: the certificates are public, and the PKCS#10 carries only a
public key and its proof-of-possession signature.
