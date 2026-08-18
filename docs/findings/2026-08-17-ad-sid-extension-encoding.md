# The AD SID security extension carries a *string*, not a binary SID

**Date:** 2026-08-17
**Lab:** phase-4, `pkinitlab.internal`, Windows Server 2025 build 10.0.26100
**Unblocks:** `subordinate`'s SID extension builder — the one item on the
board that was `blocked`, inherited unsolved from the predecessor

## The blocker

`szOID_NTDS_CA_SECURITY_EXT` (`1.3.6.1.4.1.311.25.2`) is what the KDC maps a
certificate to an account on. The `subordinate` backend has to emit it itself,
and the standing rule is that its bytes may only come from a real ADCS-issued
certificate or an authoritative Microsoft vector — never from documentation,
never from the OID. No such fixture existed, so the builder stayed unwritten.

Standing up ADCS for the request-path work made one available for free: an
Enterprise CA emits this extension natively on an ordinary `User` template.

## The bytes

From a certificate issued by the lab's ADCS Enterprise CA
(`internal/encoding/testdata/adcs-user-cert.pem`):

```
3040 a03e 060a 2b06 0104 0182 3719 0201 a030 042e
532d 312d 352d 3231 2d33 3733 3437 3134 3937 372d
...
```

which parses as:

```
SEQUENCE {
  [0] {
    OBJECT IDENTIFIER 1.3.6.1.4.1.311.25.2.1   -- szOID_NTDS_OBJECTSID
    [0] {
      OCTET STRING "S-1-5-21-3734714977-4168152908-3762407930-1104"
    }
  }
}
```

## What it settles

**The SID is its textual `S-1-…` rendering in ASCII, not the MS-DTYP binary
layout.** This was explicitly flagged as open in `internal/encoding/sid.go`
and deliberately not guessed. The guess would have been wrong.

That failure mode is the reason the rule exists: the binary form is a
perfectly well-formed OCTET STRING, so a certificate built on the wrong guess
would have been structurally valid and would have named **the wrong account**
— or no account. There is no encoding error to catch it; the KDC either maps
to something unintended or refuses, and neither says why.

Two smaller details, also from the fixture rather than from prose:

- The extension is **not** marked critical.
- The inner value is wrapped in `[0]` *twice* — once for the `OtherName`
  and once for its value — which is easy to get wrong by one layer. The
  golden test caught exactly that mistake in the first implementation.

## Where it lives

- `internal/encoding/testdata/ntds-ca-security-ext.der` — the `extnValue`
- `internal/encoding/testdata/adcs-user-cert.pem` — the whole certificate, so
  the extension can be re-extracted and the provenance re-checked
- `BuildNTDSCASecurityExt` — pinned to it byte for byte by
  `TestNTDSCASecurityExtMatchesADCS`

All synthetic: a throwaway account in a disposable lab forest on an isolated
network.

## What it does not change

`adcs` remains the preferred backend. This removes `subordinate`'s blocker; it
does not remove `subordinate`'s other costs — that backend still has to run a
CA and sign and publish a CRL, both of which `adcs` gets from infrastructure
that already exists.
