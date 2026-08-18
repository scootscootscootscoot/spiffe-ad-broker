# Fixtures

## `ntds-ca-security-ext.der` / `adcs-user-cert.pem`

The AD SID security extension (`szOID_NTDS_CA_SECURITY_EXT`,
`1.3.6.1.4.1.311.25.2`), captured from a **real ADCS-issued certificate** —
which is the only acceptable provenance for these bytes. They were not
inferred from documentation, from the OID, or from a description of the
structure.

`adcs-user-cert.pem` is the whole certificate, kept so the extension can be
re-extracted and the provenance re-checked. `ntds-ca-security-ext.der` is its
`extnValue`, byte for byte.

Provenance:

| | |
|---|---|
| Issued by | `CN=PKINIT Lab Issuing CA, DC=pkinitlab, DC=internal`, an ADCS Enterprise Root CA |
| Host | Windows Server 2025, build 10.0.26100 |
| Template | `User` (default), enrolled via `certreq -submit` |
| Captured | 2026-08-17, phase-4 lab |

Everything here is synthetic. `pkinitlab.internal` is a disposable lab forest
on an isolated libvirt network; `.internal` is ICANN-reserved for private use.
The SID belongs to a throwaway account in that forest and to nothing else.

### What it settles

The structure, as ADCS actually emits it:

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

The SID is the **textual** `S-1-…` rendering in ASCII, *not* the MS-DTYP
binary layout that `MarshalSID` produces. That was an open question, and
guessing it wrong would have produced a well-formed extension naming the
wrong account. The extension is **not** marked critical.
