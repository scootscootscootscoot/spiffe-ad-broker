# The ADCS request path: CES/CEP over HTTPS, with two http.sys prerequisites

**Date:** 2026-08-17
**Lab:** phase-4, `pkinitlab.internal`, Windows Server 2025 build 10.0.26100
**Decides:** next action 1 ("decide the ADCS request path") and next action 4
("stand up ADCS in the phase-4 lab")

## Question

The `adcs` backend has to get a certificate request to an Enterprise CA. Two
candidate paths were open:

- **MS-WCCE over DCOM** — the native one, and painful from Go.
- **CMC/WSTEP over the CES/CEP HTTP endpoints** — the realistic alternative.

The recorded next step was to *establish which the lab's ADCS can be made to
speak before writing any client code*. This is that result.

## Answer

**CES/CEP over HTTPS, authenticated with a client certificate.** A
zero-dependency Go client using only `crypto/tls` and `net/http` authenticates
to both endpoints and retrieves the enrollment policy, on TLS 1.2 and TLS 1.3
alike.

Out of the box only DCOM was reachable — ports 135 and 445 open, nothing on
443. CES and CEP had to be installed (`ADCS-Enroll-Web-Svc`,
`ADCS-Enroll-Web-Pol`), both configured with `-AuthenticationType Certificate`.
Once installed, from the Linux host:

```
POST /ADPolicyProvider_CEP_Certificate/service.svc/CEP   -> 200, 24123 bytes
```

The MS-XCEP `GetPoliciesResponse` enumerates all 13 templates and hands back
the CES endpoint URI, which is how the broker would discover where to enrol.
The IIS log records the caller as `PKINITLAB\labadm` — the client certificate
mapped to its AD account.

This matters beyond convenience: DCOM from Go needs an MSRPC/NTLM stack, which
means a dependency tree inside a credential-minting process. The module's zero
dependencies are an auditability property. **The HTTP path preserves it.**

## The part that would have cost a day later

Getting a 200 from Go needed **two settings on the ADCS host's http.sys SSL
binding** that IIS does not set when CES/CEP are installed:

```
netsh http update sslcert ipport=0.0.0.0:443 certhash=<thumb> appid=<guid> \
  certstorename=MY clientcertnegotiation=enable dsmapperusage=enable
```

Both are required, and each fails differently:

| Setting | Default | Symptom when unset |
|---|---|---|
| `clientcertnegotiation` | Disabled | Go never sees a `CertificateRequest` |
| `dsmapperusage` | Disabled | Cert accepted, but no AD identity ⇒ HTTP 500 |

**Why `clientcertnegotiation` matters.** By default IIS obtains the client
certificate *after* the handshake — by TLS 1.2 renegotiation, or TLS 1.3
post-handshake authentication. Go's `crypto/tls` client supports **neither**:
it refuses renegotiation outright (`local error: tls: no renegotiation`) and
does not implement TLS 1.3 post-handshake client auth, so the server's request
is simply never answered and IIS returns 500 with win32 status 50
(`ERROR_NOT_SUPPORTED`). curl succeeds in both modes, which makes this an easy
thing to mis-diagnose: **the endpoint works fine from curl and is unusable
from Go.** Enabling `clientcertnegotiation` moves the request into the initial
handshake, where a stock Go client answers it normally.

**Why `dsmapperusage` matters.** Once http.sys owns the negotiation it also
owns the mapping to a Windows identity. With it disabled the certificate is
accepted at the TLS layer but the request arrives anonymous — the IIS log shows
an empty username — and CES, which needs a caller identity, returns 500. The
site root still returns 200, so the binding looks healthy while every
enrollment call fails.

Neither is a broker code change. Both are **deployment prerequisites the
`adcs` backend has to document**, because both produce a confusing failure at
a layer nobody would look at first.

## Left open

Authentication and transport are settled; the request *body* is not. A
PKCS#10 submitted in an MS-WSTEP `RequestSecurityToken` was rejected with
`The EncodingType is invalid` across every documented combination of
`ValueType`/`EncodingType` tried. Notably, the `wsa:Action` must be the
Microsoft URI, not the OASIS one:

```
http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep
```

with the OASIS action, CES answers `The action is invalid`.

Per this project's own rule, the wire format should be taken from a real
Windows client rather than from documentation. An attempt to capture one via
WCF message logging on the CES `web.config` did not produce output before the
lab was torn down (trace files created, zero bytes), and driving a Windows
enrollment through PowerShell remoting hit the classic double-hop
(`WS_E_ENDPOINT_ACCESS_DENIED`) because the remote session has no client
certificate to present. Next attempt should stand up a second CES instance
with Kerberos authentication and enrol locally, avoiding both problems.

## Method notes

- Enterprise Root CA, one tier. Topology does not bear on the protocol
  question, and the lab's standing rule is to resist growing it.
- **The CA auto-published itself into `NTAuthCertificates` on install.** That
  is the `adcs` backend's central premise — "ADCS's issuing CA is already in
  NTAuth, and it is the leaf's immediate issuer" — now observed rather than
  assumed.
- A dedicated `labadm` account was created for the ADCS deployment cmdlets,
  which require an Enterprise Admin and reject the machine account
  (`SYSTEM`) that the guest-agent channel runs as.

## Incidental: a lab clock bug worth keeping fixed

The guest was **two hours ahead of true UTC**. libvirt presents the RTC as
host *local* time (`<clock offset='localtime'>`) while the guest was set to
Pacific and the host is `America/Chicago` — the guest read the host's local
time and added seven hours instead of five.

The first CA built in this session was post-dated by two hours, so every
certificate it issued was `notBefore` in the future and TLS from the host
failed with "certificate is not yet valid". The whole PKI was rebuilt after
correcting the clock. **A post-dated CA silently poisons every certificate,
CRL `nextUpdate`, and PKINIT result taken from this lab**, so the guest
timezone must stay matched to the host's while the RTC is presented as
localtime.
