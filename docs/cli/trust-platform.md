# Bootstrapping Trust from a go-trusted-platform Node

This guide walks through using the xKey CLI to import a freshly-deployed
go-trusted-platform node's CA bundle, install it system-wide, and open a
browser that trusts the node's TLS certificate so you can register a
WebAuthn credential and log in.

## Prerequisites

- A go-trusted-platform control-plane (CP) node already deployed and
  reachable on the network.
- An xKey CLI build with `xkey trust bootstrap`, `xkey trust fetch`,
  `xkey trust add`, `xkey trust import-platform`, and
  `xkey browser launch` available.
- Either Chrome (or a Chromium-derivative) **or** Firefox installed for the
  WebAuthn login step.

## Security model

xKey supports exactly **three** legitimate paths for establishing trust in
a platform CA. None of them rely on trust-on-first-use (TOFU), and none of
them ever set `tls.Config.InsecureSkipVerify=true` without a strict
`VerifyPeerCertificate` callback installed alongside it.

| Path                          | Authentication                                                                              | When to use                                                                |
| ----------------------------- | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| 1. `xkey trust bootstrap`     | go-truststrap: DANE TLSA records, Noise handshake, SPKI manifest, or Direct mode            | Recommended when the operator has provisioned a truststrap configuration. |
| 2. `xkey trust fetch <url> --spki-pin <hex>` | Operator-supplied SPKI SHA-256 pin obtained out-of-band                          | Direct REST fetch with a pin from a secure channel (see below).            |
| 3. `xkey trust add <pem-file>`| Manual import of a PEM bundle copied out-of-band                                            | Air-gapped sites, USB stick transfer, signed email, etc.                   |

There is **no** trust-on-first-use path. There is **no** code path that
disables TLS chain validation without a strict pin verifier in place.
`InsecureSkipVerify=true` appears in exactly one place in the codebase
(`pkg/trust/fetcher/spki.go::BuildTLSConfig`) and only because a
`PinVerifier` callback is the sole authority on whether the peer is
acceptable.

### What "out-of-band" means for the SPKI pin

The SPKI hash passed to `--spki-pin` MUST be obtained through a secure
channel that does not depend on the very TLS connection it is meant to
verify. Acceptable sources include:

- An HSM-attested deployment manifest cryptographically bound to the node's
  identity at provisioning time.
- A signed deploy log emitted by the platform installer onto persistent,
  authenticated storage (e.g., the node's PIV credential or signed cloud
  metadata).
- A value manually transcribed from the server console at first boot.
- A provisioning artifact authored by an operator and delivered via a
  trusted secure-distribution mechanism.

Pasting a hash from an HTTP page, a chat message, or any unauthenticated
source defeats the entire purpose of pinning. If you cannot obtain the
hash through a secure channel, use `xkey trust bootstrap` (which derives
trust from DNSSEC/DANE or a pre-shared truststrap manifest) or
`xkey trust add` (manual PEM import after secure file transfer) instead.

## Path 1: `xkey trust bootstrap` (recommended)

When the platform deployment includes a truststrap configuration (DANE
TLSA records, Noise pre-shared key, SPKI manifest, or Direct mode keys),
the bootstrap command will derive and verify trust automatically. See the
go-truststrap documentation for the configuration formats.

```
xkey trust bootstrap --config /etc/xkey/truststrap.yaml
```

This is the preferred mode because it requires no manual hash transcription
and produces the same auditable result on every node.

## Path 2: `xkey trust fetch` (SPKI-pinned)

When a truststrap configuration is not available but the operator has the
SPKI pin in hand, fetch the bundle directly:

```
xkey trust fetch https://cp.example.internal:9443/api/v1/ca/bundle \
  --spki-pin 3a7be5f1c0baf12c... \
  --install-system
```

Sample output:

```
Fetching CA bundle from https://cp.example.internal:9443/api/v1/ca/bundle
Bundle fetched from https://cp.example.internal:9443/api/v1/ca/bundle
  certificates: 2 (added: 2, skipped: 0)
  leaf SPKI:    3a7be5f1c0baf12c...
  installed to OS trust store: xkey-3a7be5f1c0baf12c (Platform Root CA)
```

`--spki-pin` is mandatory. Omitting it returns:

```
trust: invalid fetch arguments: --spki-pin is required (no trust-on-first-use path)
```

### Convenience: `import-platform`

When the URL follows the canonical path, you can pass just `host:port`:

```
xkey trust import-platform cp.example.internal:9443 \
  --spki-pin 3a7be5f1c0baf12c... \
  --install-system
```

This expands to `https://cp.example.internal:9443/api/v1/ca/bundle` and
runs the same logic. `--spki-pin` is required here as well.

## Path 3: `xkey trust add` (manual PEM import)

For air-gapped or fully out-of-band workflows, copy the platform CA PEM
bundle to the host through a secure channel (USB stick, signed email,
authenticated artifact server, etc.) and import it directly:

```
xkey trust add /path/to/platform-ca.pem --install-system
```

No network connection to the platform is opened. Trust comes entirely
from the integrity of the file you supplied.

## 2. Verify the trust store

After any of the three paths complete, the certificates are visible via
`xkey trust list`:

```
xkey trust list
```

The new CA appears with:

- `purpose` = `bootstrap-ca` (override with `--purpose`)
- `source`  = `platform:cp.example.internal:9443` for path 2; the file path
  for path 3; the truststrap source label for path 1 (override with
  `--source`)
- `system_install` = `true` if you passed `--install-system`

## 3. Launch a trusting browser

Open the CP's web UI in a browser whose profile has been preconfigured with
the platform CA:

```
xkey browser launch https://cp.example.internal:9443
```

Mechanism:

- Chrome / Chromium: writes an isolated NSS `cert9.db` containing every
  certificate in the xKey trust store (no `certutil` dependency — the
  database is built in pure Go via `pkg/nssdb`).
- Firefox: drops a `policies.json` overlay into the profile so the
  enterprise-roots policy picks up the certificates.

To force a particular browser:

```
xkey browser launch --browser /usr/bin/firefox https://cp.example.internal:9443
```

Errors:

- `browser: no Chrome or Firefox browsers detected` — install one.
- `browser: launch failed: ... no certificates` — run step 1 first.

## 4. Register a WebAuthn credential and log in

With the browser now trusting the platform CA, the CP's web UI loads
without a TLS warning. Register a WebAuthn credential through the platform
admin/login flow, then return to the CLI for headless authentication:

```
xkey auth login --server cp.example.internal:9443
```

(WebAuthn ceremony details are owned by go-trusted-platform; this guide
only covers the trust-store + browser preconditions.)

## Reference

| Command                                              | Purpose                                                  |
| ---------------------------------------------------- | -------------------------------------------------------- |
| `xkey trust bootstrap`                               | go-truststrap-mediated trust establishment (DANE/Noise/SPKI/Direct). |
| `xkey trust fetch <url> --spki-pin <hex>`            | Fetch a CA bundle by full URL with mandatory SPKI pin.   |
| `xkey trust import-platform <host:port> --spki-pin <hex>` | Fetch using the canonical platform URL with mandatory SPKI pin. |
| `xkey trust add <pem-file>`                          | Import a PEM bundle from disk (manual out-of-band).      |
| `xkey trust list`                                    | List all certificates in the xKey trust store.           |
| `xkey trust install <fp>`                            | Re-install a stored cert into the OS store.              |
| `xkey browser launch [url]`                          | Launch Chrome/Firefox with the CA preinstalled.          |

### Flags shared by `trust fetch` and `trust import-platform`

| Flag                       | Description                                                                                              |
| -------------------------- | -------------------------------------------------------------------------------------------------------- |
| `--spki-pin <hex>`         | **Required.** Pin the leaf certificate's SPKI SHA-256 hash (64 hex chars). Obtain out-of-band.           |
| `--purpose <purpose>`      | Certificate purpose tag (default `bootstrap-ca`).                                                        |
| `--source <source>`        | Recorded provenance string (default `platform:<host>`).                                                  |
| `--install-system`         | Promote root certificates to the OS trust store after fetch.                                             |
| `--timeout <duration>`     | HTTP transaction timeout (default 30s).                                                                  |

Omitting `--spki-pin` returns `trust: invalid fetch arguments`.

## Security notes

- `xkey trust fetch` and `xkey trust import-platform` always pin the leaf
  certificate's SPKI SHA-256 hash. There is no trust-on-first-use path,
  no `--insecure-first-touch` flag, and no automatic acceptance of an
  unverified server.
- `--spki-pin` bypasses system trust store validation (the platform CA is
  what we are bootstrapping — its root is by definition not yet trusted)
  and validates the leaf SPKI cryptographically against the pre-shared
  hash.
- `tls.Config.InsecureSkipVerify=true` is permitted in exactly one place:
  `pkg/trust/fetcher/spki.go::BuildTLSConfig`. It is gated by
  `PinVerifier`, which is the only path through which a TLS handshake can
  succeed in this codebase without a system-rooted chain.
- The fetched bundle is recorded with the `bootstrap-ca` purpose by
  default so subsequent operations can distinguish operator-fetched
  platform CAs from manually-imported corporate roots.
