# ACME Issuance — User Guide

> **Status: NORMATIVE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-09-28

## Prerequisites

- An `xkmsd` with a CA and the ACME server enabled, and its directory URL.
- The CA bundle in your trust store — see
  [`../trust-bootstrap/user.md`](../trust-bootstrap/user.md). ACME will not save
  you here: you must already trust the server you are asking for certificates.
- `trusted-acme-client` on your PATH, or any standard ACME client.

## You can use any ACME client

The server implements RFC 8555. `certbot`, `lego`, `caddy` and everything else
work against it, pointed at the directory URL:

```
https://kms.example.com:8443/api/v1/acme/directory
```

Use `trusted-acme-client` when you want the parts that are not in the standard —
TPM-backed account keys, `enroll-01` hardware enrollment, and device attestation.

## First run

```
trusted-acme-client account add prod \
    --directory https://kms.example.com:8443/api/v1/acme/directory \
    --email ops@example.com
```

Put the account key somewhere real if this account can issue anything that
matters:

```
trusted-acme-client account add prod \
    --directory https://kms.example.com:8443/api/v1/acme/directory \
    --email ops@example.com \
    --key-store tpm2 --key-algorithm ECDSA --key-curve P-384
```

An ACME account key is a standing authority to obtain certificates. On disk it
is a file someone can copy; in a TPM it is not.

## Getting a certificate

Certificates are named specs in your config file — subject, SANs, key
parameters and challenge type live there, so the commands stay short:

```
trusted-acme-client cert request web-prod
trusted-acme-client cert show   web-prod
trusted-acme-client cert deploy web-prod
```

Renewal, by hand or by service:

```
trusted-acme-client cert renew web-prod
trusted-acme-client service start
trusted-acme-client service status
```

Revocation:

```
trusted-acme-client cert revoke web-prod --reason 1
```

Reason `1` is key compromise, `4` is superseded, `0` is unspecified.

## Choosing a challenge

| Challenge | Use it when | What it needs from you |
|---|---|---|
| `http-01` | the name resolves to a host you control on port 80 | that port reachable from the server; `challenge.http01.host` (env `ACME_CLIENT_CHALLENGE_HTTP01_HOST`) binds one interface, empty binds all |
| `dns-01` | you control DNS, or the host is not publicly reachable | a DNS provider the client can write TXT records to |
| `device-attest-01` | the key is in a device that can attest to it | the device |
| `enroll-01` | the thing being certified is a TPM | the TPM, and its EK chain trusted by the CA |
| `endorse-01` | an existing trusted party vouches for the requester | an EAB credential |

## Enrolling hardware

This is the path the platform uses to admit a node. Devices, like
certificates, are named specs in the config file — configure the account,
the TPM, the common name and the PCR selection once under `devices.<name>`,
then act on the name:

```yaml
devices:
  node-07:
    account: prod
    common-name: node-07.example.com
    identifier: node-07.example.com
    pcr-selection: [0, 1, 2, 3, 4, 5, 6, 7]
    tpm:
      config:
        device: /dev/tpmrm0
```

```
trusted-acme-client device enroll node-07
```

The server sends a challenge only the real TPM can answer: it encrypts a secret
to the TPM's endorsement key, and the TPM must activate it. Nothing you can type
substitutes for the hardware.

To bind the certificate to the machine's measured state as well as its identity:

```
trusted-acme-client device attest node-07
```

Choose the PCR set deliberately. The default covers firmware and boot. Including
a PCR that changes on every kernel update means the attestation stops matching
after the next update — which is either the security property you wanted or an
outage you did not, depending on what the certificate is for.

`tpm` is optional; leaving it unset opens go-xkms's own simulator-backed TPM2
defaults, which is development and testing only. A production spec always
sets `tpm.config.device` to an already-provisioned TPM — see
[cli.md](cli.md#trusted-acme-client-device).

## Joining a cluster with attested enrollment

When a cluster is configured with attested Raft enrollment, joining nodes get
their certificates through this feature automatically:

```yaml
cluster:
  raft_enrollment:
    key_backend: tpm2
    acme:
      enabled: true
      directory_url: "https://node1.example.com:8443/api/v1/acme/directory"
      challenge_port: "8080"
```

Two things surprise people: `directory_url` is **required on joining nodes and
ignored on the first node** (which issues in-process), and `challenge_port` is a
port the *server dials back to on the joining node* — so it has to be reachable
from the server, not just open locally. The listener binds `server.host`, so a
node pinned to one interface serves the exchange on that interface only.

## Browsing the API interactively

`GET /docs` on the Admin API address serves a Swagger UI you can browse the
RFC 8555 and admin surfaces from, and try requests against directly. It is
admin-gated — the same Bearer JWT or mTLS credential and permission grant
`GET /admin/algorithms` requires — because the specs it renders list every
admin route, parameter and permission this deployment exposes:

```
curl -H "Authorization: Bearer $TOKEN" https://kms.example.com:8443/docs
```

Open that URL in a browser signed in the same way (or via an mTLS-aware proxy)
and switch specs with the **ACME API** / **Admin API** links in the top bar, or
`?spec=acme-api` / `?spec=admin-api` in the URL. The raw specs are also
available on their own for tooling that consumes OpenAPI directly:

```
curl -H "Authorization: Bearer $TOKEN" https://kms.example.com:8443/openapi/acme-api.yaml
curl -H "Authorization: Bearer $TOKEN" https://kms.example.com:8443/openapi/admin-api.yaml
```

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| `badNonce` on every request | the client is not reading the `Replay-Nonce` header | use a compliant client; nonces are single-use |
| doubled path in the directory, `/api/v1/api/v1/acme/...` | the server's base URI is misconfigured | fix the server's `baseRESTURI`; the client is fine |
| `rejectedIdentifier` | the identifier is blocklisted, is not under a public suffix, or (for an IP) is in a reserved/loopback range | check `acme.policy` in the server config, or request an identifier the policy allows |
| `caa` error | a CAA record forbids this CA outright, restricts issuance to a different ACME account (`accounturi`) or challenge type (`validationmethods`, RFC 8657) than this request used, has a malformed `accounturi`/`validationmethods` value, or the server could not determine the CAA RRset at all (DNS failure fails closed, RFC 8659 §5.1) | fix the CAA record — issuer domain, `accounturi`, or `validationmethods` — to allow this CA, this account, and the challenge type you're using; or retry once DNS is reachable |
| `rateLimited` | per-client request cap hit — the whole ACME surface is capped per client IP, and new-order, finalize and failed validations also per verified account | back off; the response carries `Retry-After` |
| HTTP 413 with a `malformed` problem | the request body is larger than 256 KiB | a normal ACME request is far smaller; for a TPM enrollment finalize, the platform's boot event log is unusually large |
| `malformed`: "Order has N identifiers; at most 100 are allowed" | a single new-order listed more than 100 identifiers | split the names across several orders |
| `orderNotReady` on finalize | an authorization is still pending | complete the challenge first |
| `badCSR` | the CSR does not match the order's identifiers | regenerate the CSR from the order |
| `badCSR` on a `device-attest-01`/`enroll-01` CSR finalize | the CSR has no RFC 4043 `permanentIdentifier` otherName (OID `1.3.6.1.5.5.7.8.3`) in its `subjectAltName` | the identifier is never read from the Common Name; encode it as the otherName |
| `rejectedIdentifier` on finalize with a correct otherName | the CSR carries a DNS/IP SAN, or a permanent identifier value, the order did not authorize | regenerate the CSR with only the names the order's identifiers list |
| `enroll-01` never completes | the TPM's EK does not chain to a manufacturer root the CA trusts | import the manufacturer chain server-side |
| joining node hangs during enrollment | the server cannot reach `challenge_port` on the node | open it, or fix the advertised address |
| `incorrectResponse` on challenge validation, right away instead of after a timeout | the `http01`/`dns01` circuit breaker is open — the verifier failed enough times recently that the server is failing fast instead of retrying a target it already knows is unreachable | fix or wait out whatever is unreachable (the target host, DNS); check `GET /acme/health` for the breaker's state and when it last tripped |
| finalize fails for a tenant-CA order specifically, other orders unaffected | the `kms` circuit breaker is open — the tenant KMS signer is unreachable | check the KMS backend; `GET /acme/health` reports the `kms` breaker |
| `GET /acme/directory` or `GET /acme/ca-bundle` returns a `Warning: 110 - "Response is stale"` header | the `storage` breaker (CA/keystore access) is open and the server is serving its last known-good response instead of failing the request | check `GET /acme/health`'s `degradation.active`; `POST /acme/new-order` and the rest of the protocol are unaffected by this — only these two GET endpoints degrade |

Circuit breakers guard individual dependencies (the challenge verifiers, the
tenant KMS signer, CA-bundle storage access), not order creation:
`POST /acme/new-order` is never refused because a breaker is open. `GET
/acme/health` reports every breaker's state and whether the server is
currently serving degraded (cached) directory/CA-bundle responses. Both
xkmsd's embedded ACME listener and the standalone `trusted-acme-client
serve` / `TrustedCA` deployment wire this the same way: `http01`/`dns01`
appear once a challenge verifier for that type is configured, and `storage`
is always present. Configure the breakers and the degradation cache under
`acme.resilience` (xkmsd) or `acme.resilience` in `TrustedCAConfig` (the
standalone deployment) — the same fields, same defaults, in both.

## Where to go next

- Operating the CA behind ACME: [`../certificate-authority/user.md`](../certificate-authority/user.md)
- Trusting the server in the first place: [`../trust-bootstrap/user.md`](../trust-bootstrap/user.md)
- What TPM attestation actually proves: [`../tpm2/user.md`](../tpm2/user.md)
