# Network Agent — User Guide

> **Status: NORMATIVE** · Feature: `agent` · Module: `go-xkms/xkey` · Last verified: 2026-09-23

## What this is

The xKey network agent lets a remote machine use the xKey services running
on a master machine — PKCS#11, FIDO2, PIV, CCID, crypto, SSH — without the
remote machine ever holding key material. All operations are proxied over
an mTLS connection back to the master, which is the only place private keys
live.

## Enroll and start the server

```
xkey agent start --xkmsd-url grpcs://kms.example.com:8443 \
    --tls-cert server.pem --tls-key server-key.pem --tls-ca ca.pem
```

Then generate a code for the remote device's operator to use. This can be
run from any machine and process with access to the same xKey data
directory the running `agent start` uses — a separate terminal, a script,
or later — since the code's hash is persisted to the enrollment store and
honored by whichever process the enrolling agent reaches:

```
xkey agent code --validity 30m
```

Give the printed code to the remote device, which runs `xkey device enroll`
(documented separately) with it. On approval, the remote device receives a
signed certificate and can now `xkey device connect` to the master.

If the remote device instead submits a request for manual approval, list
and approve it from the master:

```
xkey agent pending
xkey agent approve <request-id>
```

or reject it, deleting the request without ever signing its CSR:

```
xkey agent reject <request-id> --reason "not authorized"
```

## Check status

```
xkey agent status
```

Shows whether the server is running and lists every enrolled agent,
whether or not the server is currently running.

## Remove an agent

```
xkey agent remove <agent-id>
```

This is the only correct way to revoke a remote device's access. It
revokes the agent's certificate through the certificate authority, then
deletes the enrollment record — in that order, so a partially-completed
removal never leaves a certificate that still works. If the certificate
authority cannot be reached, the command fails and the agent stays
enrolled; retry once connectivity is restored. Deleting the enrollment
record any other way (editing the store directly, for example) would
leave the certificate valid and is not supported.

Removal works from any invocation — the running `agent start` daemon, the
GUI, or a later CLI session — because enrollment records live on disk, not
in a running process's memory. The same is true of `agent code`, `agent
pending`, `agent approve`, and `agent reject`: every verb reads and writes
the same on-disk enrollment store.

## Server configuration

`xkey agent start` flags, or the equivalent `agent:` section of the xkey
config file:

| Field | Type | Default | Description |
|---|---|---|---|
| `listen_address` | string | `:9443` | Bind address; `--listen` overrides |
| `tls_cert_file` | string | | Server TLS certificate path |
| `tls_key_file` | string | | Server TLS private key path |
| `tls_ca_file` | string | | CA certificate for client verification (enables mTLS and the revocation/enrollment checks) |
| `enrollment_methods` | []string | `[one_time_code]` | Allowed enrollment methods |
| `require_attestation` | bool | `false` | Require platform attestation during enrollment |
| `cert_validity_days` | int | `365` | Validity period for issued agent certificates |
| `max_agents` | int | `0` | Maximum enrolled agents (`0` = unlimited) |
| `one_time_code_length` | int | `8` | Character length of generated enrollment codes |
| `one_time_code_validity` | duration | `15m` | Default validity for one-time codes |

```yaml
agent:
  listen_address: ":9443"
  tls_cert_file: /etc/xkey/agent-server.crt
  tls_key_file: /etc/xkey/agent-server.key
  tls_ca_file: /etc/xkey/ca.crt
  enrollment_methods:
    - one_time_code
    - admin_approval
  require_attestation: false
  cert_validity_days: 365
  max_agents: 50
  one_time_code_length: 8
  one_time_code_validity: 15m
```

Client-side (`xkey device connect`) configuration is unchanged by this
feature; see the device-enrollment documentation.

## See also

- [CLI](cli.md) — every `xkey agent` verb, with flags
- [Architecture](architecture.md) — why a removed or revoked agent is
  rejected at connect time, and how codes and pending requests are
  persisted
