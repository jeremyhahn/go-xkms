# PIV Smartcard — CLI

> **Status: NORMATIVE** · Feature: `piv-smartcard` · Repo: `go-xkms` · Last verified: 2026-09-03

Binary: `xkmsctl`, group `piv` (`cmd/xkmsctl/piv.go`). Global flags —
`--backend`, `--pkcs11-module`, `--pkcs11-slot`, `--pkcs11-pin`, `--transport`,
`--server` — are in [`../key-management/cli.md`](../key-management/cli.md).

`<slot>` is always one of the defined PIV slots: `9a`, `9c`, `9d`, `9e`, `f9`,
or a retired slot `82`–`95`. Anything else is rejected before a device is
touched.

| Verb | Args | Purpose |
|---|---|---|
| `piv list` | — | List slots and their occupancy |
| `piv get <slot>` | slot | Read the certificate in a slot |
| `piv store <slot>` | slot | Write a certificate into a slot |
| `piv delete <slot>` | slot | Clear a slot |
| `piv generate <slot>` | slot | Generate a key in a slot |
| `piv import <slot>` | slot | Import a certificate |
| `piv export <slot>` | slot | Export the certificate |
| `piv csr <slot>` | slot | Produce a CSR for the slot's key |

## `piv list`

No flags. Reports each slot's metadata and whether it is occupied.

```
xkmsctl piv list -o json
```

## `piv get <slot>` / `piv export <slot>`

| Flag | Type | Default |
|---|---|---|
| `--format` | string | `pem` — `pem` or `der` |

```
xkmsctl piv get 9a --format pem
xkmsctl piv export 9a --format der > auth.der
```

Both return the **certificate**. There is no verb that exports a PIV private
key, on any storage type.

## `piv store <slot>` / `piv import <slot>`

| Flag | Type | Default | Required |
|---|---|---|---|
| `--cert-file` | string | `""` | **yes** — path to the certificate |
| `--format` | string | `pem` | no — `pem` or `der` |

```
xkmsctl piv store 9a --cert-file auth.crt --format pem
```

**`piv import` imports a certificate, not a private key.** It is an alias for
`store` and shares its request type. Passing a private key to it puts the key
in a field named `Certificate` — the defect that motivated adding a real
private-key import path.

Importing a private key has **no CLI verb**: it is reachable only through the
SDK (`xkms.ImportPIVKey`), because its input is private key material and this
feature keeps key material off the transports. See
[`api.md`](api.md) and [`architecture.md`](architecture.md).

## `piv generate <slot>`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--algorithm` | string | `ecdsap256` | key algorithm |
| `--subject` | string | `""` | certificate subject, e.g. `CN=alice` |

```
xkmsctl piv generate 9a --algorithm ecdsap256 --subject "CN=alice,O=Example"
```

**Pick the slot for its purpose, not for convenience.** `9a` is
authentication, `9c` is digital signature and non-repudiation, `9d` is key
management, `9e` is card authentication *without cardholder interaction*. A
general-purpose key belongs in a retired slot (`82`–`95`) — that is what they
are for, and taking `9a` breaks card authentication for every other tool that
reads the card.

## `piv csr <slot>`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--subject` | string | `""` | CSR subject, e.g. `CN=alice,O=Example` |

```
xkmsctl piv csr 9a --subject "CN=alice,O=Example" > alice.csr
xkmsctl ca sign-csr --csr alice.csr --profile client --output alice.crt
xkmsctl piv store 9a --cert-file alice.crt
```

That three-step sequence — generate in the slot, CSR out, signed certificate
back in — is the normal PIV enrollment path. The private key never moves.

## `piv delete <slot>`

No flags. Clears the slot.

## Choosing where the slots live

Storage is a server-side configuration choice between `file`, `tpm2` (NV) and
`pkcs11` (token objects) — see [`engineering.md`](engineering.md)
§Configuration. The verbs are identical across all three; what changes is where
the bytes end up and what the guarantee is.

## Exit codes

`0` on success; non-zero on an invalid slot, an absent device, a locked token, a
full NV space, or a format mismatch. An invalid slot fails before any device is
touched.

## Parity coverage

**Defect: no `piv` verb has a `CommandDefinition` in
`test/integration/api/commands/commands.go`.** The eight PIV routes exist on
REST, gRPC, QUIC, Unix and MCP (see [`api.md`](api.md)) and the handlers have
their own suites, but the CLI verbs are absent from the table-driven
multiprotocol parity runner.
