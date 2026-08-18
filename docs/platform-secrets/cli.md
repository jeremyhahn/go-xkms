# Platform Secrets — CLI

> **Status: NORMATIVE** · Feature: `platform-secrets` · Repo: `go-xkms` · Last verified: 2026-08-19

Binary: `xkmsctl`, group `platform` (`cmd/xkmsctl/platform.go`). Global flags:
[`../key-management/cli.md`](../key-management/cli.md).

| Verb | Args | Purpose |
|---|---|---|
| `platform put <name>` | name | Store a secret |
| `platform get <name>` | name | Retrieve and unseal it |
| `platform delete <name>` | name | Remove it |
| `platform list` | — | List secret **names** |
| `platform reseal <name>` | name | Re-seal against the current platform state |
| `platform status` | — | Report the store's state |

## `platform put <name>`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--value` | string | `""` | secret value; `-` reads stdin; prompted when omitted |
| `--file` | string | `""` | read the secret bytes from a file |

```
xkmsctl platform put upstream-api-token --value -
printf '%s' "$TOKEN" | xkmsctl platform put upstream-api-token --value -
xkmsctl platform put webhook-secret --file ./webhook.key
```

Omitting `--value` prompts; `-` reads stdin. A literal value on the command line
lands in shell history and `ps` output.

**`put` over an existing name overwrites it with a fresh seal.** There is no
versioning and no previous value to recover.

## `platform get <name>`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--output` | string | `""` | write the raw bytes to a file at mode 0600 |

```
xkmsctl platform get upstream-api-token --output /run/secrets/token
xkmsctl platform get upstream-api-token          # to stdout
```

Without `--output` the secret goes to stdout — and into your scrollback.

## `platform list` / `delete` / `status`

```
xkmsctl platform list -o json
xkmsctl platform delete upstream-api-token
xkmsctl platform status -o json
```

`list` returns **names**. Names are not secret; values are.

## `platform reseal <name>`

```
xkmsctl platform reseal upstream-api-token
```

Reads the current plaintext, discards the old sealed copy, and writes it back
sealed against the machine's **current** state.

This is the remedy for the expected failure: on a TPM-sealed backend, a firmware
or boot change makes existing secrets unopenable. `reseal` re-binds them.

Two things to hold onto:

- It is **explicit on purpose**. Resealing automatically on every read would
  rebind secrets to whatever state the machine happens to be in.
- It re-binds to *this* machine, *now*. Run it on a machine whose state you have
  not verified and you have just blessed that state.

## "Not found" and "cannot open" are different

A secret that will not unseal because the platform state changed is **not** a
missing secret. If `get` fails, check whether the platform state changed before
concluding that the name was never stored.

## Is this store actually sealed?

The store does not seal — its backend does. On a `sealed.Backend` values are
protected by the barrier's strategy; on a plain file or memory backend they are
stored as-is, which is right for tests and wrong for production. That is a
server-side configuration question, and `platform status` is the closest the CLI
gets to answering it.

## Exit codes

`0` on success. Non-zero for a missing name, a value that cannot be unsealed in
the current state, or a failed reseal.

## Parity coverage

**Defect: no `platform` verb has a `CommandDefinition` in
`test/integration/api/commands/commands.go`**, despite all six operations having
routes on REST, gRPC, QUIC and Unix.
