# Sealing and Barrier — CLI

> **Status: NORMATIVE** · Feature: `sealing-and-barrier` · Repo: `go-xkms` · Last verified: 2026-09-23

Binary: `xkmsctl`. Groups: `barrier` (`cmd/xkmsctl/barrier*.go`), `policy`
(`cmd/xkmsctl/policy.go`), and the top-level `seal` / `unseal` / `can-seal`
data verbs. Global flags: [`../key-management/cli.md`](../key-management/cli.md).

## `xkmsctl barrier status`

No flags. The first command to run when anything is failing — most "broken
server" symptoms are a sealed barrier.

```
xkmsctl barrier status -o json
```

## `xkmsctl barrier init`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--barrier-strategy` | string | `passphrase` | `tpm2`, `pkcs11`, `awskms`, `gcpkms`, `azurekv`, `vault`, `passphrase`, `shamir`, `none` |
| `--passphrase` | string | `""` | for a passphrase strategy |
| `--so-pin` | string | `""` | security-officer PIN |
| `--user-pin` | string | `""` | user PIN |

```
xkmsctl barrier init --barrier-strategy tpm2 --user-pin -
xkmsctl barrier init --barrier-strategy passphrase --passphrase -
```

**This choice is the deployment's security posture, and it is not revisited
automatically.** The library has no preference order and never falls back: a
barrier initialized `passphrase` stays `passphrase` even on a machine with a
TPM. `none` disables barrier encryption entirely.

## `xkmsctl barrier init-shamir`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--threshold` | int | `0` | M — shares needed to unseal |
| `--total` | int | `0` | N — shares produced |
| `--passphrase` | string | `""` | optional |
| `--so-pin` / `--user-pin` | string | `""` | hardware credentials |

```
xkmsctl barrier init-shamir --threshold 3 --total 5
```

The shares are printed once. There is no way to recover a share that was not
recorded.

## `xkmsctl barrier unseal` / `unseal-shares`

| Verb | Flag | Type | Purpose |
|---|---|---|---|
| `barrier unseal` | `--passphrase` | string | passphrase-strategy unseal |
| `barrier unseal-shares` | `--share` | string slice | repeatable: `--share a --share b …` |
| | `--shares-file` | string | read shares from a file |

```
xkmsctl barrier unseal --passphrase -
xkmsctl barrier unseal-shares --share "$S1" --share "$S2" --share "$S3"
xkmsctl barrier unseal-shares --shares-file ./shares.txt
```

For a `tpm2` or cloud strategy, unsealing needs no secret from you — the
hardware or the provider releases the key, assuming the machine is still in the
state it was sealed against.

## `xkmsctl barrier seal`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--so-pin` | string | `""` | authorizing PIN |
| `--assume-yes`, `-y` | bool | `false` | skip confirmation |

Closes the barrier. Everything that needs a key stops working until it is
unsealed again — that is the point, and why it confirms.

## `xkmsctl barrier rekey`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--so-pin` | string | `""` | authorizing PIN |
| `--threshold` | int | `0` | new Shamir M |
| `--total` | int | `0` | new Shamir N |

Generates a new root key and re-seals. Old shares and recovery keys stop
working.

## `xkmsctl barrier recovery`

| Verb | Flags | Purpose |
|---|---|---|
| `recovery generate` | `--threshold`, `--total`, `--so-pin` | Produce recovery keys |
| `recovery recover` | `--share` (repeatable) | Unseal using recovery keys |
| `recovery delete-keys` | — | Destroy the recovery keys |
| `recovery root-token` | `--share` (repeatable) | Generate a root token |

```
xkmsctl barrier recovery generate --threshold 2 --total 3 --so-pin -
xkmsctl barrier recovery recover --share "$R1" --share "$R2"
xkmsctl barrier recovery delete-keys
```

**Recovery keys are a second door into the barrier.** Generating them and then
storing them next to the server is equivalent to not having a barrier at all.
`delete-keys` exists so the door can be closed again.

## `xkmsctl barrier enable-encryption`

Migrates a barrier from `none` to a keyed strategy — or between keyed
strategies.

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--tenant-id` | string | `""` | which barrier; empty = the system barrier |
| `--strategy` | string | — | **required** — keyed target, e.g. `passphrase`, `shamir` |
| `--mechanism` | string | `swap` | `swap` (default) or `in-place` |
| `--availability` | string | `quiesced` | `quiesced` (default) or `online` |
| `--passphrase` | string | `""` | for a passphrase target |
| `--threshold` / `--total` | int | `0` | for a Shamir target |

```
xkmsctl barrier enable-encryption --strategy passphrase --passphrase - \
    --mechanism swap --availability quiesced
```

`--availability online` keeps writes flowing during migration; `quiesced` is the
default and the safer one. `--mechanism in-place` rewrites without a staging
copy — faster, less room for recovery if it is interrupted.

## Data-level sealing

Separate from the barrier: sealing an arbitrary payload with a backend's native
mechanism.

| Verb | Args | Purpose |
|---|---|---|
| `seal <data>` | data | Seal with the backend's mechanism |
| `unseal <ciphertext>` | ciphertext | Unseal |
| `can-seal` | — | Whether the current backend can seal |

```
xkmsctl can-seal --backend tpm2
xkmsctl seal "secret payload" --backend tpm2
```

## `xkmsctl policy`

TPM 2.0 PCR-bank sealed-secret authorization policies (pkg/seal/policy): a
policy captures the values of a set of PCRs in a given bank, and a sealed
secret bound to it can only be unsealed while the platform's PCRs still
match. go-xkms#691 wired every verb onto all five network transports
(REST, gRPC, QUIC, Unix, MCP); previously only REST served it, and a
route/handler parameter mismatch (`{id}` registered, `chi.URLParam(r,
"name")` read) meant every named-policy REST call answered 400 regardless.

| Verb | Args | Flags | Purpose |
|---|---|---|---|
| `policy create <name>` | name | `--bank` (default `sha256`), `--pcrs` (required, comma-separated indices) | Capture current PCR values into a new named policy |
| `policy list` | — | — | List all policies |
| `policy get <name>` | name | — | Show a policy, including its captured PCR values |
| `policy delete <name>` | name | — | Delete a policy |
| `policy refresh <name>` | name | — | Re-capture a policy from current PCR values (after an expected platform change) |
| `policy verify <name>` | name | — | Verify a policy against current PCR values; exits non-zero on mismatch |
| `policy export <name>` | name | `--output` (file path; stdout if omitted) | Export a policy document |

```
xkmsctl policy create boot --pcrs 0,2,4,7
xkmsctl policy create boot --bank sha384 --pcrs 0,7
xkmsctl policy verify boot
xkmsctl policy export boot --output boot-policy.json
```

Authorization is the `policy:*` permission family (`policy:create`,
`policy:get`, `policy:list`, `policy:delete`, `policy:refresh`,
`policy:verify`, `policy:export`) — a resource go-qrdb's canonical registry
does not declare, so xkms mints and scopes it itself
(`pkg/apimodule/module_scopes.go`), the way it already does for
`bootstrap:read`.

## Exit codes

`0` on success. A sealed barrier is not an error from `barrier status` — it is a
reported state. Unseal failures are non-zero and never partial. `policy verify`
is non-zero when the policy no longer matches current PCR values.

## Parity coverage

`CommandDefinition` entries exist for `seal`, `unseal`, `can-seal`, and (as of
go-xkms#691) every `policy` verb.

**Defect:** none of the `barrier` verbs — `status`, `init`, `init-shamir`,
`unseal`, `unseal-shares`, `seal`, `rekey`, the four `recovery` verbs, or
`enable-encryption` — has a definition in
`test/integration/api/commands/commands.go`, despite all of them having routes
on four transports.
