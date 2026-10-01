# Password Vault — CLI

> **Status: NORMATIVE** · Feature: `password-vault` · Repo: `go-xkms` · Last verified: 2026-10-01

Binary: `xkmsctl`, group `password` (`cmd/xkmsctl/password.go`). Global flags:
[`../key-management/cli.md`](../key-management/cli.md).

The desktop equivalent is `xkey password …`. It reaches the store differently:
`xkmsctl` always talks to a server, while `xkey` asks the running desktop
daemon over its IPC socket and falls back to the on-disk store, naming which
answered. See
[`xkey/docs/usage/live-state.md`](../../xkey/docs/usage/live-state.md).

## Unlocking

Under the `session_based` access mode your personal entries are unreadable
until you unlock your own session (shared entries need no unlock; the session
is per user, so it neither opens nor closes anyone else's):

```
xkmsctl password unlock --passphrase -
xkmsctl password status -o json
xkmsctl password lock
```

`--passphrase` is your own vault passphrase (not a deployment PIN). It
accepts `-` for stdin and prompts without echo when omitted.

## `password vault`

Your personal entries are sealed with your own key, wrapped under the
factors you enroll. The first enrollment creates the vault, opens your
session and prints a one-time **recovery code**: store it immediately, it is
never shown again.

| Verb | Flags | Does |
|---|---|---|
| `vault status` | | whether your vault exists and is unlocked, your factors (ID, type, label; a key factor's backend, key and fingerprint), and the passkey relying party |
| `vault enroll` | `--passphrase <v\|->`, `--label` | enroll a passphrase; the first enrollment prints the recovery code; later ones need your session unlocked |
| `vault rotate` | `--factor-id`, `--passphrase <v\|->`, `--label` | replace a passphrase with a new one; the old one stops working, your entries are untouched |
| `vault remove` | `--factor-id` | remove a factor; the last unlock factor and the recovery code cannot be removed |
| `vault recover` | `--recovery-code <v\|->`, `--passphrase <v\|->`, `--label` | lost your factors: enroll a new passphrase with the recovery code, which is replaced by a new one (printed once) |

A new passphrase is asked twice when prompted; at most one flag may read
stdin.

**Passkeys.** `--passkey` replaces `--passphrase` on `unlock`,
`vault enroll` and `vault recover`: the factor is a credential on your FIDO2
security key (relying party: the server's `passkey_rp_id`, evaluated with the
WebAuthn prf salt transform -- see
[`architecture.md`](architecture.md#passkey-salt-handling)). The key's PIN is
always required and comes from `--pin-stdin`, `XKMS_FIDO2_PIN`, `--pin`, or a
no-echo prompt; touch the key when asked (twice on enrollment). With more
than one key attached, `--device <hidraw path>` names the one to use, as on
the other FIDO2 verbs; without it the first attached key is used. A passkey
cannot be rotated -- enroll a new one and remove the old one; `vault rotate`
on a passkey says so.

```
xkmsctl password vault enroll --label laptop
xkmsctl password vault status -o json
xkmsctl password vault rotate --factor-id 3fa2c1d09b7e4a55
xkmsctl password vault recover --recovery-code - < code.txt
xkmsctl password vault enroll --passkey --label "yubikey"
xkmsctl password unlock --passkey
```

**Key factors.** `--key-factor certificate|tpm` replaces `--passphrase` on
`vault enroll` and `vault recover`, and `--key` unlocks with one. The factor's
secret is sealed by the server to the key's public half, and xkmsctl recovers
it with the private key, which never leaves its token. Exactly one key source:

| Source | Flags | Notes |
|---|---|---|
| software key (PEM) | `--key-file`, `--cert-file` | e.g. a client certificate's key; a `certificate` factor needs `--cert-file`, and it must be the key's |
| TPM 2.0 | `--tpm-device` (a device, or `tcp://host:port` for a TPM over TCP such as swtpm), `--tpm-data-dir <dir>`, `--key-id`, `--tpm-create`, `--tpm-policy` | `--tpm-data-dir` holds the TPM's key store (`tpm/`) and named-policy registry (`tpm-policies/`, `tpm-keys/`) -- the layout of xkey's data directory, so pointing it there shares xkey's keys and policies. `--tpm-create` makes the key under `--tpm-policy`: `platform` (the default) or a named policy in that registry, e.g. one made with `xkey tpm policy create`; the registry records the key against the policy, so the policy cannot be deleted under it |

**PIV cards and PKCS#11 tokens are xkey's.** xkmsctl is built without CGO, so
it has no PKCS#11 and there is no PKCS#11 build of it: `--key-factor piv`
answers `ErrVaultKeyNeedsXkey` ("use xkey for PIV/PKCS#11 factors"). Enroll
and unlock those factors with `xkey password vault enroll --key-factor piv`
or the xkey app; a factor enrolled there unlocks the same vault.

Before enrolling, xkmsctl seals a throwaway secret to the token's own key and
opens it; a token that cannot (`vaulttoken.SelfTest`) is refused and nothing
is enrolled.

```
xkmsctl password vault enroll --key-factor certificate --key-file client.key --cert-file client.pem
xkmsctl password unlock --key --key-file client.key
xkmsctl password vault enroll --key-factor tpm --tpm-data-dir ~/.xkmsctl/tpm --key-id vault --tpm-create
xkmsctl password vault enroll --key-factor tpm --tpm-data-dir ~/.xkey --key-id vault-boot --tpm-create --tpm-policy boot
xkmsctl password unlock --key --tpm-data-dir ~/.xkmsctl/tpm
```

## `password add <name>`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--password` | string | `""` | value; `-` reads stdin; prompted when omitted |
| `--username` | string | `""` | associated username |
| `--url` | string | `""` | associated URL |
| `--notes` | string | `""` | free-form notes |
| `--folder` | string | `""` | folder path |
| `--expires-at` | string | `""` | RFC 3339 |
| `--tenant-id` | string | `""` | tenant scope |
| `--shared` | bool | `false` | share with the tenant |

```
xkmsctl password add "upstream-portal" --username ops@example.com \
    --url https://portal.example.com --folder infra --password -
```

Omit `--password` and it prompts. `-` reads stdin. A literal value goes into
shell history.

**`--notes` reaches durable storage.** It is where people put "the other
password"; do not.

## `password get <id>`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--tenant-id` | string | `""` | tenant scope |

```
xkmsctl password get pw-123 -o json
```

The store must be unlocked first (`password unlock`); the entry, including the
password field, comes back exactly as stored
(`pkg/xkms/servicer_password.go:168`). There is no per-request decrypt option:
confidentiality at rest is provided by the tenant barrier, not by a decryption
step on `get`, and every store reachable through this servicer
(`staticpw.BackendStore`, `staticpw.ScopedStore`, `staticpw.DAOStore`) returns
entries the same way. `xkmsctl` never accepted a `--decrypt` or `--user-pin`
flag on `get`; earlier revisions of this page described one, but the servicer
never implemented it (removed in #1061).

## `password list`

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--folder` | string | `""` | filter by folder |
| `--tenant-id` | string | `""` | tenant scope |
| `--scope` | string | `""` | `own`, `shared`, or `all` |

```
xkmsctl password list --folder infra --scope all -o json
```

Listing never returns plaintext.

## `password update <id>`

`--name`, `--username`, `--password` (`-` for stdin; empty prompts), `--url`,
`--notes`, `--folder`, `--expires-at`, `--tenant-id`.

```
xkmsctl password update pw-123 --password - --expires-at 2027-01-01T00:00:00Z
```

## `password delete <id>`

`--tenant-id`.

## `password access-mode <mode>`

```
xkmsctl password access-mode session_based
```

`session_based` is the only mode that can actually take effect: the mode is
fixed by how the store was set up when the server started
(`pkg/staticpw/access.go:17`-`26`). Requesting the mode already in force
succeeds; requesting `pin_per_operation` against a `session_based` store
fails rather than silently doing nothing.

- **`session_based`** — unlock once, read your personal entries freely until
  you lock. Anything that can act as you while your session is unlocked can
  read them. `password lock` when you are done.

## `password generate`

| Flag | Type | Default |
|---|---|---|
| `--length` | int | `0` — server default |

```
xkmsctl password generate --length 32
```

## `password status`

Works while locked — that is the point. Reports whether your own session is
unlocked, whether the tenant barrier is sealed, how many entries you can read
now, and which access mode is in force.

## Exit codes

`0` on success. Non-zero for a locked session, a missing or wrong credential, or an
unknown ID. An entry outside your scope reports as **not found**, not
forbidden — so a 404 here is not proof the entry does not exist somewhere.

## Parity coverage

**Defect: no `password` verb has a `CommandDefinition` in
`test/integration/api/commands/commands.go`**, despite all ten operations having
routes on REST, gRPC, QUIC, Unix **and** MCP — the password surface is one of
only three features with complete MCP coverage, and none of it is in the parity
runner.
