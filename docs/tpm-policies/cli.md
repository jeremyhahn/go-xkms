# TPM Policies — CLI

> **Status: NORMATIVE** · Feature: `tpm-policies` · Repo: `go-xkms` · Last verified: 2026-10-17

`xkmsctl` calls the API in [`api.md`](api.md) over any configured transport.
`--tenant <id>` addresses another tenant's scope (system callers only; the
default is the caller's own). `--owner-auth` is the physical TPM's
owner-hierarchy authorization, needed only when the owner hierarchy has one;
`--owner-auth -` reads it from standard input.

| Command | Flags | Purpose |
|---|---|---|
| `tpm policy create <name>` | `--pcrs` and `--bank` (`sha256`), or `--branch` (repeatable); `--description`, `--auto-unseal`, `--owner-auth`, `--tenant` | Create a policy; the values of its pcr conditions are read from the TPM |
| `tpm policy describe <name> <text>` | `--tenant` | Replace the policy's description (`""` clears it) |
| `tpm policy list` | `--tenant` | List policies |
| `tpm policy get <name>` | `--tenant` | Show a policy, its branches with their PCR values, and approval |
| `tpm policy update <name>` | `--branch <name>` with `--reference-values <corim>`, `--tenant` | Re-capture and re-approve after an expected platform change; with `--branch`, approve only that branch for the PCR values a signed CoRIM predicts, before the change |
| `tpm policy revoke <name>` | `--tenant` | Withdraw the approval |
| `tpm policy verify <name>` | `--tenant` | Compare each branch with the live PCRs; exits non-zero on a mismatch or no approval |
| `tpm policy delete <name>` | `--owner-auth`, `--tenant` | Delete a policy; refused while objects use it |
| `tpm policy objects <name>` | `--tenant` | List the keys and sealed objects bound to it |
| `tpm policy auto-unseal <name>` | `--disable`, `--tenant` | Mark (or unmark) the policy barrier auto-unseal uses |
| `tpm authority rotate` | `--tenant` | Rotate the tenant's policy authority |
| `key generate <id> --tpm-policy <name>` | | Create a TPM2 key bound to a policy (default `platform`) |
| `key policy <id>` | `--sealed`, `--tenant` | Show the policy a key (or sealed object) was created under |
| `seal <data> --tpm-policy <name>` | `--password`, `--key-id` | Seal a TPM2 object bound to a policy; prints `tpm_public`, `tpm_private` and `key_id` |
| `unseal --tpm-public <b64> --tpm-private <b64>` | `--password`, `--key-id` | Unseal a TPM2 sealed object |
| `tenant tpm-mode <id> [none\|shared\|vtpm]` | `--owner-auth` | Show or set a tenant's TPM mode (system only) |
| `tenant vtpm status\|start\|stop <id>` | | A vtpm-mode tenant's virtual TPM (system only) |

### Branches

`--pcrs 0,7 [--bank sha384]` creates the common policy: one branch holding
one pcr condition. `--branch` gives a branch explicitly, once per branch,
branches tried in order; it cannot be combined with `--pcrs` or `--bank`. A
branch is an optional `name=NAME` and conditions, joined by `;`:

| Element | Meaning |
|---|---|
| `name=NAME` | The branch's name: 1-64 letters, digits, `.`, `_` or `-`, unique within the policy; `branch-N` (N counted from 1) when omitted. `update --branch` and `verify` name branches this way |
| `pcr=[BANK:]LIST` | The PCRs in `LIST` of `BANK` (`sha256` when omitted) hold the values captured at create or update |
| `auth_value` | The object's password is presented |
| `locality=LIST` | The command comes from one of the TPM localities (0-4) in `LIST` |

`LIST` is comma-separated indices or ranges (`0,7`, `0-7`). A branch has at
most one condition of each kind. A key or sealed object bound to a policy
with `auth_value` needs a password.

```
xkmsctl tpm policy create boot --pcrs 0,7 --description "firmware and Secure Boot"
xkmsctl tpm policy create boot-or-pin --branch 'pcr=sha256:0,7' --branch auth_value
xkmsctl tpm policy create strict --branch 'pcr=sha256:0,7;auth_value;locality=0'
xkmsctl tpm policy describe boot "firmware, Secure Boot and the boot loader"
xkmsctl --backend tpm2 key generate signer --key-type signing --key-algorithm ecdsa --tpm-policy boot
xkmsctl tpm policy objects boot
xkmsctl key policy signer
xkmsctl tpm policy update boot          # after a firmware or kernel update
xkmsctl tenant tpm-mode acme vtpm
```

A platform update without a window where nothing unseals uses two branches,
`current` and `next`: approve `next` for the new image's signed reference
values before the update, then `current` after it.

```
xkmsctl tpm policy create unlock --branch 'name=current;pcr=0,7' --branch 'name=next;pcr=0,7'
xkmsctl tpm policy update unlock --branch next --reference-values image-v2.corim
xkmsctl tpm policy verify unlock       # each branch by name, with the reference values it is approved for
```

`xkmsctl policy` (the PCR snapshot store) was removed with `pkg/seal/policy`;
`refresh` and `export` have no successor.

## Key versions

`--backend` names the key's backend, as for every `key` command.

| Command | Flags | Purpose |
|---|---|---|
| `key rotate <id>` | | Create the key's next version and make it current; prints the new version, and warns when the key has a certificate to re-issue |
| `key rotate-all` | `--tenant` | Rotate every key of the caller's tenant (or, for a system caller, `--tenant`); lists each key's state (`rotated`, `skipped` with the reason, `failed` with the error) and exits non-zero if any key failed |
| `key versions <id>` | | List the versions: number, state, current, created at and by |
| `key version enable <id> <n>` | | Enable a disabled version |
| `key version disable <id> <n>` | | Disable a version; refused for the current one |
| `key version retire <id> <n>` | | Delete a version's key material for good; refused for the current one |
| `key version enable-all <id>` | | Enable every disabled version |
| `key version disable-all <id>` | | Disable every version but the current one |
| `key verify <id> <data> <sig>` | `--key-version` | Verify with that version (default: every enabled version); prints the version that verified |
| `key decrypt <id> <ct>` | `--key-version` | Decrypt with that version (required for AES-CBC and RSA PKCS#1 v1.5 once a key has several enabled versions) |

`key sign` and `key encrypt` always use the current version; `-o json` (and,
for `key encrypt`, the text output) reports it as `key_version`. A TPM2 key
rotates into the same tenant scope and TPM policy.

```
xkmsctl --backend tpm2 key rotate signer
xkmsctl --backend tpm2 key versions signer
xkmsctl --backend tpm2 key version disable signer 1
xkmsctl key rotate-all --tenant acme
```

## xKey

`xkey tpm policy` offers the same operations on the xKey desktop app's CLI.
With `--xkmsd-url` (or `XKMSD_URL`, or `xkmsd.address` in the xkey config)
it calls the server through the transport client; otherwise it runs the
same service in-process over the host's own TPM, in the system scope, with
the registry in the xKey data directory (`<data dir>/tpm-policies`, shared
with the GUI). The `tpm` group's `--device`, `--simulator`,
`--hierarchy-auth` (the owner password, when the owner hierarchy has one)
and `-o json` apply.

| Command | Flags | Purpose |
|---|---|---|
| `xkey tpm policy create <name>` | `--pcrs` and `--bank` (`sha256`), or `--branch` (repeatable, the grammar above); `--description`, `--auto-unseal` | Create a policy; locally, `--auto-unseal` also seals the barrier password under it |
| `xkey tpm policy describe <name> <text>` | | Replace the policy's description |
| `xkey tpm policy list` | | Policies with their object counts; the built-in `platform` first |
| `xkey tpm policy get <name>` | | A policy, its branches with their captured PCR values, and approval |
| `xkey tpm policy update <name>` | `--branch <name>` with `--reference-values <corim>` | Re-capture and re-approve (no re-key); with `--branch`, approve only that branch from a signed CoRIM (server mode; local mode configures no reference signer) |
| `xkey tpm policy revoke <name>` | | Withdraw the approval |
| `xkey tpm policy verify <name>` | | Compare with the live PCRs; exits non-zero when not satisfied |
| `xkey tpm policy delete <name>` | | Refused, listing them, while objects are bound |
| `xkey tpm policy objects <name>` | | Keys and sealed objects bound to the policy (`platform` included) |
| `xkey tpm policy key <key-id>` | | The policy a TPM key was created under |
| `xkey tpm policy auto-unseal <name>` | `--off` | Locally: make it the auto-unseal policy and seal the barrier password under it (read from the terminal or piped stdin); `--off` clears it and deletes the sealed password. On a server: set the mark |
| `xkey tpm authority rotate` | | Rotate the scope's policy authority |

```
xkey tpm policy create boot --pcrs 0,7
xkey tpm policy create boot-or-pin --branch 'pcr=0,7' --branch auth_value
echo "$BARRIER_PASSWORD" | xkey tpm policy auto-unseal boot
xkey tpm policy verify boot || xkey tpm policy update boot    # after a trusted firmware update
xkey --xkmsd-url grpcs://kms.example.com:9443 tpm policy list
```

`xkey policy` (xKey's former PCR snapshot store, with `refresh`, `export`,
`set-auto-unseal` and `clear-auto-unseal`) was removed; `update` replaces
`refresh`, and `export` has no successor.
