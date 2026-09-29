# TPM Policies — CLI

> **Status: NORMATIVE** · Feature: `tpm-policies` · Repo: `go-xkms` · Last verified: 2026-09-29

`xkmsctl` calls the API in [`api.md`](api.md) over any configured transport.
`--tenant <id>` addresses another tenant's scope (system callers only; the
default is the caller's own). `--owner-auth` is the physical TPM's
owner-hierarchy authorization, needed only when the owner hierarchy has one;
`--owner-auth -` reads it from standard input.

| Command | Flags | Purpose |
|---|---|---|
| `tpm policy create <name>` | `--pcrs` (required), `--bank` (`sha256`), `--auto-unseal`, `--owner-auth`, `--tenant` | Create a policy over the TPM's live PCR values |
| `tpm policy list` | `--tenant` | List policies |
| `tpm policy get <name>` | `--tenant` | Show a policy, its PCR values and approval |
| `tpm policy update <name>` | `--tenant` | Re-capture and re-approve after an expected platform change |
| `tpm policy revoke <name>` | `--tenant` | Withdraw the approval |
| `tpm policy verify <name>` | `--tenant` | Compare with the live PCRs; exits non-zero on a mismatch or no approval |
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

```
xkmsctl tpm policy create boot --pcrs 0,7
xkmsctl --backend tpm2 key generate signer --key-type signing --key-algorithm ecdsa --tpm-policy boot
xkmsctl tpm policy objects boot
xkmsctl key policy signer
xkmsctl tpm policy update boot          # after a firmware or kernel update
xkmsctl tenant tpm-mode acme vtpm
```

`xkmsctl policy` (the PCR snapshot store) was removed with `pkg/seal/policy`;
`refresh` and `export` have no successor.

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
| `xkey tpm policy create <name>` | `--pcrs` (required), `--bank` (`sha256`), `--auto-unseal` | Create a policy over the live PCR values; locally, `--auto-unseal` also seals the barrier password under it |
| `xkey tpm policy list` | | Policies with their object counts; the built-in `platform` first |
| `xkey tpm policy get <name>` | | A policy, its captured PCR values and approval |
| `xkey tpm policy update <name>` | | Re-capture and re-approve (no re-key) |
| `xkey tpm policy revoke <name>` | | Withdraw the approval |
| `xkey tpm policy verify <name>` | | Compare with the live PCRs; exits non-zero when not satisfied |
| `xkey tpm policy delete <name>` | | Refused, listing them, while objects are bound |
| `xkey tpm policy objects <name>` | | Keys and sealed objects bound to the policy (`platform` included) |
| `xkey tpm policy key <key-id>` | | The policy a TPM key was created under |
| `xkey tpm policy auto-unseal <name>` | `--off` | Locally: make it the auto-unseal policy and seal the barrier password under it (read from the terminal or piped stdin); `--off` clears it and deletes the sealed password. On a server: set the mark |
| `xkey tpm authority rotate` | | Rotate the scope's policy authority |

```
xkey tpm policy create boot --pcrs 0,7
echo "$BARRIER_PASSWORD" | xkey tpm policy auto-unseal boot
xkey tpm policy verify boot || xkey tpm policy update boot    # after a trusted firmware update
xkey --xkmsd-url grpcs://kms.example.com:9443 tpm policy list
```

`xkey policy` (xKey's former PCR snapshot store, with `refresh`, `export`,
`set-auto-unseal` and `clear-auto-unseal`) was removed; `update` replaces
`refresh`, and `export` has no successor.
