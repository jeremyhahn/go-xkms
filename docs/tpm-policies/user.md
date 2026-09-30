# TPM Policies — User Guide

> **Status: NORMATIVE** · Feature: `tpm-policies` · Repo: `go-xkms` · Last verified: 2026-09-30

A TPM policy names a platform state — a set of PCRs and their values — that
many TPM keys and sealed objects share. The TPM refuses to use a key bound to
a policy unless the platform is in the approved state or the key's password
is presented.

1. Enable the TPM2 backend (`backends.tpm2.enabled: true`). The TPM policy
   service starts with it.
2. Create a policy over the current state:
   `xkmsctl tpm policy create boot --pcrs 0,7`.
3. Bind keys to it: `xkmsctl --backend tpm2 key generate signer --key-type
   signing --key-algorithm ecdsa --tpm-policy boot`. A key created without
   `--tpm-policy` is bound to the built-in `platform` policy.
4. After an expected change (a firmware or kernel update), re-approve the new
   state: `xkmsctl tpm policy update boot`. No key is re-created.
5. To stop every key bound to a policy from working without its password,
   `xkmsctl tpm policy revoke boot`; `update` approves it again.
6. A policy can be deleted only when nothing is bound to it;
   `xkmsctl tpm policy objects boot` lists what is.

Tenants: each tenant has its own policies and keys. The system administrator
chooses a tenant's TPM mode with `xkmsctl tenant tpm-mode <tenant>
none|shared|vtpm`; a mode can change only while the tenant has no TPM keys,
sealed objects or policies.

## Rotating keys

Any key -- a TPM2 key included -- rotates the same way: `xkmsctl key rotate
<id>` creates a new version with the same algorithm, attributes and, for a TPM2
key, the same tenant scope and TPM policy, and makes it current. Nothing
referring to the key changes.

1. Sign and encrypt switch to the new version at once. The response reports
   it as `key_version`.
2. Older versions stay enabled, so signatures and ciphertext they produced
   still verify and decrypt without naming a version. AES-CBC and RSA
   PKCS#1 v1.5 ciphertext is the exception: once a key has two enabled
   versions, pass the `key_version` the encrypt reported
   (`xkmsctl key decrypt ... --key-version 1`). Keep it with the ciphertext.
3. `xkmsctl key versions <id>` shows every version. When nothing needs an old
   version any more, disable it (`key version disable <id> <n>`, reversible)
   or retire it (`key version retire <id> <n>`, which deletes it for good).
   The current version cannot be disabled or retired.
4. `xkmsctl key rotate-all` rotates every key of your tenant at once.
5. Deleting a key deletes all its versions.

A key ID may not end in `--v` followed by digits: that suffix names versions.

## xKey

The xKey desktop app manages the same policies — on its connected server, or,
without one, on the machine's own TPM.

1. **TPM → Policies** lists the built-in `platform` policy and every named
   policy with the number of keys and sealed objects bound to it (click the
   number to see them). The panel says whether it is showing the local TPM
   or the connected server.
2. **Create Policy**: give it a name, choose the PCR bank and tick the PCRs.
   The values are read from the TPM. `xkey tpm policy create boot --pcrs 0,7`
   does the same from the CLI.
3. **Sealed Data → Seal New Data**: choose the TPM policy (the built-in
   platform policy by default, a named policy, or none) and, optionally, a
   password. With a policy and a password, the password still unseals the
   data after the platform state changes.
4. **Barrier auto-unseal**: switch on a policy's *Auto-unseal* toggle (or use
   Settings → Storage → Barrier Auto-Unseal) and enter the barrier password
   once. At startup the TPM releases it only while the platform is in the
   state the policy approves; otherwise xKey asks for the password. From the
   CLI: `xkey tpm policy auto-unseal boot`.
5. After a trusted firmware or kernel update, **Verify** shows which PCRs
   changed and **Update** re-approves the policy; nothing is re-sealed or
   re-keyed. **Revoke** stops every object bound to the policy from opening
   without its password.
6. **Delete** is refused, listing the objects, while anything — the barrier
   auto-unseal password included — is bound to the policy.
7. **Rotate Authority** replaces the TPM-resident key that approves the
   policies; every policy is re-approved and nothing is re-keyed.
