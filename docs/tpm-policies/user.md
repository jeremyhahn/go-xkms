# TPM Policies — User Guide

> **Status: NORMATIVE** · Feature: `tpm-policies` · Repo: `go-xkms` · Last verified: 2026-10-17

A TPM policy names the conditions under which many TPM keys and sealed objects
may be used. The common one is a platform state — a set of PCRs and their
values. The TPM refuses to use a key bound to a policy unless the policy is
satisfied, or the key's password is presented (for a policy with no password
condition of its own).

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

## Combining conditions

A policy can combine conditions. It is one or more *branches*; an object is
usable when **any** branch holds, and a branch holds when **all** of its
conditions do:

- **PCR values** — the selected PCRs hold the approved values;
- **password** — the object's password is presented;
- **locality** — the command comes from one of the chosen TPM localities.

```
# PCRs 0 and 7, or the object's password
xkmsctl tpm policy create boot-or-pin --branch 'pcr=sha256:0,7' --branch auth_value
# PCRs 0 and 7 and the password, from locality 0
xkmsctl tpm policy create strict --branch 'pcr=sha256:0,7;auth_value;locality=0'
```

- A key or sealed object bound to a policy with a password condition must
  have a password. That password then counts only inside the policy: it
  cannot bypass a "PCRs **and** password" branch on its own.
- Every branch has a name: give one with `name=` in the branch
  (`--branch 'name=current;pcr=0,7'`), or it is named `branch-1`,
  `branch-2`, ... in order.
- The branches are fixed at creation. `update` re-captures the PCR values of
  every branch; a different structure is a new policy.
- `verify` reports every branch by name: whether its PCRs still match,
  whether it is approved, and the signed reference values it was approved for.

## Updating without a lockout

A platform update changes the PCR values, so a policy over the old values
would refuse the updated platform until someone re-approves it. With a branch
for the running image and one for the next, the update never locks objects
out:

1. Create the policy with two branches:
   `xkmsctl tpm policy create unlock --branch 'name=current;pcr=0,7' --branch 'name=next;pcr=0,7'`.
2. Before the update, approve `next` for the new image from the signed
   reference values (a CoRIM) its provider publishes:
   `xkmsctl tpm policy update unlock --branch next --reference-values image-v2.corim`.
   The server accepts only a CoRIM signed by its configured reference signer
   (`backends.tpm2.reference_signer`). Both the old and the new image now
   satisfy the policy.
3. `xkmsctl tpm policy verify unlock` shows `next` approved for `image-v2`.
4. After the update, approve `current` the same way; the next update reuses
   `next`.
- Every policy can carry a description:
  `xkmsctl tpm policy create boot --pcrs 0,7 --description "..."`, and
  `xkmsctl tpm policy describe boot "..."` to change it.

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
4. `xkmsctl key rotate-all` rotates every key of your tenant at once. It
   skips, and says why, keys that would not benefit: PIV slot keys, TPM2
   sealed objects and the barrier's seal key (each is used by its exact name,
   so a new version would never be used), and keys with a certificate (the
   certificate would stay on the old version). Rotate a certified key alone
   with `key rotate <id>` — which warns that the certificate must be
   re-issued — then re-issue the certificate for the new version.
5. Deleting a key deletes all its versions.

A key ID may not end in `--v` followed by digits: that suffix names versions.

## xKey

The xKey desktop app manages the same policies — on its connected server, or,
without one, on the machine's own TPM.

1. **TPM → Policies** lists the built-in `platform` policy and every named
   policy with the number of keys and sealed objects bound to it (click the
   number to see them). The panel says whether it is showing the local TPM
   or the connected server.
2. **Create Policy**: give it a name and, optionally, a description. In
   **Simple** mode choose the PCR bank and tick the PCRs. In **Advanced** mode
   add branches, each with an optional name (such as `current` and `next`)
   and any of PCR values, the object password and TPM localities (0-4). The
   PCR values are read from the TPM. A policy's details list its branches by
   name; picking a CoRIM file under a branch updates that branch from signed
   reference values, like `--branch <name> --reference-values`.
   `xkey tpm policy create boot --pcrs 0,7` (or `--branch ...`) does the same
   from the CLI. **Describe** changes a policy's description.
3. **Sealed Data → Seal New Data**: choose the TPM policy (the built-in
   platform policy by default, a named policy, or none) and, optionally, a
   password. With a policy and a password, the password still unseals the
   data after the platform state changes.
4. **Barrier auto-unseal**: switch on a policy's *Auto-unseal* toggle (or use
   Settings → Storage → Barrier Auto-Unseal) and enter the barrier password
   once. At startup the TPM releases it only while the platform is in the
   state the policy approves; otherwise xKey asks for the password. From the
   CLI: `xkey tpm policy auto-unseal boot`.
5. After a trusted firmware or kernel update, **Verify** shows, per branch,
   which PCRs changed and **Update** re-approves the policy; nothing is re-sealed or
   re-keyed. **Revoke** stops every object bound to the policy from opening
   without its password.
6. **Delete** is refused, listing the objects, while anything — the barrier
   auto-unseal password included — is bound to the policy.
7. **Rotate Authority** replaces the TPM-resident key that approves the
   policies; every policy is re-approved and nothing is re-keyed.
