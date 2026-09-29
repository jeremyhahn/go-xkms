# TPM Policies — User Guide

> **Status: NORMATIVE** · Feature: `tpm-policies` · Repo: `go-xkms` · Last verified: 2026-09-29

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
