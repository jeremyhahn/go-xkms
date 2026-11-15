# Attestation Verifier — CLI

> **Status: NORMATIVE** · Feature: `attestation-verifier` · Module: `go-xkms` · Last verified: 2026-10-15

No `xkmsctl` surface. `pkg/attestation`'s `Verifier`/`VerifyInvariants` run
server-side, automatically, whenever a CSR carries attestation fields
(`AttestationFormat`/`AttestationChain`/`AttestationNonce`) — there is no
`xkmsctl` verb that invokes verification directly, and no flag that changes
how it runs. Verified: no reference to `attestation.Verifier`,
`attestation.NewVerifier`, `attestation.VerifyInvariants` or
`SetAttestationVerifiers` exists anywhere under `cmd/xkmsctl/`.

xkey's verbs reach the same `Verifier` through the SDK aliases in
`sdk/go/attestation_verifier.go` (`NewAttestationVerifier` with
`WithAttestationTrustStore`). See [`architecture.md`](architecture.md)
§"Purpose-pooled checks". The calls are:

- `xkey device attest` (`xkey/cmd/xkey/cmd/device_attest.go:260`) builds
  the Android hardware pool;
- `xkey device enroll-phone`
  (`xkey/cmd/xkey/cmd/device_enroll_phone_ca.go:73`) does the same;
- `xkey tpm ek show` (`xkey/cmd/xkey/cmd/tpm_ek.go:401`) verifies the EK
  certificate.

Two related but distinct CLI surfaces exist, neither of which is this
feature:

- **Generating** an attestation statement is `xkmsctl key attest <key-id>`,
  documented in [`../key-management/cli.md`](../key-management/cli.md) — it
  calls a backend's `AttestKey`, not anything in this package.
- **Configuring** the trust anchors this feature verifies against is a
  server-config change (`attestation.formats.<format>` in the xkmsd YAML),
  not a CLI verb — see [`engineering.md`](engineering.md) §"Configuration".
  There is no `xkmsctl` command that edits it; it takes effect on server
  restart, wired in `pkg/server/server.go:916-926`.

## Repository signing keys

`xkmsctl key signing-key` (`cmd/xkmsctl/key_signing_key.go`) names the key
that signs a repository's images and CoRIMs (#2190). A tenant may bind a
different key to each repository; the tenant's release key signs every
repository it has not bound. Each verb acts on the caller's tenant and calls
the sdk/go client method named below; `-o json` prints the response as JSON.

| Verb | Usage | Client call | Permission |
|---|---|---|---|
| sign | `xkmsctl key signing-key sign <repository> <corim-file> [--signer <name>] [--out <file>]` | `SignReleaseCoRIM` | `attestation_signing_keys:sign` |
| set | `xkmsctl key signing-key set <repository> <key-id> [--key-backend <b>]` | `SetSigningKeyBinding` | `attestation_signing_keys:bind` |
| get | `xkmsctl key signing-key get <repository>` | `GetSigningKeyBinding` | `attestation_signing_keys:get` |
| list | `xkmsctl key signing-key list` | `ListSigningKeyBindings` | `attestation_signing_keys:list` |
| delete | `xkmsctl key signing-key delete <repository>` | `DeleteSigningKeyBinding` | `attestation_signing_keys:bind` |
| resolve | `xkmsctl key signing-key resolve <repository>` | `ResolveSigningKey` | `attestation_signing_keys:get` |

`sign` sends the unsigned CoRIM to the server, which signs it (COSE_Sign1)
with the key `resolve` names. With `--out` it writes the signed CoRIM to that
file (mode 0600); without it, it prints the key id and the signed CoRIM in
base64 (`printReleaseCoRIM`). `--signer` sets the corim-meta signer name and
defaults to the repository. `set` without `--key-backend` binds the key on the
tenant's default backend. `resolve` marks the release key when the repository
has no binding (`printSigningKeyResolution`).
