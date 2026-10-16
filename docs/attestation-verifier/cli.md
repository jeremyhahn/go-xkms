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
