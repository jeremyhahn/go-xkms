- **BREAKING: every xkms-owned TPM 2.0 operation now parents exclusively off
  the Platform SRK, never the TCG-standard Shared SRK, and no Owner-hierarchy
  authorization value is ever read from or written to configuration.**
  `pkg/backend/tpm2.Backend` (its file-backend key blobs, ECDH, KDF,
  attestation and import/export operations), `pkg/tpm2.TPM2`'s generic
  `Seal`/`Unseal` (used by the barrier's `TPM2Strategy` and `PlatformSealer`),
  and the platform keystore's PIN verification all previously fell back to
  `TrustedPlatformModule.SSRKAttributes()` — the well-known, TCG-standard
  Shared SRK (handle `0x81000001`) other TCG-aware software on the same TPM
  expects to find in its default state — whenever the Platform SRK (handle
  `0x81000002`) was unavailable. That fallback is deleted everywhere it
  existed (`pkg/backend/tpm2.resolveSRKAttributes`,
  `pkg/tpm2.defaultSealKeyAttributes`, `defaultUnsealKeyAttributes`, and the
  inline fallback in `TPM2.Unseal`): a Platform SRK that is not enrolled is
  now a typed, wrapped construction/sealing error, never a silent handoff to
  a key xkms does not own. The Shared SRK is still provisioned exactly per
  TCG on every provisioning path (`Provision`, `Install`,
  `provisionSimulatorEKSRK`) so other TCG-aware software sharing the TPM
  finds it in its default state; xkms itself never authorizes with it or
  parents anything under it.

  `pkg/tpm2.PlatformSRKConfig.HierarchyAuth` — added by an earlier pass on
  this same issue — is deleted outright, along with every read of it
  (`PlatformSRKAttributesFromConfig` now always leaves
  `TPMAttributes.HierarchyAuth` unset). The Security Officer PIN, when an
  operator has set one, is never a config literal for either SRK: it reaches
  `TPM2_CreatePrimary`/`TPM2_EvictControl`/`TPM2_HierarchyChangeAuth` only as
  an explicit argument at the moment of the call — the existing `soPIN`
  parameter on `Install`/`Provision`/`ProvisionOwner` for the Shared SRK, and
  the same `soPIN` parameter already threaded through
  `PlatformKeyStore.Initialize`/`EnrollPlatformSRK`/`ensureSRKAuth` for the
  Platform SRK. No SO PIN set means the Owner hierarchy carries empty
  auth — the TCG factory-default state — on both keys. The Platform SRK's
  own authorization value (its object `Password`, distinct from the
  owner-hierarchy auth needed to create or evict it) is, and remains, the
  user PIN supplied the same way through
  `Initialize`/`EnrollPlatformSRK`/`ChangeAuth`/`VerifyAuth`.

  `pkg/backend/tpm2.Config` carries no hierarchy-auth field for either SRK
  (unchanged from the prior pass): a caller needing non-default Owner
  hierarchy behavior supplies a fully-formed `pkgtpm2.Config` via
  `Config.TPMConfig` instead.

  `pkg/tpm2.PlatformSRKConfig.SRKAuth` (a plain `string`, not even a
  `types.SecretValue`) is deleted: no production code path ever read it into
  the Platform SRK's `Password`, so it was a config-literal auth field that
  looked authoritative and was not — exactly what this project's no-config-
  literal-auth rule forbids, whether or not anything acted on it. The only
  source for that `Password` remains the `userPIN` argument to
  `Initialize`/`EnrollPlatformSRK`/`ChangeAuth`.

  The Platform SRK's default configuration (`PlatformSRK.PlatformPolicy:
  true`) binds its own authorization to a `PolicyOR(PolicyPCR,
  PolicyAuthValue)` digest (`TPM2.CreateSRK`), so a session that reproduces
  the golden PCR state can authorize the Platform SRK — and therefore load
  any child sealed under it — without the user PIN, and a session presenting
  the enrolled PIN keeps working after the PCR state moves.
  `TPM2.PlatformSRKAttributes` now takes `PlatformPolicy` from
  `PlatformSRKAttributesFromConfig` — the same function `PlatformKeyStore`
  uses — on **every** path that resolves the Platform SRK, not only when a
  `PlatformKeyStore` is attached to the `TPM2` instance
  (`TPM2.SetPlatformKeyStore`): without this fix, the no-`PlatformKeyStore`
  path (a bare `TPM2.KeyAttributes` read, which has no configuration in
  scope) left `PlatformPolicy` at its Go zero value, so
  `defaultSealKeyAttributes`/`defaultUnsealKeyAttributes` — what
  `TPM2.Seal`/`Unseal` apply by default, which is what the barrier's
  `TPM2Strategy`/`PlatformSealer` use — built a plain password session with
  empty auth bytes instead of a `PlatformPolicySession`, and the TPM
  correctly refused it (`TPM_RC_AUTH_FAIL`) against an enrolled SRK's real,
  non-empty PIN. Configuration is the source of truth on both paths now, so
  an unattended `Seal`/`Unseal` with no `PlatformKeyStore` attached — the
  state an unattended daemon boot is in — reaches the `PolicyPCR` branch
  instead. Both branches are exercised end-to-end against the simulator
  through the default `TPM2.Seal`/`Unseal` API in
  `pkg/tpm2/platform_keystore_enroll_simulator_test.go`
  (`TestEnrollPlatformSRK_DefaultSealUnseal_PCRBranchUnattended`, including
  the negative case where a PCR extend correctly fails the unattended
  unseal, and `TestEnrollPlatformSRK_DefaultSealUnseal_PINBranchViaPlatformKeyStore`).

  `pkg/backend/tpm2.Backend.srkPublicContents` (the wrapping-key read used by
  `WrapKey`/`UnwrapKey`/`ImportKey`) continues to read the backend's own
  configured storage parent (`ReadHandle` against `b.srkAttrs`) instead of
  the TCG-pinned `TrustedPlatformModule.SRKPublic()`. `TPM2.CreateSRK`'s
  diagnostic log continues to log only lengths and presence flags for
  hierarchy and object auth, never the auth bytes themselves. No component
  defaults an auth value to `DEFAULT_PASSWORD`/`"changeme"`.

  Existing deployments: any TPM2-backed key blob xkms created before this
  change is a child of the Shared SRK and will not load under the Platform
  SRK afterward, and any deployment relying on the removed SSRK-fallback
  behavior for sealing will now get a typed error instead. Re-provision
  (enroll the Platform SRK through `PlatformKeyStore.EnrollPlatformSRK`,
  which binds the operator's user PIN) on any TPM with existing
  xkms-created key material before rolling this out.
