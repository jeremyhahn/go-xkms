# Proposed SPEC row: sdk-xkey-surface (for row #2084, PR #2107)

Codex P1 on PR #2107 (round 1): docs/SPEC.md:180 requires that a surface
sdk/go lacks becomes an sdk/go row. The additions below need that row,
owner-approved, before the xkey migration lands. docs/SPEC.md is a protected
path for lanes (policy-guard), so the row is proposed here for the owner to
add to the Features table (alphabetical, before sealing-and-barrier).

## Proposed row

| sdk-xkey-surface | in progress | The sdk/go surface xkey's tests need so
they import no root pkg/* (row xkey-sdk-only, issue #2084). Every addition is
a type alias, constant or variable bound to the root symbol, never a wrapper,
so errors.Is/errors.As and type identity hold across the SDK boundary. |
none |

## Requirements (surfaces)

- sdk/go: ProvisionTPMFresh, NewTPMMemoryCertStore, TPMNVOwnerIndexFirst/Last
  (tpm.go); ErrTPMSimulatorNotAvailable (!tpm_simulator,
  tpm_simulator_stub.go); NewOIDCCredentialService, OIDCCredentialBarriers,
  OIDCCredentialRegistryBarriers (oidc.go); StorageCompareAndSwapper,
  StorageCompareAndDeleter (storage.go); ErrCAProfileNotFound,
  ErrPKCS11SessionPoolLogin, PIVStorageError, PivSlotCN, TOTPPolicyAuto.
- sdk/go/fido2: ErrNoDeviceFound. fido2/authenticator: state, handlers,
  MemoryStorage, DefaultConfig, command codes, sentinel errors.
  fido2/keybackend: attestation OU, AAGUID extension, errors. fido2/uhid:
  MaxReportDescriptorSize, create2/input2 serializers, errors.
- sdk/go/oidc: TokenEncodingJSON, CodexAuthModeChatGPT, RedirectURLError,
  CallbackHostError, token-encoding and codex-auth errors.
- sdk/go/pairingproto: fragment flags, attest constants,
  ComputeAttestChannelBinding, IsLocalMethod, errors.
- sdk/go/truststore: CertMetadata, OSCertStore, ClassifyCertificate, errors.
- sdk/go/xkmstest (test-only): SecretLiteral, RunWithEnclaveBudget, vault
  fixtures, NewBarrierRegistry, OutsideFIPS, OutsideFIPSAfterRefusal.

## Acceptance

- Each addition has a reexport test pinning identity to the root symbol
  (reflect.TypeFor for types, errors.Is for sentinels, equality for
  constants): sdk/go/*_reexport_test.go, storage_compare_test.go,
  tpm_simulator_stub_test.go, sdk/go/*/reexport_test.go,
  xkmstest/xkmstest_test.go. These are on the branch.
- The exported-API growth gate passes.

## Out of scope

New behaviour in pkg/*; an sdk/go test-server surface for
xkmsd_harness_test.go (its own row if needed).
