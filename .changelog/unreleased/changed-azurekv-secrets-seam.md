- **`pkg/backend/azurekv`'s symmetric-key path now goes through an
  injectable `SecretsClient` seam instead of constructing a real
  `*azsecrets.Client` inline, so `GenerateSymmetricKey`/`GetSymmetricKey`
  are unit-testable without live Azure credentials.** Standard-tier Key
  Vault has no oct (symmetric) key type through the Keys API, so these two
  methods (`azurekv_symmetric.go`) generate AES key material locally and
  persist it as a Key Vault secret; `storeSymmetricKeySecret`/
  `retrieveSymmetricKeySecret` previously built their own
  `azidentity`/`azsecrets.NewClient` credential chain on every call, with no
  way to substitute a test double, mirroring the exact gap `KeyVaultClient`
  already closed for the Keys API side of this backend. `SecretsClient`
  lists the two `azsecrets.Client` operations that path calls
  (`SetSecret`/`GetSecret`); `*azsecrets.Client` already satisfies it
  directly, so no wrapper type is needed. `initSecretsClient` mirrors
  `initClient`'s double-checked-locking lazy init, and the new
  `NewBackendWithClients(config, keyClient, secretsClient)` constructor
  injects both clients for tests, alongside the existing
  `NewBackendWithClient` (keys client only). `MockSecretsClient`
  (`mock_client.go`, exported like the existing `MockKeyVaultClient` so it
  is reusable across package boundaries) is an in-memory fake supporting
  injected `SetSecret`/`GetSecret` errors, direct value overrides for
  malformed-data cases, and a call counter. Verified by new tests in
  `pkg/backend/azurekv/azurekv_symmetric_test.go` (happy-path round trip,
  `SetSecret`/`GetSecret` failures, a secret deleted out of band from Key
  Vault, and malformed secret data — a nil value and non-base64 content) and
  by `pkg/seal/cloud_provision_azurekv_test.go`, which proves
  `seal.BuildCloudKMSStrategy`/`EnsureSealKey` provision and reuse the
  barrier's seal key through the real `azurekv.Backend` and complete a
  genuine `SealRootKey`/`UnsealRootKey` round trip, the same proof
  `cloud_provision_awskms_test.go` already gives for AWS KMS. Coverage of
  `azurekv_symmetric.go` rises from 40.9% to 70.1% (package total 77.1% to
  83.2%). go-xkms#1090.
