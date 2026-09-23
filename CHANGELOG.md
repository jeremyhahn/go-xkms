# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.17.0-alpha] - 2026-09-22

### Security

- **FIPS 140 algorithm enforcement, and FIPS 140 mode detection itself, are now the Go standard library's job; go-xkms keeps no approved-algorithm allowlist and no second copy of the mode signal (#21). BREAKING for anything reading `pkg/crypto/fips.ApprovedAlgorithm` / `AlgorithmPermitted` / `Compiled` / `Enabled` / `EnvGOFIPS140`, `sdk/go.FIPSMode` / `FIPSEnabled`, or relying on `GOFIPS140` set as a plain runtime environment variable to activate FIPS behaviour.** `pkg/crypto/fips`'s `approvedAlgorithms` table, `ApprovedAlgorithm`, and `AlgorithmPermitted` (including the `builtFunc` indirection #219 added for it) are deleted along with every call site: `pkg/validation.isValidAlgorithm` and `pkg/xkms/keyid.validateAlgorithm` are now grammar checks only — is `algo` a spelling the package recognizes — never a FIPS policy decision.

  Enforcement now happens where the algorithm actually runs. Under `GODEBUG=fips140=only`, or a binary built with an enabling `GOFIPS140`, the standard library crypto package that implements an algorithm refuses it on its own — `crypto/ecdh` already refused X25519 this way before this change, and `crypto/mldsa`, added in this change, refuses ML-DSA the same way under a build selecting the FIPS 140-3 Go Cryptographic Module v1.0.0 (which predates ML-DSA support). A key ID naming `chacha20-poly1305`, `x448`, or a `frost-*` ciphersuite — algorithms the grammar accepts but no backend in this repository currently wires up, or (for ChaCha20) whose own FIPS posture is already handled where it is selected, in `pkg/crypto/aead.SelectOptimal` — now validates in FIPS mode where it previously did not; the downstream crypto call for a wired algorithm still refuses exactly as before.

  **`pkg/crypto/fips.Compiled` and `Enabled` are also deleted, along with `EnvGOFIPS140`, `sdk/go`'s re-exports `FIPSMode`/`FIPSEnabled` (the file is removed), and `pkg/pkcs11/module`'s `fipsEnvForTest` constant. Every caller now calls `crypto/fips140.Enabled()` directly.** `Compiled` was `crypto/fips140.Enabled()` under another name; `Enabled` read `os.Getenv("GOFIPS140")` as a runtime policy switch, but `GOFIPS140` is exclusively a `go build`/`go test -c` selector the toolchain records into the binary at link time — the Go runtime never reads it as a process environment variable, unlike `GODEBUG`. Setting `GOFIPS140` in a running process's environment (`export GOFIPS140=latest; ./xkmsd`) therefore never did anything real; it was this repository's own invented signal. Deployments must switch to `GODEBUG=fips140=on` (module active) or `GODEBUG=fips140=only` (module active and strict) at runtime, or build with `GOFIPS140=<value>` to activate the module by default. `pkg/crypto/fips` keeps only `Built`/`BuildSetting` (build provenance, for the PKCS#11 module's FIPS artifact labels) and the `DefaultKDF`/`DefaultLUKSKDF` selectors, both now driven by `crypto/fips140.Enabled()` directly. `pkg/pkcs11/module.fipsModeEnabled` becomes an overridable function variable defaulting to `crypto/fips140.Enabled`, so its ~30 existing behaviour tests drive both sides of the FIPS gate without a live `GODEBUG=fips140` subprocess per case; `xkey/pkg/oath` and `xkey/cmd/e2eprobe` call `crypto/fips140.Enabled` directly instead of going through the now-deleted SDK re-export. `test/integration/pkcs11/module/fips`'s harness now drives the built `.so` through `GODEBUG=fips140=on`, not `GOFIPS140=on`, for the same reason.

  **`pkg/quantum/dilithium2`, `pkg/quantum/mldsa65` and `pkg/quantum/mldsa87` (ML-DSA-44/65/87) move from `github.com/cloudflare/circl` to the Go standard library's `crypto/mldsa`, added in Go 1.26.** `pkg/ca` (X.509 certificate signing/verification) and `pkg/keyprovider/quantum` (the `QuantumBackend`, `MLDSAPrivateKey`/`MLDSAPublicKey`) move with them. This is not a data migration: FIPS 204's seed-to-keypair derivation is a standardized deterministic algorithm, and CIRCL and `crypto/mldsa` were verified to produce byte-identical public keys from the same 32-byte seed and cross-verify each other's signatures, so every existing stored ML-DSA seed reconstructs the identical key pair under the new implementation. `pkg/quantum/mlkem512` (ML-KEM-512, which `crypto/mlkem` does not implement) stays on CIRCL and is this repository's one remaining production CIRCL-backed algorithm; its `New` and `Create` constructors are now the shared seam that refuses with the new `ErrFIPSMode` under `crypto/fips140.Enabled()`, since CIRCL sits outside the Go Cryptographic Module boundary the standard library polices and cannot refuse itself.

  `pkg/quantum/kyber768` and `pkg/quantum/mlkem1024` already used `crypto/mlkem`; ML-DSA is the only algorithm family this change moves. `docs/fips/README.md`, `docs/backends/quantum.md`, `docs/architecture/post-quantum-cryptography.md` and `docs/pkcs11/module/v32-compliance.md` are updated to match.
- **`xkey oidc login`'s CLI token store now moves behind the go-qrdb barrier
  the same way the OATH, FIDO2, and Noise-key stores already do, and holds
  the access/refresh/ID tokens in mlocked protected memory while resident in
  the process (go-xkms#4). BREAKING: existing logins do not survive the
  upgrade — the CLI never reads the old plaintext `~/.xkey/tokens.json`
  format, and there is no migration; run `xkey oidc login` again.** The CLI's
  own hand-rolled plaintext JSON writer/reader (`storeToken`/`loadToken`/
  `saveTokenStore` over `os.WriteFile`) is deleted outright and replaced by
  `openOIDCTokenStore` (`xkey/cmd/xkey/cmd/oidc_token_store.go`), which
  reuses the CLI's one barrier-or-warn decision
  (`resolveSecretStoreBackend`, `barrier_store.go`): a barrier-encrypted
  `xkms.StorageBackend` when a barrier is initialized, or the historical
  unencrypted file with the one standard "unencrypted at rest" warning
  otherwise — never a second encryption scheme. An explicit `--token-store
  <path>` still bypasses barrier auto-detection and writes exactly that
  file, matching `xkey oath`'s `--store` override.

  `OIDCStoredToken.AccessToken`/`RefreshToken`/`IDToken` are no longer plain
  Go string fields: they live in `*secure.Buffer` (`sdk/go/secure`), reached
  through accessor/setter methods (`AccessToken()`, `SetAccessToken`, …),
  mirroring how `xkey/pkg/oath`'s `Credential` holds its shared secret.
  `Destroy()` wipes them; every command and the auto-refresh loop now calls
  it once the token is no longer needed.

  The `--background`/`--auto-refresh` worker (`runAutoRefresh`) opens its
  token store once, before the refresh loop starts, and reuses that same
  open store — and, for a barrier-backed store, the same unsealed barrier —
  on every tick, rather than reopening (and re-unsealing) it each interval.
  The detached background process forwards `--barrier-password-file` to
  itself when set, since it has no terminal to prompt on; a bare
  `--barrier-password` value is never forwarded on argv, to keep it out of
  `ps` output, and `XKEY_BARRIER_PASSWORD` reaches the child through normal
  environment inheritance instead.
- **Four more root-module secrets that used to sit as plain `[]byte`/`string`
  now live in protected memory (`*secure.Buffer` / `*secure.Secret` /
  `types.SecretValue`), closing another slice of #587's inventory (refs
  #41).** `luks.TPMSealResult.Passphrase` (`pkg/luks/tpm.go`) is now a
  `*secure.Buffer`; `SealPassphrase` seals the random passphrase into it
  immediately after the TPM2_Create call consumes the plaintext, and the
  narrow `Seal()` wrapper — whose signature callers still depend on — borrows
  and copies out only at that one required `[]byte` boundary, then destroys
  the buffer.

  `pkcs11/module.ExportKeyMaterialResponse.KeyMaterial` and
  `ImportKeyMaterialRequest.KeyMaterial` (`pkg/pkcs11/module/crypto.go`) are
  now `*secure.Buffer`. The export path seals the backend's response the
  moment it crosses into the module's own response type; the import path
  seals `C_CreateObject`'s CKA_VALUE before handing it to the BYOK wrap
  ceremony. `Module.secretKeyValue` — which fills a revealable secret key's
  CKA_VALUE for `C_GetAttributeValue` — borrows and copies out at the one
  place that protection necessarily ends: PKCS#11's C ABI has no enclaved
  `CK_ATTRIBUTE.Value`, so only that last copy is unbounded Go-heap memory.

  `clusterca.KeyProtection.Passphrase` (`pkg/trust/clusterca/keyprotect.go`)
  is now a `*secure.Secret`, and its config source,
  `RaftEnrollmentConfig.CAKeyPassphrase` (`pkg/config/config.go`), is now a
  `types.SecretValue` rather than a plain string — the same protected-config
  pattern #41 established for CA identity passwords. `Server.
  resolveClusterCAKeyPassphrase` (`pkg/server/cluster_ca_strategy.go`)
  resolves any `credential://` reference through the server's secret
  registry and reseals the plaintext into the `*secure.Secret`
  `KeyProtection.Passphrase` needs; the tpm-kek strategy's seed-derived KEK
  (`kekProtection` in `pkg/trust/clusterca/keystrategy_tpmkek.go`) is sealed
  the same way, preserving the existing hex-string passphrase exactly so
  already-sealed keystores keep decrypting.

  `acme/client.CertificateResource` (`pkg/acme/client/types.go`) had no
  constructor or consumer anywhere in the tree outside its own coverage
  tests, so it — and its four methods (`GetCertificate`, `GetPrivateKey`,
  `GetTLSCertificate`, `SaveToFiles`) and the error values only they used —
  were deleted rather than converted; `encodePrivateKeyPEM` and
  `ErrUnsupportedKeyType`, which serve a different, still-live test path,
  were left in place.
- **Ten xkey leaf secrets move into protected memory, and one unimported
  duplicate PIV package is deleted** (#587, #41, #133). String-like secrets
  become `*secure.Secret`, byte secrets `*secure.Buffer`, always borrowed at
  the point of use rather than materialized as an unwipeable Go string: `usb.ImageConfig.Passphrase`
  (`formatLUKS` opens and borrows it for the whole LUKS format/unlock/lock
  sequence); `pwimport.ParsedEntry.Password` (the CSV, KDBX and XML parsers
  seal the parsed password immediately, and `ToStaticPassword` opens it only
  at the storage boundary); `authenticator.pinReadResult.pin`, whose
  `readPIN` now returns a `*secure.Buffer` the caller destroys, trimming
  surrounding whitespace on the raw bytes instead of a heap string; `gui/services.SudoElevator.password`,
  whose `Run` assembles the sudo stdin payload into a wipeable slice instead
  of an unwiped `bytes.Buffer`; `cmd/xkey/cmd.sharedKeyMaterial.KeyMaterial`,
  borrowed only for the duration of the phone share request; `cmd/xkey/cmd.FIDO2Config.PIN`,
  sealed once from viper and opened only to seed the authenticator's initial
  PIN; and `cmd/xkey/cmd.passwordListEntry.Password`, written to the CLI
  writer directly from the borrowed bytes rather than through a `%s` verb.
  `authenticator.UserVerificationResult.PIN` is deleted outright along with
  its only writers (`AutoGrantHandler`'s `simulatedPIN` and
  `NewAutoGrantHandlerWithPIN`): nothing in the tree ever read it. The
  unimported `xkey/pkg/pivcert` package, a stale duplicate of the canonical
  `pkg/pivcert`, is deleted. `scripts/secure-analyzer-allowlist.txt` drops
  the ten now-enforced entries; `make secure-analyzer` is green with no
  stale entries.

### Added

- **`xkey/skills/xkey-agent/SKILL.md`: an Agent Skill for driving an existing xKey instance from the CLI (#1).** It teaches an AI agent the read-only and status verbs it may run (`barrier status --json`, `cert show|export`, `piv list|show|status`, `fido2 status`, `agent status`, `oath list|generate`, `version`) and marks every human-only step as off-limits: barrier unseal, `unlock`, `touch`, `fido2 init-token`, certificate requests, auth ceremonies, PIV generate/delete and OATH add/scan/remove. An agent never supplies a PIN, passphrase or secret by stdin, environment or flag. Every command and flag in the skill was checked against the built CLI's `--help` output. Per-agent headless instances are a separate design, #624.

### Removed

- **Six xkey `Migrate*` helpers with no non-test caller are gone, along with the CLI/GUI config migrator — BREAKING.** `xkey/pkg/agent/migration.go` (`MigrateFileStoreToDAO`), `xkey/pkg/serverregistry/migration.go` (`MigrateToDAO`, `ErrMigration`), `xkey/pkg/audit/migration.go` (`MigrateFromBackend`, `ErrMigration` — distinct from the live `audit.Store.MigrateBackend` method in `store.go`, which is unaffected and stays), `xkey/pkg/oidc/migration.go` (`MigrateFromBackend`, `ErrMigration`), `xkey/pkg/tokenstore/migration.go` (`MigrateFromBackend`, `ErrMigration`), and `xkey/pkg/authenticator/migration.go` (`MigrateRPPolicies`) are deleted with their tests: none had a caller outside their own test file. `xkey/pkg/config/migrate.go` (`Migrate`, 361 lines, plus `ErrConfigMigrationFailed`) and `migrate_test.go` are deleted the same way; the "Migration from Legacy Config" section is dropped from `xkey/docs/configuration/app-configuration.md`.
- **Three dead TCG OID aliases in `pkg/ca/tcg_oids.go` are gone — BREAKING.** `OIDTCGSpecification`, `OIDTCGEKCertificate`, `OIDTCGAIKCertificate` duplicated `OIDTCGAttributeTPMSpecification`, `OIDTCGKpEKCertificate`, `OIDTCGKpAIKCertificate` respectively. `pkg/ca/tcg.go`'s three call sites now use the canonical names directly.
- **`kyber768.ErrInvalidSecretKey` is gone — BREAKING.** It was an unused alias for `ErrInvalidSeed` with zero callers, including in tests.
- **`pkcs11.Backend.SetP11Ctx` is gone — BREAKING.** Test-only raw-context injection; `SetSessionPool` is the supported integration point.
- **`wrapping.GetHashForAlgorithm` is gone — BREAKING.** Test-only helper with no production caller.
- **The process-global `http01.Setup`/`http01.Shutdown` pair is gone — BREAKING.** Both were already `Deprecated` with zero production callers (every real caller uses `NewResponder`, which binds eagerly and returns a typed error). The package-level `activeResponder`/`serverMu`/`fatalHandler` state backing them is deleted along with the tests that only existed to exercise it; `docs/acme/challenges.md` and `docs/acme/sdk/README.md` drop the references.
- **`mcp.Config.Addr` is gone — BREAKING.** Set by `pkg/server` `buildMCPConfig` but never read by the MCP server (it carries no listener). `pkg/server/server.go` stops computing the now-unused address for it.
- **`transport/mcp.SendError` (and its `sdk/go/transport/mcp` re-export) is gone — BREAKING.** Retained only for a client library that no longer has a distinct write-phase failure to report; `ReceiveError` covers every failure mode of the Streamable HTTP client.
- **An orphaned `Deprecated: Use PINBackend()` doc comment for a PIN manager that no longer exists is removed from `pkg/tpm2/platform_keystore.go`.** `PINBackend` is the only accessor; the stale comment pointed at a method that was already gone.
- **A stale comment in `pkg/ca/cross_signing.go` claiming readers fall back to a legacy `xsigned/` key prefix is corrected.** The reader only ever looked under `cross-signed/`; no such fallback exists in the code.
- **`hardware.NewPKCS11CertStorage` is gone — BREAKING.** The "backward-compatible constructor" was a thin, always-non-SO wrapper around `NewPKCS11CertStorageWithSO`. Its four production callers (`pkg/pivcert/pkcs11/pkcs11.go` x3, `pkg/backend/pkcs11/cert_config.go`) and three integration-test callers now call `NewPKCS11CertStorageWithSO(pool, tokenLabel, "", "", false)` directly.
- **`fido2.GenerateLUKSKey` is gone — BREAKING.** Unused alias for `GenerateDerivedKey`.
- **Dead `phone.requestChallenge`/`phone.submitAttestation` protocol leftovers are gone from `xkey/pkg/pairing/protocol_local.go` — BREAKING.** `MethodPhoneRequestChallenge`, `MethodPhoneSubmitAttestation`, `phoneMethodNames`, `IsPhoneMethod`, and the `PhoneRequestChallengeResult`/`PhoneSubmitAttestationParams`/`PhoneSubmitAttestationResult` types implemented an attestation direction the protocol no longer uses (`remote.attestDevice` is the real flow) and had no caller outside their own tests.
- **`xkey/pkg/gui/services/fido2_device_service.go`'s `SetWindowHideFunc` no-op is gone — BREAKING.** It shadowed the real, live `AppService.SetWindowHideFunc` under the same Wails-exposed name; the Wails bindings (`frontend/wailsjs/go/services/FIDO2DeviceService.{d.ts,js}`) are hand-edited to match since nothing regenerates them here.
- **`nativemsg.PairingVerifier.GetState()` and `.Unpair()` are gone — BREAKING.** `GetState` (arbitrary single-extension state) had no caller; `Unpair` was a one-line alias for `UnpairAll` with its sole caller (`xkey/cmd/xkey/cmd/extension.go`) switched to call `UnpairAll` directly.
- **`PairingService.GetPairingStatus()` (and its private `getPairingStatusLocked` helper) is gone — BREAKING.** Single-extension status accessor with no frontend or Go caller; `GetPairedExtensions()`/`GetExtensionFullStatus()` are the live multi-extension APIs. The Wails binding is hand-edited to match.
- **Two frontend-only compatibility aliases are gone from xkey's Svelte frontend.** `phoneState` (`frontend/src/lib/stores/pairing.ts`, aliased to `pairingState`) and `notifyWailsRequired` (`frontend/src/lib/api/backend.ts`, aliased to `notifyBackendUnavailable`) had no remaining callers.
- **The seven `*/legacy_format_test.go` known-answer-vector test files are renamed to `kat_test.go`** (`pkg/backend/mocks`, `pkg/backup`, `pkg/crypto/aesgcm`, `pkg/crypto/ecies`, `pkg/keyprovider/quantum`, `pkg/keyprovider/symmetric`, `pkg/seal`). Their on-disk layouts are unchanged — they are known-answer tests, not backward-compatibility shims — so comments and test names describing them as "legacy"/"compatibility" checks are reworded to say "known-answer" instead.
- **Stale "backward compatibility" framing is reworded on two live SDK re-exports.** `sdk/go/types.go`'s `ClearPassword` alias and `sdk/go/errors.go`'s `XKMSError.Is` sentinel-matching switch are unchanged in behavior — both are live, intentional design — only their comments no longer imply they exist for legacy support.

Not removed despite matching the survey: `pkg/pivcert/pkcs11.NewFromSession` has a genuine production caller (`xkey/pkg/gui/pivcert_pkcs11.go`, the no-`soPin` branch of `newPKCS11PIVCertStorageFromConnection`) and stays. `cmd/xkmsctl/config.go`'s `BackendFactory`/`Config.BackendFactory`/`CreateBackend` are the live dependency-injection seam behind two production commands (`migrate.go`, `tls.go`, 7 call sites) and roughly 40 test call sites across `config_test.go`, `migrate_test.go`, `tls_test.go`, `tls_run_test.go` — rewriting those commands onto `ClientFactory` is an architecture change outside this PR's no-behaviour-change scope and needs an explicit ruling.
- **Every remaining backward-compatibility shim in the root storage formats is gone — BREAKING (on-disk data).** Per the owner's 2026-09-22 ruling ("we dont need to preserve any backward compatibility at the expense of bloating and complicating our codebase"), the dual readers, version-gated inference and silent fallbacks below are deleted outright; old data now fails with a typed error instead of being interpreted. The stack is pre-release alpha, so no migration tool is provided.
  - **`pkg/keyprovider/symmetric.Marshal`/`Unmarshal`** now write and accept only wire version 2 (version byte + explicit GCM nonce mode marker byte). The version-1 layout (no marker byte) is refused by `Unmarshal` with a typed error naming the removed format; there is no dual reader. `GCMNonceMode` itself is unaffected.
  - **`pkg/keyprovider/symmetric`'s key metadata** is a single schema version. `loadKeyMetadata` now returns `(*keyMetadata, error)`: a missing record, an unparseable record, or a record stamped with any other schema version is `ErrKeyMetadataNotFound` or a parse/version error, not a silently-defaulted `Exportable=false, Sensitive=true` record. `deleteKeyMetadata` no longer swallows a missing record — it also reports `ErrKeyMetadataNotFound`. `ListKeys` and `DeleteKey` now fail on a key with no valid metadata record instead of listing/deleting it with guessed attributes.
  - **`pkg/keyprovider/pkcs8`'s key metadata** is a single schema version. `resolveKeyOrigin` is a plain read of the record's `key_origin` field with no version-gated inference: a record with no origin recorded (including a record whose schema version does not match, which is now discarded exactly like a corrupt record) resolves `types.KeyOriginUnknown`, not `types.KeyOriginGenerated`. `pkg/xkms`'s PIV attestation path (`refuseUnattestableKey`) already treats `KeyOriginUnknown` as safe-to-attest for backends that never record provenance (PKCS#11, TPM2, cloud KMS), so this only changes behavior for pkcs8-backed keys whose metadata record predates the origin field or fails to parse.
  - **`BackendFor`/`getBackendForKID` (go-xkms#312) no longer fall back to treating `StoreType` as a registry name.** `ParseKeyIDToAttributes` now sets `KeyAttributes.Backend` from a Key ID string's backend segment (previously only `StoreType`), matching what `ListKeys`'s `stampBackendName` has already done for listed keys. Attributes that carry only `StoreType`, with no `Backend`, now resolve to `DefaultBackend` instead of to whichever registered backend happens to report that `StoreType`.
  - **`pkg/storage/hardware.TPM2CertStorage`** requires every NV certificate record to carry its magic header (`XKC1`) and, for a chain, the explicit chain-marker PEM header on every block. The headerless record shape and the NV-handle addressing form that existed only to reach it (`"0x01800000"` as a certificate ID) are gone, as is the member-count inference that classified an unmarked multi-block record as a chain. A record missing the magic header now fails a direct lookup with `ErrCertRecordMissingHeader` and is skipped by `ListCerts` (indistinguishable from another subsystem's use of the same NV index range) instead of being listed under its NV handle.
  - **`pkg/pkcs11/module.ModuleStorage.LoadFailedAttempts`** drops its `recordUser, recordSO uint32` parameters and no longer seeds the dedicated lockout-counter key from the token record's embedded snapshot. A dedicated key that is absent now reads as zero attempts, not as the record's stale snapshot value.
  - **`pkg/xkms.Unseal`** no longer falls back to the default auto-generated sealing key when a supplied `KeyID` fails to parse (the legacy `storeType:keyType:CN:algo` `ID()` shape). A non-empty `KeyID` that fails `ParseKeyIDToAttributes` now always returns `ErrKeyIDParse`, matching `Seal`'s existing behavior; the auto-resolve-to-default-sealing-key path still applies only when no `KeyID` is supplied at all.
- **Wire and CLI backward-compatibility shims for keys, WebAuthn, the
  barrier and PKCS#11 state are gone — BREAKING.** Five independent compat
  paths, all reachable from wire input, are deleted outright rather than
  deprecated (owner rule 2026-09-22: no backward compatibility, BREAKING is
  fine).
  - `PKCS11StateCASRequest.ExpectAbsent` (proto field 6,
    `pkg/api/grpc/proto/xkmsv1/xkms.proto`) — the field that let a CAS call
    double as `PutIfAbsent` is removed; the field number is `reserved`. The
    dedicated `PKCS11StatePutIfAbsent` RPC is the only create-if-absent path.
    Every server handler, transport (`rest`/`unix`/`grpc`/`quic`), the
    `pkg/pkcs11/module` remote-state client and the cluster CAS integration
    test are updated; none of them still set the field, so this is a
    documentation-only proto/wire change with no client migration required.
  - The WebAuthn ceremony requests' dual `email`/legacy-`username` JSON keys
    (`pkg/api/transport/types.go` `BeginRegistrationRequest`,
    `BeginAuthenticationRequest`, `FinishAuthenticationRequest`) collapse to
    a single `email` tag; `loginKeyFromWire`,
    `ErrRegistrationLoginKeyConflict` and `ErrAuthenticationLoginKeyConflict`
    are deleted. `xkey auth register`/`auth login`'s `--username` deprecated
    alias for `--email` is deleted along with its cobra deprecation plumbing.
  - `pkg/api/rest/handlers_barrier_pin.go` `BarrierInitializeRequest` /
    `BarrierUnsealRequest` lose the plaintext `secret` JSON field and its
    fallback in `barrierCredentialsFromRequest`; only the enclaved
    `password_b64` field carries the passphrase now.
  - `KeyType` is no longer read as an algorithm name when `Algorithm` is
    empty: `Algorithm` is now a required field on every `GenerateKeyRequest`
    path (`pkg/api/rest/handlers.go`, `pkg/api/grpc/service.go`, and
    `pkg/xkms/servicer_key.go`'s `buildKeyAttributes`, which backs the MCP
    and embedded transports). `KeyType` is purely a purpose
    (signing/encryption/tls/...) again. Every in-tree caller that previously
    sent only `KeyType` — `cmd/xkmsctl/key.go`'s symmetric-key path,
    `xkey/pkg/gui/services/key_service.go`, `pkg/pkcs11/module/crypto.go`'s
    two mechanism-translated generate calls, `pkg/api/mcp` handlers and its
    ~80 table-driven test literals, the `sdk/go` doc/example snippets, and
    the gRPC/REST/xkms test suites across `pkg/api/grpc`, `pkg/api/rest`,
    `pkg/xkms`, `pkg/api/transport/*` and `test/integration/*` — now sends
    `Algorithm` explicitly.
  - The FIDO2 `hmac-secret` legacy insecure derivation is gone:
    `pkg/fido2/types.go` `DerivationModeLegacyInsecure`, the
    `deriveSecretLegacy`/`legacyHMACSecret` implementation in
    `pkg/fido2/hmac_secret.go`, the `sdk/go/fido2` re-export, and
    `xkmsctl fido2 authenticate --legacy-hmac-derivation` are deleted.
    `DerivationModeCTAP2` (CTAP 2.1 §12.5) is the only derivation; a volume
    still keyed with the removed derivation must be re-enrolled.

  The xkey GUI's `GenerateKeyParams.KeyType` field and its purpose/algorithm
  fallbacks are deleted as well: `GenerateKeyDialog.svelte` now sends the
  selected algorithm as `algorithm` and leaves `purpose` unset, so the server
  applies its SIGNING default exactly as before.

  Docs: `docs/webauthn/{api,engineering}.md`, `docs/fido2/README.md`,
  `docs/fido2-ctap2/{user,cli,api,engineering}.md`,
  `xkey/docs/headless-webauthn/{cli,engineering,user}.md`.
- **Every xkey on-disk and config migration path is gone — BREAKING, no compatibility with pre-migration data.** xkey never carried more than one on-disk shape for the same state; each shape now has exactly one reader, and a record in the old shape is a typed error telling the operator what to do, not a silent upgrade. Affected areas and required operator action:

  - **GUI config.** `~/.xkey/gui.json` is no longer copied from its legacy
    location on load, and `GUIConfig.PINStrategy` (#307) plus
    `ResolvePINBackend`'s legacy-strategy parameter are gone — the PIN
    backend is derived from the live TPM/store state on every start, not a
    persisted strategy field. `xkey/pkg/gui/migration.go`, which deleted
    stale pin-state files on every start, is deleted along with its `app.go`
    call site. Operator action: none for a config already in the current
    shape; a `gui.json` at the old path is simply not read.
  - **Data-dir moves.** `app.go`'s `MigrateFrom`/`migrateBarrierData` sealed
    barrier data relocation, `SealService.MigrateFrom`,
    `BarrierService`'s cross-directory fallback probe, `TPMService`'s
    one-time `pcr_policies.json` import (`SetPolicyStore` is now mandatory —
    calling it without a store returns `ErrTPMPolicyStoreNotSet`), and
    `sshstore.MigrateLegacyStores` are all deleted. `phone.yaml` is no
    longer renamed to `devices.yaml` on read (`cmd/xkey/cmd/device.go`,
    `phone_service.go`). Operator action: data left at a superseded path is
    not picked up automatically — move `pcr_policies.json`, barrier/seal
    blobs, SSH store files, and `phone.yaml` (rename to `devices.yaml`) into
    their current locations by hand before upgrading.
  - **Config defaults.** `PolicySection.RequirePlatformPolicy` (#313) is
    deleted from the config struct and from `PolicyCanonicalJSON` — the
    HMAC over an enterprise policy document changes as a result; a policy
    signed under the old canonical form must be re-signed.
    `config.AutoPopulateBackends` (the derive-on-read backend-list backfill)
    is gone; `DefaultConfig()` now seeds the one built-in software backend
    directly, so a config written before this change and missing a backend
    list stays empty instead of being backfilled at read time. Browser
    profile-mode backfill (`browser_service.go`, `Settings.svelte`) and the
    CLI's per-mode `server_url` fallback (`cmd/xkey/cmd/trust.go`, now
    requires `trust.bootstrap.server_url` directly) are removed the same
    way. `SealService.SealData`/`UnsealData` no longer default an empty
    `PolicyType` to `"none"` or infer a missing `BackendID`; both fields are
    now required on every seal/unseal call and blob record
    (`ErrSealInvalidPolicyType`, `ErrSealBlobPolicyTypeMissing`,
    `ErrSealBlobBackendIDMissing`). Operator action: set
    `trust.bootstrap.server_url` explicitly if it relied on per-mode
    derivation; re-sign any enterprise policy document; a stored seal blob
    missing `policy_type`/`backend_id` must be re-sealed.
  - **Pairing records.** The Noise-key sealed/plaintext migration
    (`migrateLegacyNoiseKeyAndSave`, `migrateLocalNoiseKey`, and the reseal
    branches in `device_listen.go`, `device_attest_device.go`, and
    `phone_service.go`'s `Connect`) is deleted. Both storage forms — sealed
    (barrier present) and plaintext (no barrier) — are still read, but a
    stored key whose form doesn't match the current barrier state is now
    `pairing.ErrNoiseKeyFormMismatch` instead of being transparently
    resealed. Device attestation records with no `AttestationProtocolVersion`
    or `AttestationProtocolVersion == 1` (#129/#130, predating the
    challenge-response attestation model) are now
    `ErrDeviceAttestationVersionUnsupported` rather than being treated as a
    legacy enrolment. Operator action: re-pair any device that hits either
    error.
  - **Services.** `StaticPasswordService.AddPassword`/`UpdatePassword`'s old
    positional-argument (V1) signatures are deleted; the struct-parameter
    (V2) versions are renamed to the base names
    (`AddPasswordParams`/`UpdatePasswordParams`) and are now the only
    entry points — `Passwords.svelte` and the generated Wails bindings are
    updated to call them under the new names.
    `TPMStatusLevelDefault`/`Provisioned`/`Verified` (unused status-level
    constants) and their `TPM.svelte` cases are removed.
    `tokenstore.BackendTokenStore` is deleted; every caller now constructs
    a `tokenstore.DAOStore` via `xkms.NewKVStoreAdapter` +
    `tokenstore.NewDAOStore`, the same DAO path already used elsewhere.
    Operator action: none — these are internal API renames/removals with
    no on-disk format change.
  - **staticpw.** `pkg/staticpw/migration.go`
    (`MigrateEntry`/`MigrateStore`/`MigrateToScopedLayout`/
    `MigrateFromBackend`) and `EncryptedStore.MigrateToEncrypted` are
    deleted, along with the plaintext pass-through in
    `EncryptedStore.GetDecrypted`: a stored password with no `ENC:` prefix
    is now `ErrPasswordNotEncrypted` rather than being returned as
    plaintext. The `MigrateStaticPasswordEntry`/`MigrateStaticPasswordStore`
    re-exports are removed from `sdk/go/staticpw.go` and
    `xkey/pkg/staticpw/lib.go`, and the `app.go` call into
    `staticpw.MigrateStore` is removed. Operator action: an entry rejected
    with `ErrPasswordNotEncrypted` must be deleted and re-added through
    `EncryptedStore` so it is written back out encrypted; there is no
    automatic upgrade path.
  - **LUKS default paths unified to xhome.** `xkey/pkg/luks`'s deprecated
    `DefaultLUKSFile`/`DefaultDataDir` constants and
    `GetDefaultLUKSPath`/`GetDefaultDataDir` helpers (home-relative
    `~/.xkey.luks` and `~/.xkey`, computed independently of `xhome`) are
    deleted. `luks.NewVolume` and every CLI/GUI caller that previously fell
    back to them (`unseal`, `lock`, `seal`, `wipe`, `migrate`,
    `import-data`, and `StorageService`) now resolve paths through
    `xhome.Resolve()` exclusively, matching every other xkey path
    resolution. Operator action: a LUKS container created under the old
    `~/.xkey.luks` file path (rather than `<xhome>/xkey.luks`) is not found
    automatically — pass `--path`/`--mount-point` explicitly to locate it,
    or move it into the resolved xhome directory.

### Fixed

- **A TPM endorsed through endorse-01 can now enroll an IDevID: its EK certificate records the TPM manufacturer code where enroll-01 reads it.** Every enroll-01 of an endorsed TPM (one with no manufacturer EK certificate — swtpm, many platform TPMs) was refused with a bare `500 serverInternal: Failed to sign TCG-CSR-IDEVID`, because `SignTCGCSRIDevID` could not find the tcg-at-tpmManufacturer code TCG DevID v1 r12 §8.1 puts at the head of the hardwareModuleName (`ErrTCGEKManufacturerUnknown`). Two defects combined. The endorse-01 finalize handler never passed a manufacturer to `IssueEKCertificate`; and when one was passed, `IssueEKCertificate` wrote it as a standalone extension under the attribute's own OID, which `TCGTPMManufacturer` does not read. Now the endorse-01 client reads the code from the TPM (`TPMModule.TPMManufacturer`, from `TPM_PT_MANUFACTURER`) and asserts it in the finalize CSR as a subjectAltName directoryName; the handler validates its form (`id:` + eight uppercase hex digits, `ValidateTCGTPMManufacturer`), holds it to any `deviceInfo.tpmManufacturer` the account's EAB names, and refuses with `badCSR` / `unauthorized` otherwise; and `IssueEKCertificate` records it in a subjectAltName directoryName per the TCG EK Credential Profile. The finalize handler now logs the CA's error when TCG-CSR-IDEVID signing fails. `BuildSubjectAltName` gained a `directoryNames` parameter and `CertificateSpec` a `DirectoryNames` field; `TCGTPMManufacturerFromCSR` and `TCGTPMManufacturerSubjectAltName` are new. **Breaking:** `CreateTPMManufacturerExtension`, `CreateTPMModelExtension` and `CreateTPMVersionExtension` are removed from `pkg/ca` and `sdk/go` — they produced the unreadable encoding and had no callers; `acmeclient.TPMModule` gained `TPMManufacturer() (string, error)`. Found on hardware: a worker node's platformd crash-looped at enrollment against a control plane that had endorsed its TPM.

## [0.16.0-alpha] - 2026-09-22

### Security

- **xkmsd's bootstrap listener no longer keeps its Noise/P-256 static keys in
  plaintext config or regenerates them every restart; they are now persisted
  barrier-sealed (#35, #42, #436).** `bootstrap.noise.static_key_hex` /
  `static_key_file` / `p256_static_key_hex` / `p256_static_key_file` put a
  private key inline in YAML or in a plaintext file, and configuring neither
  generated a fresh ephemeral key on every boot — silently invalidating every
  client that had pinned the previous public key. The xkey pairing half of
  this custody model landed first as #42
  (`xkey/pkg/pairing/noise_key_seal.go`); this closes the xkmsd half.

  `pkg/server/bootstrap_key_custody.go` resolves each suite's key on boot:
  with a barrier configured (`s.barrier`, adopted from the embedded qrdb node
  or built by `initializeBarrier` — the boot order already runs this
  post-unseal, since `s.barrier` is only ever set once `initEmbeddedQRDBNode`
  has confirmed the node unsealed), the hex-encoded key is read from and
  written to the barrier's own key-value store
  (`bootstrap-noise/x25519-static-key`, `bootstrap-noise/p256-static-key`) via
  `seal.Barrier.Get`/`Put`, the same mechanism `pkg/server/credentials`
  already uses for operator-owned secrets. The first boot after upgrade reads
  the deprecated config field once, seals the key it names, and logs that the
  field is deprecated; every later boot finds the sealed key and never reads
  config again. With no barrier configured, the deprecated fields are still
  honored unchanged, and a key with neither configured is persisted (not
  regenerated) as a 0600 file in the server's data directory, with one warning
  that it lacks barrier protection.

  The four config fields are marked `Deprecated` in
  `config.NoiseBootstrapConfig`'s doc comments; they still parse (the
  migration depends on it) but are not read again once a key is sealed or
  persisted. `pkg/server/bootstrap_key_custody.go`,
  `pkg/server/bootstrap_key_custody_test.go`, `pkg/server/errors.go`,
  `pkg/config/config.go`.

### Added

- **`xkey oidc` can now authenticate against providers with no discovery
  document, and can address a token endpoint that expects a JSON body
  instead of form encoding** (#4, gaps 2 and 3 of 4; gap 1, CLI token-store
  custody, and gap 4, RFC 8628 device flow, remain open pending an owner
  ruling). `pkg/oidc.ProviderConfig` gained `AuthorizationEndpoint`,
  `TokenEndpoint`, `JwksURI`, and `UserinfoEndpoint` fields: setting any of
  them makes `NewProvider` skip `.well-known/openid-configuration` entirely
  and use the supplied endpoints, requiring the first three and validating
  with the existing `ErrMissingAuthEndpoint`/`ErrMissingTokenEndpoint`/
  `ErrMissingJWKSURI` family via the new `ErrIncompleteManualEndpoints`. A
  bare `SkipDiscovery: true` with no manual endpoint keeps its prior
  contract — an uninitialized `Provider` the caller populates itself. The
  CLI exposes this through `--authorization-endpoint`, `--token-endpoint`,
  `--jwks-uri`, and `--userinfo-endpoint` on `xkey oidc login` and
  `xkey oidc providers add`; a partial set is refused with a typed error
  (`ErrOIDCIncompleteEndpoints`) naming exactly which flags are missing,
  and a saved provider's manual endpoints now carry into `xkey oidc refresh
  --provider <name>` too, so a manual-endpoint provider survives past the
  first login. A new `TokenEncoding` field (`pkg/oidc.TokenEncoding`, `form`
  default or `json`) selects how the authorization-code exchange and
  refresh requests are POSTed; `pkg/oidc.EncodeTokenRequestBody` is the one
  place that makes this decision, used by `Client.doPlainTokenRequest` and
  `Client.doDPoPTokenRequest` (and therefore by the GUI's `OIDCService`,
  which already builds providers through `pkg/oidc.NewProvider`/`NewClient`)
  and by the CLI's `exchangeCodeForTokens`/`refreshTokens` alike, so the
  encoding decision lives in one place instead of being duplicated between
  the CLI and the library. `--token-encoding` on `xkey oidc providers add`
  and `xkey oidc login` persists the choice per provider
  (`oidc-providers.json`'s `token_encoding` key); an unrecognized value is
  refused via `oidc.ErrInvalidTokenEncoding`. Background auto-refresh
  carries the resolved token endpoint and encoding across its re-exec the
  same way it already carries the client ID. Files:
  `xkey/pkg/oidc/provider.go`, `xkey/pkg/oidc/token_encoding.go`,
  `xkey/pkg/oidc/client.go`, `xkey/pkg/oidc/errors.go`,
  `xkey/cmd/xkey/cmd/oidc.go`. Tests: `pkg/oidc/provider_test.go`,
  `pkg/oidc/token_encoding_test.go`, `pkg/oidc/client_test.go`,
  `pkg/oidc/client_dpop_test.go`, `cmd/xkey/cmd/oidc_test.go`,
  `cmd/xkey/cmd/oidc_cmds_test.go` cover manual-endpoint discovery skipping
  against a server that never serves `.well-known`, partial-endpoint
  refusal, form vs. json request bodies against a fake token endpoint for
  both exchange and refresh (including the DPoP path), and refusal of an
  unrecognized encoding.

### Changed

- **`scripts/secure-analyzer-allowlist.txt` now keys each exemption by path +
  rule + the finding's own symbol, not by `path:line`** (#607, #549). A
  `path:line` key breaks on any edit that shifts the exempted line — it broke
  Lint on `main` twice in one week (`fido2.go` 208→207 after #181,
  `mock_extended.go` after #154) — with no signal beyond a red job days
  later. The symbol is the forbidden import path for rule 1, the call
  expression's own source text for rule 2, or `<Struct>.<Field>` for rule 3;
  rule 2 and rule 3's symbols aren't in the diagnostic message, so
  `scripts/secure-analyzer.sh` reads them back out of the source at the
  diagnostic's `file:line:col` via a new `go/ast`-based helper,
  `scripts/secure-analyzer-symbol`. The matching and staleness-check logic
  moved into a shared, sourced `scripts/secure-analyzer-key.sh` so
  `scripts/secure-analyzer-selftest.sh` can exercise the real gate against a
  throwaway fixture: its new case proves an entry survives a line shift and
  that the stale check still catches a genuinely removed finding. All 38
  existing entries are rewritten to the new key form (they collapse to 36
  `path+rule+symbol` keys — three identical `ssh.ParsePrivateKey(buf.Bytes())`
  call sites in `pkg/ssh/keys/signer.go` now share one entry).
  `docs/development/lint-gates.md` documents the new format.
  `make secure-analyzer` and `make secure-analyzer-selftest` both verified
  green.
- **A pooled PKCS#11 session's object search is now one critical section per
  session handle (#24, #107).** `SessionPool` (`session_pool.go`) gains
  `WithSearch`, which runs `FindObjectsInit` / `FindObjects` /
  `FindObjectsFinal` under a lock keyed by the session handle, so a second
  search on the same handle can never start while an earlier one on that
  handle is still open — serialized per handle rather than across the whole
  pool, and with the same panic-safety `discardAndReplace` already gives
  `WithSession` (#107). The three search sites in
  `pkg/storage/hardware/pkcs11_cert_storage.go` (`ListCerts`,
  `findCertificateHandle`, `findChainMemberHandles`) route through it via a
  new optional `PKCS11SearchProvider` interface, following the same
  optional-interface pattern `PKCS11SOSessionProvider` already uses. The
  equivalent pooled-session searches in `pkg/backend/pkcs11`
  (`Backend.FindSecretKey`, `findKeyPairByID`, `findRSASigner`,
  `findECDSASigner`) — the sites `golangci-lint` flagged for a discarded
  `FindObjectsFinal` return — now go through the same lock via a new
  `SessionPool.FindObjectHandle` helper instead of hand-rolling the
  Init/Find/Final sequence. This closes a real, if narrow, defect: two
  sequential borrowers of the same handle could previously have their
  searches overlap if a caller's own `Init`/`Final` pairing were not
  perfectly scoped. **It does not resolve #24's `CertificateRenewal` flake.**
  Scored interleaved, run-by-run, against apt SoftHSM 2.6.1 in the
  devcontainer (300 iterations per tree, same host load): fixed tree 13/300
  (4.3%) vs. unfixed tree 18/300 (6.0%), z = 0.92 — not statistically
  significant, and both trees still fail overwhelmingly with
  `CKR_OPERATION_ACTIVE` (10/13 fixed, 15/18 unfixed) rather than a
  converted error, so the flake's mechanism is unchanged by this fix. #24
  stays open per its own prior conclusion: the defect is not reproducible in
  this repository's session bookkeeping and likely sits in SoftHSM 2.6.1 or
  the miekg binding.

### Fixed

- **The default AES-GCM `Encrypt` path now works under `GODEBUG=fips140=only`
  instead of failing on every call.** `pkg/crypto/aead.NewGCM` built
  `cipher.NewGCM`, the arbitrary-IV construction Go's FIPS 140-only mode
  refuses outright ("use of GCM with arbitrary IVs is not allowed"), so the
  symmetric (`pkg/keyprovider/symmetric`), Azure Key Vault
  (`pkg/backend/azurekv`) and TPM2 (`pkg/tpm2`) `Encrypt` implementations
  could not produce a single AES-GCM ciphertext in that mode, caller-supplied
  nonce or not. New `aead.NewGCMForFreshEncrypt` substitutes
  `cipher.NewGCMWithRandomNonce` under `fips140=only` for the one combination
  it supports — no caller-supplied nonce, the default full 128-bit tag — and
  reports the substitution through a new `types.EncryptedData.GCMNonceMode`
  field so `aead.NewGCMForDecrypt` rebuilds the matching construction from the
  ciphertext's own recorded framing rather than from the decrypting process's
  FIPS posture: a `fips140=only`-written ciphertext still opens under
  `fips140=on`, and a legacy explicit-nonce ciphertext still opens wherever
  arbitrary-IV GCM is available. The on-disk TLV envelope
  (`pkg/keyprovider/symmetric.Marshal`/`Unmarshal`) only spends a wire-format
  version bump recording the mode when it is not the zero value, so every
  ciphertext written before this change is byte-identical version-1 output
  and keeps decoding unchanged. A caller that supplies its own nonce, or
  requests a truncated tag — combinations `NewGCMWithRandomNonce` cannot
  produce — still fails closed under `fips140=only` with the typed
  `aead.ErrArbitraryIVGCMUnavailable`, extended to Vault Transit's BYOK key
  wrap (`pkg/backend/vault/vault_importexport.go`), whose wire format
  mandates a fixed all-zero nonce, using the same gate #292 established for
  PKCS#11's authenticated-wrap verbs (refs #23, #292).
- **Every permission the xkms API module contributes to go-qrdb now declares
  its tenancy scope, so a role holding one can still obtain a token.**
  go-qrdb#504 removed the implicit self-scope: under go-qrdb v0.19.0-alpha a
  permission with no declared scope is refused rather than admitted as
  `ScopeSelf`, and `rbac.ListPermissions` fails on the *first* unscoped
  permission an identity holds — so one omission denies login, not one call.
  `pkg/apimodule/module_grants.go` registered the module's 73-permission
  vocabulary with `qrdbsdk.RegisterPermissions` and declared no scope for any
  of it. 69 of those names are go-qrdb's own and carry go-qrdb's scope; the
  four go-qrdb does not declare — `keys:read`, `keys:write`, `keys:update`,
  `ssh:use` — had none, and on go-quicbaas v0.11.0-alpha (which composes
  go-xkms v0.14.0-alpha) every login for a role carrying `keys:read` was
  rejected with `permission: no scope declared for keys:read`. The new
  `pkg/apimodule/module_scopes.go` declares those four — and only those four —
  `PermissionScopeSelf` via `qrdbsdk.RegisterPermissionScope`, pinning each by
  name with its rationale: `keys:read`/`keys:write`/`keys:update` gate the
  PKCS#11 object-state and seal stores, which hold system-barrier state, and
  go-qrdb declares the whole `seal:*` family `ScopeSelf` while reserving
  `ScopeTenantOnly` for the per-tenant `tenant_barrier:*` custody; `ssh:use` is
  the blanket gate on the SSH CA route group whose siblings `ssh:read`,
  `ssh:write`, `ssh:delete` — and the matching `piv:use` — are all `ScopeSelf`
  in go-qrdb. That is the reach all four had before go-qrdb#504, so no
  deployment's authorization outcome changes; the omission simply becomes a
  decision. Registration order in `registerRoleGrants` is now permissions →
  scope → role grants, because the authorizer resolves scope before it
  consults the grant. Files: `pkg/apimodule/module_grants.go` (permission
  derivation extracted to `modulePermissions`),
  `pkg/apimodule/module_scopes.go`, `pkg/testutil/permscope.go` (reads a
  declared scope back through the SDK's `NewTenantScopeStore`, the same
  resolution path the RBAC authorizer uses, since the SDK re-exports only the
  write side of `RegisterPermissionScope`). Tests:
  `pkg/apimodule/module_scopes_test.go` is the build gate — mirroring go-qrdb's
  `TestEveryPermissionDeclaresItsScope` — asserting that every contributed
  permission resolves a scope, that xkms declares a scope for no name go-qrdb
  already owns (`RegisterPermissionScope` overwrites, so a duplicate would
  silently replace an upstream decision), that no declaration names a
  permission the module does not contribute, and that an undeclared permission
  still surfaces `*PermissionUndeclaredScopeError` so the gate cannot pass
  vacuously; `pkg/testutil/permscope_test.go` covers the resolver against
  self-, tenant-only-, and cross-scoped built-ins plus the undeclared error
  path.

## [0.15.0-alpha] - 2026-09-22

### Security

- **Two hardcoded loopback literals that relaxed validation are now
  config-gated, off by default, on every surface that constructs the affected
  types (#140).** The ACME enrollment challenge handler substituted the
  request's client IP for the challenge validation target whenever an
  authorization's permanent-identifier was the literal `127.0.0.1`, with no
  way to turn the substitution off; the Azure Key Vault backend accepted any
  `localhost`/`127.0.0.1` vault URL unconditionally, in every build,
  including production. Both were flagged as benign-but-security-relevant in
  the #140 configuration audit and ruled on (owner, 2026-09-21, option A):
  make each an explicit, config-gated development switch, default false.

  `acme.enrollment.allow_loopback_identifier`
  (`XKMS_ACME_ENROLLMENT_ALLOW_LOOPBACK_IDENTIFIER`) now gates the
  substitution in `ChallengeHandler`; with it off (the default) a loopback
  identifier is refused with `ErrLoopbackIdentifierNotAllowed` before the
  challenge verifier runs, instead of silently validating against the
  caller's address. The standalone `TrustedCA` library
  (`pkg/acme/client`, not built through `pkg/config`/viper) carries the same
  switch as `TCAACMEConfig.AllowLoopbackIdentifier`
  (`allow_loopback_identifier`), threaded into the same `ChallengeHandler`
  through `handlers.Params.AllowLoopbackIdentifier`, also off by default.

  `backends.azurekv.allow_local_vault_url`
  (`XKMS_BACKENDS_AZUREKV_ALLOW_LOCAL_VAULT_URL`) gates the local-URL bypass
  in `azurekv.Config.Validate`; with it off (the default) a `localhost`/
  `127.0.0.1` vault URL fails with `ErrLocalVaultURLNotAllowed`. The
  `xkms.AutoInitialize` map-based construction path
  (`pkg/xkms/register_azurekv.go`) reads the same switch from its
  `BackendConfigs` map under `"allow_local_vault_url"`, parsed as a `bool`; a
  present value that is not a `bool` fails with the new
  `xkms.ErrInvalidBackendConfigValue` instead of being silently ignored, the
  one behavior on this surface that previously had no failure mode at all.

  All defaults are `false`, so anyone relying on the previous unconditional
  behavior for local development or testing must now set the corresponding
  key to `true` on whichever of these surfaces they use.

  Files: `pkg/acme/server/handlers/challenge.go`, `service.go`,
  `challenge_test.go`; `pkg/acme/client/trustedca_config.go`, `trustedca.go`,
  `trustedca_loopback_identifier_test.go`; `pkg/backend/azurekv/config.go`,
  `errors.go`, `config_test.go`; `pkg/config/acme.go`, `config.go`,
  `load_test.go`; `pkg/server/backend_azurekv.go`; `cmd/xkmsd/acme.go`;
  `pkg/xkms/register_azurekv.go`, `errors.go`, `register_azurekv_test.go`;
  `docs/acme-issuance/engineering.md`, `docs/crypto-backends/engineering.md`,
  `docs/backends/azurekv.md`; example configs
  `configs/xkmsd.yaml{,.example}`, `examples/config/config-server.yaml`.
  Verified by `go test` across `pkg/acme/server/handlers`,
  `pkg/acme/client` (`-tags codec_json`), `pkg/backend/azurekv`
  (`-tags azurekv`), `pkg/xkms` (`-tags azurekv`) and `pkg/config`: each key
  defaults to refusing the loopback/local case on every surface that builds
  the corresponding type, each is settable `true`, and — for the
  `pkg/config`-driven keys — the environment name wins over a file that says
  nothing.
- **A `pinUvAuthToken` can no longer be spent by two concurrent CTAP2
  commands (#323).** `AuthorizePinUvAuthToken`'s check
  (`checkPinUvAuthTokenLocked`) and its spend (`consumePinUvAuthToken`,
  `xkey/pkg/authenticator/cmd_clientpin.go`) are two separate acquisitions of
  the authenticator's state lock, with a possible user-presence prompt in
  between, so two commands presenting the same token could both pass
  authorization before either consumed it — one PIN entry buying two
  registrations or assertions instead of one. This is a TOCTOU gap, not a
  data race: every individual access to the token state is correctly
  synchronized, which is why `go test -race` alone could not catch it (#328
  was the duplicate report of the same gap).

  `ProcessCBORWithContext` (`xkey/pkg/authenticator/authenticator.go`) now
  holds a dedicated `cmdMu` for the whole of a command, including any
  user-presence wait, so a second command cannot begin authorizing until the
  first has fully returned — closing the window by construction instead of
  narrowing it. This also makes the pre-existing `cmdCtx.Store`/`defer
  Store(nil)` single-command assumption true. The accepted trade: a command
  blocked on user presence blocks every other queued command for the whole
  wait, matching how a real CTAP authenticator (one outstanding command at a
  time) behaves; every `requestUserPresence` call site already released the
  state lock before blocking, so `cmdMu` is the only lock held across the
  wait.

  Files: `xkey/pkg/authenticator/authenticator.go`,
  `xkey/pkg/authenticator/pinuvauthtoken_toctou_test.go`,
  `xkey/docs/virtual-authenticator/engineering.md`. Verified by
  `TestConcurrentCommandsCannotBothConsumeOnePinUvAuthToken`, which mints one
  token and fires two goroutines through `ProcessCBOR` after a start barrier:
  exactly one `getAssertion` succeeds and the other fails with
  `ErrPINAuthInvalid`, stable across `go test -race -count=20`.
- **A FIPS-built artifact now keeps enforcing its approved-algorithm allowlist
  even when an operator sets `GODEBUG=fips140=off`** (#219, owner ruling on
  the policy question `pkg/crypto/fips/algorithms.go` left open in #568).
  `AlgorithmPermitted` disabled the allowlist whenever `Compiled() ||
  Enabled()` was false — the crypto actually in force — which let an
  operator turn a validated build's module off at runtime and have it accept
  any algorithm the caller already trusted, exactly as a non-FIPS build
  does. `AlgorithmPermitted` now also consults `Built`, the build-provenance
  signal #568 added: the allowlist stays active whenever the binary was
  built with an enabling `GOFIPS140`, regardless of the module's runtime
  state. A binary never built with `GOFIPS140` is unaffected — it still
  permits every algorithm whenever neither `Compiled` nor `Enabled` is
  active. Verified by unit tests driving `Built` through a package-private
  indirection (`builtFunc`): a forced `Built()=true` refuses every
  non-approved algorithm regardless of `GODEBUG=fips140=off`, and a forced
  `Built()=false` alongside an unactivated module and `GOFIPS140=off`
  permits them, matching the two new cases in `algorithms_test.go`.
- **The CA identity key password and software keystore password config
  fields are now `types.SecretValue`-typed instead of plain `string`, so the
  four `SecretValue.String()` call sites this repo carried — each suppressed
  with a per-line `//nolint:staticcheck // go-xkms#41` — are gone along with
  their directives** (#41, #133). `SecretValue.String()` copies a resolved
  secret into an immutable, unwipeable Go string on the GC heap; the two
  production sites (`pkg/server/server.go`, resolving a CA identity's
  per-key and identity-wide software keystore passwords) wrote that copy
  into a plain `string` config field that outlives the call, which is a
  custody change, not a call-site swap — the reason this issue carried
  `task:blocked` since 2026-08-20 pending an owner ruling. That ruling
  (2026-09-21, option A) is: declare the field as `SecretValue` so the
  resolved plaintext stays sealed in the field's own memguard enclave for
  the life of the config, exactly as `qrdbsecret.SecretValue`'s own doc
  comment recommends.

  `types.KeyConfig.Password` and `ca.CAKeystoreSoftwareConfig.Password`
  change from `string` to the new `types.SecretValue` alias
  (`= qrdbsecret.SecretValue`). The wire form is unchanged: both YAML and
  JSON still read and write the plain reference string (a literal password
  or a `credential://...` URI) — `SecretValue`'s own `UnmarshalYAML`/
  `UnmarshalJSON`/`MarshalYAML`/`MarshalJSON` round-trip it through `Raw`.
  The one gap that isn't covered by `SecretValue`'s own codec is that
  `pkg/config.Load` decodes through viper's mapstructure chain, not
  `yaml.v3`, so `SecretValue`'s `yaml.Unmarshaler` never runs there;
  `pkg/config/load.go` now composes a `string`→`SecretValue`
  `mapstructure.DecodeHookFunc` onto viper's default hook so a config file
  keeps loading a plain string into the field. `walkYAMLKeys` (env-key
  registration) is taught to treat `SecretValue` as a leaf rather than a
  section to descend into, so a future top-level `SecretValue` field isn't
  silently dropped from `XKMS_`-prefixed environment override the way
  descending into its unexported enclave field would drop it (today's two
  fields live inside `ca.Identity`, itself under a slice `walkYAMLKeys`
  already treats as one leaf, so this guard is defense for a shape that
  doesn't exist yet, not a fix for one that does).

  Every reader of the two fields is updated to borrow bytes at the point of
  use instead of holding a plaintext string: `types.NewPasswordFromSecretValue`
  (new) calls `SecretValue.WithBytes` to build a `types.Password` from the
  resolved enclave, falling back to treating `Raw` itself as the literal
  password only when the value was never resolved through a
  `ResolverRegistry` (`Strategy == ""`) — a `SecretValue` resolved to
  deliberately empty content (`Strategy` set, enclave empty) stays a `nil`
  password rather than reinterpreting its reference string as one.
  `KeyAttributesFromConfig` and `Identity.ToKeyAttributes` both route
  through it. `pkg/server/server.go`'s CA-init resolution loop and
  `pkg/types/types_secret.go`'s `resolveKeyConfigPasswords` move the
  registry's resolved `*SecretValue` into the field by custody transfer
  (`id.Keys[j].Password = *sv`) rather than calling `.String()`.
  `pkg/trust/clusterca/backends.go`'s `injectKeystorePassword` — a fourth,
  previously unflagged site this audit turned up, assigning a resolved
  `types.Password`'s bytes into both fields — now seals each target field
  its own enclave via the new `types.NewLiteralSecretValue`, since
  `SecretValue` is single-owner for its working life and must not be shared
  across multiple config fields as one struct copy.

  `SecretValue.String()` had no remaining caller in this repository (root,
  `sdk/go`, `xkey`) once the four sites above were migrated, so it is not
  carried forward as unused surface here — it remains available upstream in
  `go-qrdb` for callers that still need it.

  **BREAKING for a Go consumer that sets `KeyConfig.Password` or
  `CAKeystoreSoftwareConfig.Password` (also reachable as `sdk/go`'s
  `KeyConfig.Password` / `TrustedCAKeystoreSoftwareConfig.Password`)
  directly as a string** — e.g. `KeyConfig{Password: "secret"}` no longer
  compiles. Construct a `types.SecretValue{Raw: "secret"}` (unresolved,
  matching what a YAML/JSON decode produces) or, for plaintext already in
  hand, `types.NewLiteralSecretValue([]byte("secret"))` instead. Config
  documents on disk and `XKMS_`-prefixed environment overrides for these
  two fields are unaffected.

  Files: `pkg/types/types.go`, `pkg/types/types_secret.go`,
  `pkg/ca/config.go`, `pkg/server/server.go`,
  `pkg/trust/clusterca/backends.go`, `pkg/config/load.go`. Tests:
  `pkg/types/types_secret_test.go`, `pkg/types/types_extended_test.go`,
  `pkg/ca/config_test.go`, `pkg/ca/secret_wiring_test.go`,
  `pkg/server/secret_wiring_test.go`,
  `pkg/trust/clusterca/backends_test.go`. Verified by
  `go test ./pkg/config/... ./pkg/server/... ./pkg/types/... ./pkg/ca/...
  ./pkg/trust/clusterca/...` and the full repository suite: a config file
  with a plain-string password still loads into a resolved-ready
  `SecretValue`, an environment override still applies, the CA-init wiring
  borrows bytes via `WithBytes` and the source config never carries a bare
  password string, and a `SecretValue` resolved to an empty credential
  leaves `attrs.Password` `nil` rather than treating its `credential://...`
  reference as a password.
- **xkey setup wizard: the PIN service is a required constructor argument, and the dead `require_platform_policy` checkbox is withdrawn.** #313 ruling #20 (constructor shape) and interim ruling #19 (checkbox). `NewSetupWizardService()` took zero arguments and wired all fifteen collaborators through setters; `FactoryReset`'s SO PIN verification sat inside `if s.pinSvc != nil`, so a `SetupWizardService` built anywhere that missed `SetPINService` accepted any non-empty string as authorization for a full device wipe. A local nil-check for that one call site was fixed earlier (PR #334), but the constructor still let a caller build a wizard with no way to authorize it at all. `NewSetupWizardService(pinSvc *PINService) (*SetupWizardService, error)` now refuses a nil PIN service with `ErrSetupWizardPINServiceRequired`, so the omission is a compile-time argument, not a forgettable setter. Every other collaborator (TPM, seal, barrier, platform policy, storage, auto-unseal, static password, admin) stays optional through its own `Set*` method, because each may legitimately be unavailable on a given build or host — e.g. a device with no TPM (#510) — and the wizard already degrades those steps to a warning rather than fabricating success. `SetPasswordProtectionService` and `SetPostApplyFunc` are deleted: the first set a field (`ppSvc`) that no code in the package ever read, and the second wired a callback `app.go` never called; both were coverage-only in tests.

  Ruling #19: the enterprise wizard's "Require platform policy" checkbox wrote `SetupChoices.RequirePlatformPolicy`, which nothing read, while `ApplySOProvisioning` separately wrote `policy.RequirePlatformPolicy = true` into the persisted config unconditionally, regardless of the checkbox — so the control could not have fired even if something had read the choice. The checkbox is removed from `SetupWizard.svelte`, the unconditional write is removed from `ApplySOProvisioning`, and `SetupChoices.RequirePlatformPolicy` is deleted. `PolicySection.RequirePlatformPolicy` (`xkey/pkg/config/policy.go`) stays, with a doc comment marking it reserved, so configs written before this change keep parsing. Wiring it to an actual enforcement path is #313 (A)/(B), still open, along with the other 20 inert `PolicySection` fields the same audit found.

  Files: `xkey/pkg/gui/services/setup_wizard_service.go`, `xkey/pkg/gui/services/errors.go`, `xkey/pkg/gui/app.go`, `xkey/pkg/config/policy.go`, `xkey/frontend/src/views/SetupWizard.svelte`, `xkey/frontend/src/lib/types/setup.ts`, `xkey/frontend/wailsjs/go/models.ts`, `xkey/frontend/wailsjs/go/services/SetupWizardService.{d.ts,js}` (hand-edited: `wails` is not installed on this host, so the generator could not be run), and every `pkg/gui/services` test file that constructed a `SetupWizardService`. Also fixed in passing: `ApplySetup`'s auto-unseal step called `s.sealSvc.CanSeal()` before checking `s.sealSvc != nil`, which panics (not just returns false) on a nil `*SealService` receiver because `CanSeal`'s own panic recovery dereferences the same nil receiver while logging. Verified with `go test ./xkey/pkg/gui/services/... ./xkey/pkg/config/...`: the constructor refuses a nil PIN service and accepts a real one; `TestFactoryReset_RefusesWhenPINServiceUnwired` (constructed via struct literal, the only way to reach that state now) still proves the destructive-operation guard fails closed on its own; every existing wizard test passes against the new constructor; and no test writes or reads `require_platform_policy` through the wizard.
- **Security: xkey's Noise static private key is now sealed in the barrier, never persisted as plaintext** (#42, refs #130, #114). `PairedDevice.LocalNoisePrivateKey` (`xkey/pkg/pairing/device.go`) used to hold the host's Curve25519 pairing key as raw base64 — an immutable Go string that could not be wiped, at rest in `devices.yaml` protected only by filesystem permissions. It now holds one of two forms, distinguished by a marker only: `pairing.NoiseKeySealedPrefix` ("`xkey-noise-sealed-v1:`") followed by base64 of the private scalar encrypted under the barrier's master key (`pairing.SealLocalNoiseKey`/`UnsealLocalNoiseKey`, `xkey/pkg/pairing/noise_key_seal.go`), or the legacy raw-base64 form kept readable — with no barrier required — so an existing pairing is not broken by the fix. Generation, sealing and use all happen at the point the private scalar is already in protected memory (`phone.StaticKey.Private` on the way in, `sdk/go/secure.Buffer` on the way out of `UnsealLocalNoiseKey`); the plaintext form is never assembled into a heap string.
  **Migration** is automatic and one-way: the first successful use of a legacy record — `phone_service.Connect` in the GUI, `device attest-device` and `device listen` in the CLI — re-seals the key and rewrites `devices.yaml`, after which only the sealed form is ever written for that device.
  **Custody, per the owner's revised ruling on #42**: a host that has never run `xkey barrier init` (GUI: no `BarrierService`, or one with `IsInitialized() == false`) is never refused — `PhoneService.Pair` and the CLI's `device pair` write the legacy plaintext form and log one `slog.Warn` per operation pointing at `xkey barrier init` (`PhoneService.sealOrWarnLocalNoiseKey`, `cmd.sealOrWarnLocalNoiseKey`); `device listen` and `device attest-device` do the same on read and skip migration until a barrier exists. A barrier that **does** exist but cannot currently be opened — sealed (an app lock), or the CLI wasn't given a working password — still refuses outright (`ErrPhoneBarrierRequired` / `ErrDeviceBarrierUnsealFailed`), never falling back to plaintext for a host that opted into protecting this key. `PhoneService.resolveNoiseKeyBarrier` and the CLI's `openDeviceBarrier` (`xkey/cmd/xkey/cmd/device_barrier.go`, `--barrier-password`/`--barrier-password-file`/`XKEY_BARRIER_PASSWORD`) are what draw this line for each surface. (An earlier version of this fix refused pairing/connecting outright whenever no barrier was wired at all; the owner overrode that after landing — degrading gracefully with a warning is the ruling, not a refusal.) The shared session opener every other device-backed command funnels through (`openDeviceSession`, `newPairedDeviceBackendConfig` in `device_session.go` — OATH sync, backup, sharing, re-attest, phone enrollment, the FIDO2 phone backend) is unaffected by this distinction: a legacy record was already read with no barrier, and a sealed one already required `XKEY_BARRIER_PASSWORD`.
  `pkg/attestation.DeviceBindingFor` and the rest of `pkg/attestation` never touch the private key field and needed no change.
- **The `xkey oath` CLI, `xkey backup`, and `xkey device oath-sync` now
  encrypt OATH TOTP/HOTP secrets at rest through the same barrier the GUI and
  `xkey extension serve` already use, instead of always writing a plain
  `oath.json` file** (#134, #148, refs #210). Owner ruling: no second
  encryption scheme and no new wrapping key — every OATH store path opens
  `oath.NewBackendStore` over the unsealed barrier backend
  (`xkms.NewBarrierBackend`) when a barrier is initialized at the default
  store location, sharing the `--barrier-password` / `--barrier-password-file`
  / `XKEY_BARRIER_PASSWORD` reach `xkey fido2` and `xkey extension serve`
  already have through one new shared helper
  (`resolveSecretStoreBackend`, `xkey/cmd/xkey/cmd/barrier_store.go`). When no
  barrier is initialized, the historical 0600 `oath.NewFileStore` is
  unchanged, and xkey now logs one `slog.Warn` per store open naming the
  store and pointing at `xkey barrier init` — never a silent plaintext
  fallback. A barrier that is initialized but cannot be opened (wrong or
  missing password, unsupported strategy, corrupt root key) is a typed
  refusal (`ErrBarrierStoreOpenFailed`), never a downgrade to plaintext. An
  explicit `--store` / `--oath-store` path always selects the plain file at
  that path, bypassing the barrier decision, matching the pre-existing
  `xkey backup` convention for explicit store overrides. `xkey backup`
  reads/writes the OATH store through the same resolution
  (`resolveOATHBackupStore`), so a backup taken while the barrier is active
  captures the same ciphertext the GUI wrote instead of a stale or absent
  plaintext file; the trust store and password store are unchanged and keep
  their existing barrier-encrypted refusal at their own default locations.
  `fido2`'s explicit `--storage barrier` path was refactored onto the same
  low-level unseal primitive (`openBarrierBackend`) so there remains exactly
  one function in the CLI that knows how to unseal the barrier, removing a
  duplicate inline copy that also leaked an unused file-backend handle. The
  dead `oath.NewDAOStore`, `OATHCredentialEntity`, and their
  `MigrateFromBackend` helper (no production caller; only the FIDO2
  authenticator's own, unrelated DAO store remains) were deleted along with
  their tests. In-memory secret custody from #210
  (`Credential.secret *secure.Buffer`) is unchanged; the accepted
  `crypto/hmac` ipad/opad residue documented at `GenerateCounter`
  (`xkey/pkg/oath/generator.go`) is unchanged and cross-referenced from
  `xkey/docs/oath/README.md`. Verified by CLI tests asserting a
  barrier-backed `oath add` writes no plaintext secret or name to disk, a
  no-barrier `oath add` logs the warning and still round-trips through the
  plain file, a wrong or missing barrier password is a typed refusal that
  never writes plaintext, an explicit `--store` bypasses the barrier, and a
  full `xkey backup create`/`restore` round trip against a barrier-backed
  OATH store never leaks the plaintext secret into the sealed backup file.
- **The FIDO2 passkey store now warns once, at open, when it is holding
  private keys unencrypted (#181).** go-qrdb's seal barrier is the *only*
  at-rest encryption in this stack; xkey adds no per-credential wrap of its
  own on top of it. When a barrier is active, `authenticator.BackendStorage`
  is constructed over the barrier backend and credential records are
  encrypted by the barrier the same way every other barrier-routed store is
  (GUI: `xkey/pkg/gui/app.go:753`; standalone daemon: `xkey fido2
  --storage-type barrier`, `xkey/cmd/xkey/cmd/fido2.go:1400-1458`). Without a
  barrier — `xkey fido2 --storage-type file`
  (`xkey/cmd/xkey/cmd/fido2.go:1375-1386`) and the GUI's pre-`barrier init`
  fallback (`xkey/pkg/gui/app.go:761-772`) — the store is a plain 0600 file
  and always has been; that plaintext state is the operator's configuration
  choice, not a bug, but it was previously silent.

  Both file-store construction sites now emit one `slog.Warn` naming the
  exposure ("passkey store is unencrypted at rest: private keys are stored
  in plaintext") and pointing at the remedy (`xkey barrier init`) every time
  the store is opened — never a refusal, never a silent fallback.
  `--storage-type memory` (the daemon's default) and the barrier-backed path
  are unaffected; neither writes plaintext to disk. This is deliberately
  narrow: #134 is adding a shared "is the barrier initialized? open it or
  warn" helper for the OATH paths in a parallel branch, so the two file-store
  sites here warn directly rather than growing a second helper that would
  need reconciling with it. #42 is the tracking issue for the standalone
  daemon's credential-store hardening this change is one step of.

  `xkey fido2 status` already named the live store and its
  `EncryptedAtRest` field already reported `false` for `file`/`memory` and
  `true` for `barrier` (`xkey/cmd/xkey/cmd/fido2_status.go`); that disclosure
  is unchanged, now pinned by `TestDescribeStorageNamesTheFileStoreAsUnencrypted`
  and its siblings in `fido2_status_store_test.go`.

  Also deleted the dead `DAOCredentialStore` (`xkey/pkg/authenticator/dao_credential_store.go`,
  its `FIDO2CredentialEntity` DAO entity in `entity.go`, and both test files):
  `NewDAOCredentialStore` had zero non-test callers — the GUI and the
  standalone daemon both construct `authenticator.BackendStorage`, not a
  DAO-backed store, so there was no barrier-protected-versus-unprotected
  split between them to begin with, only the barrier-versus-no-barrier split
  this change addresses. `MigrateCredentials` (`xkey/pkg/authenticator/migration.go`),
  the only production reference to the deleted type, is removed with it; it
  also had zero callers.

  Files: `xkey/cmd/xkey/cmd/fido2.go`, `xkey/cmd/xkey/cmd/fido2_init_token.go`,
  `xkey/cmd/xkey/cmd/fido2_provision_attestation.go`, `xkey/pkg/gui/app.go`,
  `xkey/pkg/authenticator/migration.go`. Verified by
  `TestCreateFIDO2Storage_FileWarnsUnencrypted`,
  `TestCreateFIDO2Storage_MemoryDoesNotWarn`,
  `TestNewFIDO2Device_FileStorageWarnsUnencrypted`,
  `TestNewFIDO2Device_MemoryStorageDoesNotWarn`
  (`xkey/cmd/xkey/cmd/fido2_passkey_store_warning_test.go`), and
  `TestInitializeDataDir_WarnsWhenFIDO2StoreUnencrypted`,
  `TestInitializeDataDir_NoWarningWhenBarrierActive`
  (`xkey/pkg/gui/fido2_passkey_store_warning_test.go`).
- **`xkey unlock` now enforces its own 8-attempt budget on the PIN it
  carries over IPC, and the `--pin`/`--so-pin` value flags are gone (#272,
  #307).**
  The unlock IPC verb is the one PIN-carrying message the socket accepts,
  and until now nothing counted a wrong PIN against it: a sealed barrier's
  own credential counter is unreadable until the very PIN it protects has
  already succeeded, and the software PIN backend keeps no counter of its
  own at all, so any local process could drive `unlock` at machine speed.
  `AppLockService` now owns an independent, CTAP2-sized budget
  (`AppLockPINMaxAttempts = 8`), persisted outside the barrier at
  `<dataDir>/pin/unlock_attempts` (JSON, atomic temp-file-then-rename,
  `0600`) so it is readable and writable while the barrier stays sealed. A
  strategy fault or a corrupt root key (`ErrAppLockUnsealUnavailable`,
  `ErrAppLockStorageCorrupt`, `qrdbsdk.ErrPINNotSet` — the #510
  classifications) never spends an attempt; only an evaluated-and-rejected
  credential does. Once the budget reaches zero, `Unlock` refuses with the
  typed `ErrAppLockPINBlocked` *without evaluating the PIN*, and every
  rejection or refusal is wrapped in `*AppLockAttemptsError`, which carries
  the attempts remaining while still satisfying `errors.Is` against the
  underlying cause; the IPC `UnlockResult` gained a `RemainingAttempts
  *int` field so `xkey unlock --pin-stdin` reports the count in band, not
  only in its error string. A successful Security Officer PIN verification
  resets the budget: `PINService.ResetLockout` and `PINService.SetUserPIN`
  call a newly wired `AppLockService.ResetAttempts` when one is present
  (the GUI and the headless `xkey extension serve` daemon both wire it),
  and the equivalent CLI verbs — `xkey pin reset-lockout` and `xkey pin
  set-user` — call the new `services.ResetAppLockAttempts(dataDir)` to
  reach the same persisted file from a separate process, since the daemon
  whose `AppLockService` holds the live counter is not the process running
  the CLI.

  **Breaking:** the `--pin` and `--so-pin` VALUE flags (`xkey unlock`,
  `xkey auth register`, `xkey auth login`, `xkey device pair`, `xkey
  extension serve`) are removed. They were visible to every other process
  on the host via `ps`, which is a wider audience than the IPC socket the
  PIN is usually headed for, and their own help text said so. `--pin-stdin`
  / `--so-pin-stdin` and the `XKEY_PIN` / `XKEY_SO_PIN` environment
  variables are unaffected; any script still passing `--pin <value>` or
  `--so-pin <value>` now gets a cobra "unknown flag" error and must switch
  to one of those two.

### Added

- **The signed CRL is now a replicated artifact, so any go-xkms instance in a
  qrdb/Raft cluster can serve it, not just the one that most recently
  generated it** (#275). Revocation *state* (serial, reason, revokedAt) has
  been persisted through `CA.revocationStore` since the datastore-backed
  revocation store landed, and replicates under Raft — but the signed CRL
  *bytes* `GenerateCRL` produced were hard-coded to
  `certstore.compositeCertStore`'s in-memory cache, an unreplicated,
  per-process map. `POST /ca/crl` was consequently the only way to obtain a
  CRL at all, and it answered from whatever a single instance happened to
  have signed. `pkg/ca/crl_persistence.go` persists the CRL DER alongside its
  `Number`/`ThisUpdate`/`NextUpdate` as a sibling of the revocation records,
  keyed by the issuing certificate's Subject Key Identifier
  (`crl/<ski-hex>`), through the same `revocationStore` (preferred) /
  `objectStore` (legacy fallback) preference order `recordRevocation`
  already uses — so the artifact replicates exactly the way the state that
  produced it does, with no new storage wiring.

  A new `CA.CRL(ctx)` accessor returns the persisted DER, regenerating and
  persisting first only when none exists yet or the published `NextUpdate`
  has passed; `recordRevocation` also refreshes the CRL (best-effort) right
  after a successful revocation, so a client rarely observes staleness in
  practice. There is deliberately no leader election and no background
  scheduler: any instance may sign a refresh, staleness is detected and
  repaired on read, and `GenerateCRL` remains available as the explicit,
  always-regenerate force-refresh verb. `compositeCertStore.StoreCRL`/
  `GetCRL` stay as the in-memory hot-path cache `CA.CRL` checks before
  falling through to the persisted artifact, rather than a second, competing
  source of truth.

  `GET /ca/crl` (`application/pkix-crl`) is new and reads without forcing a
  signing operation; `POST /ca/crl` is unchanged in behavior but is now
  documented as the explicit force-regenerate verb. REST is the only CA
  transport that exposes a CRL read today — gRPC, QUIC, MCP, and the Unix
  socket transport carry only the generate verb, and none of them gained a
  new one here.

  Separately, `OCSPResponder.checkCertificateStatus`'s cold path (consulted
  when a serial is absent from the in-memory revocation map, e.g. a fresh
  process that has not reloaded state yet) only ever read `ca.objectStore`,
  never the preferred `ca.revocationStore` — so a CA configured with only the
  datastore-backed store, the common replicated configuration, silently fell
  back to always answering `ocsp.Good` on that path. `getRevocationBlob`
  gives both the OCSP responder and the CRL persistence layer the same
  store-preference read, closing that gap.

  Files: `pkg/ca/crl_persistence.go`, `pkg/ca/crl_persistence_test.go`,
  `pkg/ca/ca.go`, `pkg/ca/ca_extensions.go`, `pkg/ca/ocsp.go`,
  `pkg/ca/ocsp_revocationstore_test.go`, `pkg/ca/interface.go`,
  `pkg/ca/provider/provider.go`, `pkg/certstore/composite_certstore.go`,
  `pkg/api/rest/handlers_ca.go`, `pkg/api/rest/routes.go`,
  `pkg/xkms/servicer_ca.go`, `docs/ca/`. Verified by
  `go test ./pkg/ca/... ./pkg/certstore/... ./pkg/api/rest/...`: persist/read
  round trip across independent `*CA` instances sharing a backend,
  refresh-on-revoke incrementing the `Number` extension and including the new
  serial, regenerate-on-read past `NextUpdate` and not before it (via an
  injected clock), `GenerateCRL` forcing regeneration even when the published
  CRL is still fresh, `GET /ca/crl` returning `application/pkix-crl` and a
  404 for an unknown issuer, and the OCSP cold path answering from a
  revocation-store-only CA.
- **PIV enrollment records an attestation level, distinguishable from key
  origin** (#220, completes #207). `types.AttestLevel` (`pkg/types`, beside
  `types.KeyOrigin`) is the one shared vocabulary for "where a key lives" —
  `AttestLevelHardware`, `AttestLevelSoftware`, `AttestLevelUnattested` — that
  go-xkms and go-quicbaas's `AttestLevel` (go-quicbaas#379) now both speak,
  settling the cross-repo ownership question #220 raised: xkms owns the
  spelling. `types.KeyAttributes.AttestLevel` sits next to `KeyOrigin`, not
  merged into it — #207's own design note is explicit that the two answer
  independent questions, and an imported hardware key is the case that would
  lose meaning if they were one field.

  **Spelling note for go-quicbaas#379**: go-quicbaas's independently-drafted
  `AttestLevel` used `hardware` / `software` / `none`. xkms keeps
  `unattested` rather than adopting `none`, because `unattested` is already
  the REST `attest_level` claim value issued on live tokens (#200) and
  changing it would be a breaking wire change for every already-minted
  token. Per the ruling, go-quicbaas imports `types.AttestLevel` rather than
  keeping its own enum, so this is the one place the spelling needed to be
  reconciled, not two parallel vocabularies going forward.

  A new optional `xkms.PIVKeyGenerator` capability, `PIVAttestLevelReporter`
  (`AttestLevel(slot, cn) (types.AttestLevel, error)`), mirrors
  `PIVKeyOriginReporter`'s shape but answers a different kind of question: a
  backend's hardware backing does not vary key to key, so the answer is read
  live from `types.Capabilities.HardwareBacked` rather than from a per-key
  record, and it is always answerable rather than carrying a "not found"
  case. Both `PIVKeyGenerator` implementations in the tree satisfy it:
  `backendPIVKeyGenerator` classifies from the underlying backend's
  `Capabilities()` (hardware for TPM2/PKCS#11/cloud KMS, software for the
  PKCS#8-backed software backend), and `softwarePIVKeyGenerator` always
  reports software. `pivAttestLevel` is the fallback for a `PIVKeyGenerator`
  that implements no reporter at all — a caller-supplied generator that
  cannot back any hardware-backing claim — resolving to
  `AttestLevelUnattested` rather than a guess.

  `backendPIVKeyGenerator.GeneratePIVKey` and `.ImportPIVKey` stamp
  `attrs.AttestLevel` at the same write as `attrs.KeyOrigin`; an imported key
  on a hardware backend still records `AttestLevelHardware` — AttestLevel
  answers where the key lives, not whether it is exclusive, which
  `AttestPIVSlot`'s existing origin-based refusal already covers separately.
  `pkg/keyprovider/pkcs8` needs no metadata round trip for this field, unlike
  `KeyOrigin`: PKCS#8 storage is software cryptography by construction, so
  `ListKeys` always resolves to `AttestLevelSoftware`, correcting rather than
  trusting whatever was claimed in memory.

  The REST PIV login exchange (`POST /api/v1/auth/login/piv`) now prefers a
  recorded enrollment level over the certificate chain when one is available:
  `PIVLoginOptions.RecordedLevel` (`func(cert *x509.Certificate)
  (types.AttestLevel, bool)`) is consulted first, and only when it is nil or
  reports not-found does the pre-existing chain-derived decision run. This is
  a strict precedence, not a merge — a recorded `hardware` is never
  downgraded by a missing or failing chain (the chain is not examined once a
  recorded level is found), and a recorded `software` or `unattested` is
  never upgraded by a chain that happens to verify. `AllowUnattested` still
  gates whether a non-hardware level, recorded or chain-derived, may log in
  at all; `RecordedLevel` only decides which level that is. The existing
  `PIVAttestLevelHardware` / `PIVAttestLevelUnattested` REST constants move
  onto `types.AttestLevel` (`string(types.AttestLevelHardware)` /
  `string(types.AttestLevelUnattested)`) so there is one vocabulary rather
  than a second, independently-spelled copy — pinned by a test asserting the
  minted claim's string value is unchanged. gRPC and MCP have no parallel PIV
  login path to update: PIV login is REST-only, and the SDK's login client
  speaks to that one endpoint over mTLS.

  `RecordedLevel` is wired, not left as an unused seam: a new
  `PIVManager.AttestLevelForCertificate(ctx, cert)` (`pkg/xkms`) computes the
  login certificate's SPKI SHA-256 thumbprint with `qrdbsdk.ComputeSPKIThumbprint`
  — the one cert-binding algorithm this stack already uses for admin cert
  binding and the PIV login user lookup itself, not a second one invented
  for this — and scans the enrolled PIV slots of every backend with a
  registered PIV store for a certificate sharing that thumbprint. A match
  resolves the level through that backend's `PIVAttestLevelReporter`; no
  match reports `found=false` with no error (the certificate may simply not
  correspond to any PIV enrollment, which is the common case); a backend
  whose store cannot be listed reports the typed `ErrPIVAttestLevelLookupFailed`
  rather than being silently read as no match. `pkg/server` wires this at
  REST composition via a new `xkms.GetPIVManager()` accessor, guarded so a
  build with no PIV manager initialized leaves `RecordedLevel` nil and falls
  back to the pre-existing chain-only behavior exactly as before.

  Coverage: `types.AttestLevel` round trip, `ParseAttestLevel`'s typed error
  (`types.ErrUnknownAttestLevel`), and JSON/YAML round trip
  (`pkg/types/attest_level_test.go`); both `PIVAttestLevelReporter`
  implementations and `pivAttestLevel`'s capability/error fallback, plus
  enrollment-time stamping on both `GeneratePIVKey` and `ImportPIVKey`
  (`pkg/xkms/piv_attest_level_test.go`); `AttestLevelForCertificate` matching
  a hardware-enrolled key, a software-enrolled key, no match, a nil
  certificate, and a backend listing failure
  (`pkg/xkms/piv_attest_level_for_certificate_test.go`); the pkcs8 `ListKeys`
  override (`pkg/keyprovider/pkcs8/attest_level_test.go`); and the REST
  precedence table plus the constants' pinned string values
  (`pkg/api/rest/handlers_auth_recorded_level_test.go`).

### Changed

- **`pkg/xkms` backend resolution is now keyed by registry name, not by a
  parse of it** (#312, #297, #172). `BackendFor` and `getBackendForKID` used
  to resolve `GetBackend(string(attrs.StoreType))` — which worked only
  because every backend that existed had been registered under a name that
  was also a store-type keyword (`software`, `pkcs11`, `tpm2`, …); a backend
  registered under any other name, e.g. a second PKCS#11 token named
  `token-a`, resolved to `backend not found: unknown` on every path that
  read the key back through its stored attributes. `types.KeyAttributes`
  gains a `Backend` field carrying the exact registry name a key's operation
  ran against; `xkms.Backend` gains `Type() types.StoreType`, implemented by
  every backend and wrapper in the tree (the composite backend, the
  tenant-scoping wrapper, and every test fake), so a resolved backend can
  report what kind it is without unwrapping to `KeyProvider()` and losing
  tenant scope (#163). Every producer that used to write
  `StoreType: types.ParseStoreType(backendName)` now writes `Backend:
  backendName, StoreType: b.Type()` instead, so `StoreType` is a label the
  backend reports about itself, never a second name for the same registry
  entry. The last surviving `ParseStoreType` override, in MCP's
  `handleExportKey`, is replaced by the resolved backend's own `Type()` for
  the same reason, and the two independently-maintained copies of
  `ValidateBackendName` (`pkg/validation`, `pkg/api/rest`) are now one,
  imported from `pkg/validation`.

  **Migration**: keys persisted before this change carry no `Backend` value,
  and a backend's own `ListKeys` has no way to learn the registry name it
  was registered under, so this is not a one-time backfill — `BackendFor`
  and `getBackendForKID` permanently fall back to treating `StoreType` as
  the name when `Backend` is empty, which reproduces the exact resolution
  every caller depended on before this field existed. `KeyAttributes.ID()`
  is unaffected for every key that exists today: a backend registered under
  a store-type keyword reports that same keyword from `Type()`, so `ID()`'s
  `StoreType` segment is byte-identical to what `ParseStoreType(backendName)`
  produced. A backend registered under a non-keyword name now stores new
  keys under its real kind (e.g. `pkcs11`) instead of the `unknown` segment
  `ParseStoreType("token-a")` used to leave in `ID()` — a new-key
  improvement pinned by test, not a change to any key that already exists.
  The Simplified API's package-level `ListKeys` now stamps `Backend` onto
  every key it returns with the name it was listed under, so a caller that
  lists keys and then calls `Key`/`Signer`/`Decrypter`/`DeleteKey` with one
  of them (as the PIV slot lookups in `xkey/pkg/gui/services/piv_service.go`
  do) resolves the same backend the listing came from, including for
  non-keyword names.
- **CI now fails a run that leaves the checkout dirty after `make test`, closing out the remainder of #454.** #469 fixed the two measured causes -- `npm install` rewriting lockfiles and vitest's coverage HTML being tracked -- but nothing stopped a future change from reintroducing either defect, or a new one, silently: a green gate that still drifts the tree is a PR that ships a build different from what's in source control, and the drift is only caught if someone happens to run `git status` afterward. The `test` job in `.github/workflows/ci.yml` now runs `git diff --exit-code --stat` and a `git status --porcelain` check immediately after `make coverage` (the job's `make test` invocation), printing the offending paths and failing the run if either finds anything.

  Re-measured the other open half of #454, `xkey/frontend/dist`: two independent builds -- `make build-xkey` (the Docker builder image) and a second run against the host's own npm/node, both `npm ci` against the committed lockfile -- produced byte-identical hashed asset names (`index-ClR-jwrm.css`, `index-DxZbWHr5.js`) and left `git status --porcelain` empty. The content-hash churn the issue measured was `npm install` resolving a different dependency set on every run, not bundler nondeterminism; `npm ci` (already landed in #469) already fixes it. `dist` stays tracked (owner ruling 2026-09-21, option A) since `xkey/frontend/embed.go`'s `//go:embed all:dist` needs it at compile time and CI's `build` job deliberately builds xkey without the GUI tags to avoid needing the npm toolchain at all, so no CI job exercises the `dist`-regenerating path today -- this guard covers what CI does run, `make test`.

  Files: `.github/workflows/ci.yml`. Verified: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`; `make build-xkey` and a second manual `npm ci && vite build` in `xkey/frontend` both followed by `git status --porcelain` with empty output (#454).
- **The Lint job now enforces go-qrdb's `pkg/secure` analyzer rules on this
  repository instead of assuming them (#549).** `pkg/secure/analyzer` is a
  complete, unit-tested `go vet` plugin banning raw `memguard` imports outside
  `pkg/secure`, `ssh.ParsePrivateKey`, and sensitive-named struct fields typed
  `string`/`[]byte` — but an analyzer enforces nothing where its own make
  target does not run, and nothing in go-qrdb reaches into this repository, so
  compliance here was unmeasured. `make secure-analyzer` builds the analyzer
  from the pinned go-qrdb dependency and sweeps it, as `go vet -vettool=...`,
  over every module in this tree (`.`, `sdk/go`, `xkey`, `web/desktop`) under
  every build-tag combination that module's own vet/lint/test targets already
  declare; `make secure-analyzer-selftest` proves the gate can still find a
  known violation and stays silent on its compliant counterpart
  (`test/lint/secure/_fixtures`) before either result is trusted. Both run in
  CI's Lint job, after golangci-lint.

  Triage found six raw `memguard` imports and four `ssh.ParsePrivateKey`
  calls. One `memguard` import (`cmd/xkmsctl/bootstrap_noise.go`) and two
  `memguard.WipeBytes` calls (`cmd/xkmsctl/bootstrap_p256.go`,
  `pkg/server/bootstrap_suite.go`) were fixable in place and are now
  `secure.Buffer`/`secure.Wipe` from `sdk/go/secure`. The remainder needed an
  explicit, reasoned exemption in `scripts/secure-analyzer-allowlist.txt`
  rather than a code change, because the reported line asks for something the
  code cannot currently supply:

  - Five raw `memguard` imports (`cmd/xkmsctl/bootstrap_p256.go` and its test,
    `pkg/server/bootstrap_suite.go` and its test, `pkg/trust/bootstrap/suite_test.go`)
    exist because go-truststrap v0.4.0-alpha's `p256proto.{NewStaticKey,
    EncodeStaticKey,DecodeStaticKey}` take a `*memguard.LockedBuffer`
    directly, and `secure.Buffer` deliberately exposes no accessor to produce
    one. Filed upstream as **jeremyhahn/go-truststrap#60**.
  - Four `ssh.ParsePrivateKey` calls in `pkg/ssh/keys/{parse.go,signer.go}`
    already operate on `*secure.Buffer`/`*secure.Secret`-backed bytes; the
    call exists only to distinguish an unencrypted key from
    `*ssh.PassphraseMissingError` before falling back to
    `ParsePrivateKeyWithPassphrase`, which cannot parse an unencrypted key at
    all. The narrowing this needs is in the rule's own detection, not in this
    package — tracked as a rule-2 narrowing on go-qrdb.

  The sweep also surfaced 31 pre-existing rule-3 findings (sensitive-named
  fields predating this gate, across `pkg/crypto/rand`, `pkg/luks`,
  `pkg/fido2`, `pkg/backend/mocks`, `pkg/backup`, `pkg/factor/fido2`,
  `pkg/pivcert`, `examples/symmetric-encryption`, `pkg/auth`,
  `pkg/pkcs11/module`, `pkg/trust/clusterca`, `pkg/acme/client`,
  `sdk/go/piv_signer.go`, and thirteen sites under `xkey/`). None is fixable
  without changing an exported field's type across its call sites, so each is
  listed in the allowlist as a named, pre-existing finding pending design
  review rather than converted or silently dropped. Every allowlist entry —
  all three classes — is matched by exact `file:line` and fails the sweep as
  stale the moment it stops matching anything, so an exemption cannot outlive
  the code it was written for. Files: `Makefile`, `scripts/secure-analyzer.sh`,
  `scripts/secure-analyzer-selftest.sh`, `scripts/secure-analyzer-allowlist.txt`,
  `test/lint/secure/_fixtures/{bad,clean}`, `.github/workflows/ci.yml`,
  `cmd/xkmsctl/bootstrap_noise.go`, `cmd/xkmsctl/bootstrap_p256.go`,
  `pkg/server/bootstrap_suite.go`, `docs/development/lint-gates.md`. Verified
  by `make secure-analyzer` and `make secure-analyzer-selftest`, both exit 0.
- **`docker-compose.production.yml` no longer builds its own images; it runs
  the ones the `docker-build-*` Make targets produce (#228).** The compose
  file's `build:` blocks pointed at the real Dockerfiles with no secret
  injection, so a bare `docker compose build` (or an accidental `docker
  compose up` before the images existed) failed on the first private
  `github.com/jeremyhahn/*` module with an opaque authentication error — the
  in-house Go module credential is staged to a gitignored file by
  `stage-gomodauth` and passed to BuildKit only as a build secret
  (`--secret id=gomodauth`) by `make docker-build-*`, and compose has no
  equivalent step. Each service's `build:` now points at
  `Dockerfile.compose-build-unsupported`, a stub that fails immediately with a
  message naming the correct `docker-build-*` target, so the failure is
  actionable instead of opaque. The `image:` tags were also corrected to match
  what the Make targets actually tag (`go-xkms-server:${VERSION:-latest}`,
  etc. — they previously read `go-xkms/server:...`, a name nothing ever
  built), so `docker compose up` picks up a Make-built image once one exists.
  Files: `docker-compose.production.yml`, `Dockerfile.compose-build-unsupported`,
  `docs/deployment/docker.md`. Verified with `docker compose -f
  docker-compose.production.yml config` (parses) and `docker compose -f
  docker-compose.production.yml build` (fails, naming the per-service
  `docker-build-*` target).
- **Every Dockerfile now builds from `golang:1.27.0`, not `golang:1.26.x` (#36).**
  #560 moved every `go.mod` and the CI `GO_VERSION` pin to Go 1.27.0 but left
  the container base images behind, so a Docker build still resolved a
  toolchain a full minor version older than the one `go.mod` requires and CI
  runs against. Every `Dockerfile*` under the repository root, `.devcontainer/`,
  `test/integration/`, and `xkey/test/integration/` now pulls
  `golang:1.27.0-bookworm` or `golang:1.27.0-alpine` (same variant each file
  already used), the `create-dockerfile` fallback target in the Makefile emits
  the same pin, and the `.github/workflows/ci.yml` `GO_VERSION` comment — which
  still said the 1.27 move was pending "the Go 1.27.0 wave" — was rewritten to
  record that #560 already made it. `go.mod` files are unchanged; this is a
  base-image-only cleanup closing out the residue of #36.
- **Headless-browser guidance for xkey's UV behaviour is now documented, closing #395 without a code change.** Owner ruling 2026-09-21 (option A) upholds #365/#280: xkey's virtual authenticator reports `uv=false` unless a PIN was actually verified inside that ceremony, so Chrome raises its native PIN dialog on every assertion that requests user verification, and nothing driving the page over CDP can answer a dialog that lives in the browser's UI. `xkey/docs/agent-automation/user.md` gets a new "Headless browsers and automation" section stating the observed behaviour, the one-paragraph CTAP 2.1 §6.1.2/§6.2.2 and `credProtect`/WebAuthn L2 §5.2.1 reasoning for why xkms will not report a fabricated `uv=true`, and two runnable client-side recipes: (a) Chrome DevTools Protocol `WebAuthn.addVirtualAuthenticator` with `hasUserVerification: true, isUserVerified: true` (a Playwright snippet and a raw CDP snippet), distinguished from xkey's own `--cdp` bridge, which still applies xkey's real UV rules; and (b) relying-party-side `userVerification: "discouraged"`, with the trade-off it gives up. It also corrects the record on `--auto-uv`: the flag does not exist (removed by #365), and the actual machine-identity trade today is `--require-touch=false` with a real PIN, a different trade from either browser recipe. `xkey/docs/virtual-authenticator/user.md` gains a cross-reference clarifying that its `--cdp` bridge drives xkey's own real authenticator and is not a substitute for Chrome's own virtual authenticator. No other sentence in `xkey/docs/virtual-authenticator/`, `xkey/docs/agent-automation/`, or the legacy `xkey/docs/fido2/` implied the GUI could report `uv=true`; none needed correcting.

  Files: `xkey/docs/agent-automation/user.md`, `xkey/docs/virtual-authenticator/user.md`. Verified: Markdown code-fence count is even in both files (no unterminated fences) and `go build ./...` untouched — no source files changed (#395, #365, #280).
- **The MCP transport's WebAuthn registration and authentication methods are now a documented, typed exclusion rather than a transitional stub (#193).**
  `pkg/api/transport/mcp.Transport`'s `BeginRegistration`, `FinishRegistration`,
  `BeginAuthentication` and `FinishAuthentication` returned the generic
  `ErrNotSupported`, which read as "not implemented yet." Owner ruling
  2026-09-21 (option C) settled it as a named exclusion: an agent-facing
  tool-call surface must not mint sessions or enrol credentials, and MCP
  holds no identity-ceremony state. The four methods now return the typed
  `ErrIdentityCeremonyExcluded` (re-exported unchanged by
  `sdk/go/transport/mcp`), and `pkg/api/mcp.ModuleMethods`, the MCP tool
  capability surface, never lists a tool for them, so a client can discover
  the exclusion without calling and failing. Documented in
  `docs/webauthn/api.md` §Capability matrix, `docs/webauthn/engineering.md`
  §Error semantics, and `docs/key-management/api.md` §"How the six
  transports are shaped".
- **The unwipeable copies stdlib parsing leaves behind are now recorded repo policy, not an open question (#133).** Owner ruling 2026-09-21 (option 1): accept the documented residue, decline `unsafe` layout pokes. `pkg/backend/software/zeroize.go`'s `zeroizeParsedPrivateKey` and its pinning test, `TestZeroizeParsedPrivateKey_ECDHIsNotWipeable` (`zeroize_test.go`), already bounded and asserted the residue — `rsa.PrivateKey.Precomputed`'s unexported bigmod cache and the `ecdh.PrivateKey` scalar cannot be wiped through Go's public API. `docs/development/lint-gates.md` gains an "Accepted residue: stdlib copies no exported API can wipe" section naming exactly which stdlib representations are affected (the RSA and ECDH cases above, plus `crypto/hmac`'s ipad/opad blocks, #134, #41), why (no exported route without `unsafe`), and what mitigates it (bounded process lifetime, every field an exported API reaches is zeroized, no long-lived parsed private keys). The doc comment on `zeroizeParsedPrivateKey` and the pinning test's comment now point at that section, so the residue reads as ruled policy rather than a bug someone forgot to fix.
- **Cutting a release is now two steps, and only the second one publishes**
  (#419, #211, #421). `scripts/release-alpha.sh` used to commit the version
  bump, create all three lockstep tags, and push the commit *and* the tags to
  `main` atomically, in one run, with no pull request anywhere in that path —
  on 2026-09-06 two releases raced for the same base commit exactly because
  that path had no review gate to hold either one, and the unreviewed run
  published `v0.9.5-alpha`, a PATCH carrying nine new exported symbols with
  nothing to catch it. `make release-alpha` (`scripts/release-alpha.sh`) now
  fetches `--branch` (default `main`) from `--remote` (default `dev`) and
  reads `VERSION`, the reciprocal pins and `CHANGELOG.md` from that fetched
  tip — never from the operator's own checkout, which may be stale
  (go-xkms#211's "fetch-and-assert"; a fully isolated, disposable checkout was
  considered and declined). On a real cut it checks out a new branch
  `release/X.Y.Z-alpha` from the fetched tip, assembles the changelog, moves
  the pins, bumps `VERSION`, commits, and pushes **that branch only**; it
  prints the pull request URL and stops. Nothing is tagged and `main` is never
  written.

  A new `make release-tag VERSION=X.Y.Z-alpha` (`scripts/release-tag.sh`)
  publishes, run only after that pull request has been reviewed and merged. It
  fetches `--branch` again and refuses unless the local checkout's `HEAD` is
  byte-identical to the just-fetched tip, `VERSION` at that commit (read from
  the git object, not the working tree) is exactly `--version`, and a commit
  reachable from that tip carries the exact `chore(release): <version>`
  message `release-alpha.sh` produces (a squash merge's appended `(#<pr>)` is
  the one accepted variation) — then re-checks the reciprocal pins and the
  `CHANGELOG` heading against that resolved commit before creating and pushing
  the three annotated, signed tags atomically. `release-tag.sh` reuses
  `TAG_NAMESPACES`, `PIN_EDGES` and every pure function from
  `release-alpha.sh` by sourcing it with `RELEASE_ALPHA_LIB=1` rather than
  redeclaring any of it. `.github/workflows/release.yml`'s `push: tags: v*`
  trigger is unchanged and still fires exactly the same way; what changed is
  that nothing but `release-tag.sh` can ever create a tag, so a direct push to
  `main` can no longer produce one.

  Separately, `release-alpha.sh` now refuses an effective PATCH bump — derived
  from comparing the stated versions' MAJOR/MINOR, not from whether `--bump`
  was passed, since the incident that motivated this shipped with no `--bump`
  at all — that adds exported Go API to a published module since the previous
  release's tag. The comparison is `scripts/exportsurface`, a small
  dependency-free Go program (parses with `go/parser`, never resolves a
  module graph) that diffs the exported top-level declarations of every
  non-internal package under the root, `sdk/go` and `xkey` modules between two
  materialized trees — the previous tag via `git archive`, the fetched tip
  about to become the new release — and lists what was added.

  Files: `scripts/release-alpha.sh`, `scripts/release-tag.sh` (new),
  `scripts/exportsurface/main.go` (new), `Makefile`,
  `.github/workflows/release.yml`, `test/scripts/release-alpha.test.sh`,
  `test/scripts/release-tag.test.sh` (new), `docs/release-engineering/`.
  Verified by `make test-scripts`: the pure-function suite plus, end to end
  against throwaway fixture repositories with their own bare `dev` remotes —
  a dry run reads the network but writes nothing; prepare validates against
  what was just fetched even when the local checkout has never seen the
  remote's real state; a duplicate release branch is refused; the growth gate
  refuses an implied or explicit PATCH that grew the API and allows the same
  growth under MINOR; a real cut lands on a new branch, leaves `main` (local
  and remote) untouched, and refuses to prepare the same version twice; and
  `release-tag.sh`, using this repository's own agent signing key, refuses a
  stale `HEAD`, a branch mismatch, a `VERSION` mismatch, an unreachable
  release commit, an inconsistent pin set and a missing `CHANGELOG` heading in
  turn, then succeeds and pushes three verified, signed tags atomically.
- **`storage.CompareAndSwapper.CompareAndSwap` no longer treats a `nil`
  `expected` as "require the key to be absent" — BREAKING.** The contract used
  to give `CompareAndSwap` a second job: `expected == nil` meant "create only
  if the key is absent," the same precondition `PutIfAbsent` uses. That
  diverged from go-qrdb's own `GuardedKVClient.CompareAndSwap`, whose
  `KVEngine.handleCompareAndSwap` refuses unconditionally on an absent key
  ("an absent key is NOT created — a swap moves a record between two states,
  and a record that does not exist has no first state") and from this
  package's own `CompareAndDeleter.CompareAndDelete`, which already reads
  `nil` as "equivalent to an empty slice," never as a wildcard for absence. A
  swap now edits and never creates: `expected` — nil included — is compared
  as raw bytes against the current value, so `nil` matches only a stored
  empty value, and an absent key refuses regardless of what `expected` was. A
  caller that wants a guarded create uses `PutIfAbsent`, which already exists
  for exactly that precondition. One caller needed the old "absent-or-equals"
  combination — `pkg/pkcs11/module`'s remote lockout-counter increment,
  detailed below — and moved to `PutIfAbsent` plus a `CompareAndSwap` retry
  loop that never passes a nil `expected`; every other caller in this
  repository was already a plain value-compare or a pass-through and needed
  no change. Implementations updated to match: `pkg/storage/engine.go` (`engineBackend`,
  backing `NewMemory`/`NewFile`/`NewPebble`) now checks existence
  unconditionally before the byte comparison, instead of branching on
  `expected == nil`; `pkg/storage/qrdb/backend_compareandswap.go`'s
  transaction fallback now sends the same two ANDed preconditions
  `CompareAndDelete` already sends (`version > 0` **and** `value == expected`)
  instead of substituting a `version == 0` "absent" precondition when
  `expected` was nil — go-qrdb evaluates a value compare against `nil` for an
  absent key as a match (`bytes.Compare(nil, nil) == 0`), so a value-only
  compare would otherwise let a nil-expected swap create the key: exactly the
  wildcard this change removes. `pkg/storage/kvadapter/atomic.go`'s
  `atomicKVStoreAdapter.CompareAndSwap` — which used to refuse a nil
  `expected` outright specifically because the two contracts disagreed — is
  now a straight delegation, the same shape `CompareAndDelete` already had,
  because the contracts agree. `pkg/storage/prefix_compareandswap.go` and
  `pkg/storage/file/storage_compareandswap.go` needed no logic change; they
  already delegate to the engine. The shared conformance suite
  (`pkg/storage/storagetest/absentkey.go`, run by every fixture in
  `pkg/storage`, `pkg/storage/file`, `pkg/storage/luks`,
  `pkg/storage/sealed` and `pkg/storage/mocks`) now asserts that
  `CompareAndSwap` refuses on an absent key for a nil, empty, and non-empty
  `expected` alike, skipping backends that do not claim the optional
  `storage.CompareAndSwapper` capability.

  **The PKCS#11 remote multi-client lockout-counter caller moved to the
  explicit verb, in the same change.** `ModuleStorage.incrementViaCAS`
  (`pkg/pkcs11/module/storage.go`) used the old wildcard to create a token's
  failed-attempt counter on its first increment (`expected = nil //
  require-absent`); it now calls `PutIfAbsent` to create the counter at `1`
  when `Get` reports it absent, and only enters the `CompareAndSwap` retry
  loop once it holds real bytes — losing the create race just means a
  concurrent writer won, so it re-reads and falls through to the loop instead.
  The loop itself now treats a refusal's `current == nil` (a concurrent
  reset/delete) the same way, recreating rather than ever looping back into
  `CompareAndSwap` with a nil `expected`.

  The `PKCS11StateCAS` RPC's `ExpectAbsent` field
  (`pkg/api/transport/types_pkcs11state.go` and every transport that carries
  it: grpc, unix, quic, rest, plus the REST handler and grpc service) is kept
  on the wire for compatibility — no proto regeneration — but is REDEFINED:
  it no longer selects "require absent" on a compare-and-swap (there is no
  such precondition to select, post-#186); it now tells
  `pkg/xkms/servicer_pkcs11state.go`'s `PKCS11StateCAS` handler to perform
  `PutIfAbsent` using the request's `New` field as the value instead of a
  compare-and-swap. `pkg/pkcs11/module`'s `remoteBackend.CompareAndSwap`
  (`storage_remote.go`) no longer sets `ExpectAbsent` — it forwards `expected`
  as an ordinary value compare, nil included — because the module reaches
  `PutIfAbsent` directly through the RPC that already existed for it
  (`PKCS11StatePutIfAbsent`) rather than asking the CAS RPC to do double duty.
  `test/integration/cluster/cluster_cas_test.go`'s real 3-node Raft E2E test
  follows the identical split (`putIfAbsentCounter` then `swapCounter`, never
  setting `ExpectAbsent`) so it keeps proving the multi-client property against
  the real cluster.

  Verified: `pkg/pkcs11/module` passes in full under `-race`, including
  `TestModuleStorage_FailedAttemptCounter_CAS`,
  `TestModuleStorage_FailedAttemptCounter_ConcurrentAccumulates`, and the
  rewritten `TestRemoteBackend_CompareAndSwap` (plus the new
  `TestRemoteBackend_CompareAndSwap_NeverSendsExpectAbsent`, which pins that
  the client-side change actually took). `go vet -tags integration
  ./test/integration/cluster/...` is clean (the suite needs the real cluster
  to run). (#186, follows #125)
- **xkey: the CLI's, the GUI's and pkg/pairing's paired-device records are now one owned type** (#130, #124). `pairing.PairedDevice` (`xkey/pkg/pairing/device.go`) is the single definition of a `devices.yaml` record; `cmd.PairedDevice` and `services.phoneConfigDevice` are now type aliases to it rather than hand-maintained mirrors. Three times the two mirrors drifted on the same field — `attestation_protocol_version` missing from the GUI's copy silently read a CLI-paired challenge-response device as unbound (#95, #124 round 1, and the GUI mirror's own omission before this change) — and the fix is structural: there is nothing left to drift. The GUI's Wails-facing view model (`services.PairedDevice`) is now a pure projection, `deviceView(d pairing.PairedDevice, connected bool) PairedDevice`, and `pkg/gui/services/device_view_fieldset_test.go` reflects both types' field sets so a field added to one without a recorded decision for the other fails the build. The duplicated `attestationBinding()`/`recordVerifiedAttestation` methods are now the single `attestation.DeviceBindingFor` and `attestation.ApplyVerifiedAttestation` functions, shared by the CLI and the GUI. Every field carries both a `yaml` and a `json` tag; the `yaml` tags are byte-compatible with the pre-unification CLI's `devices.yaml` (verified by a byte-identical round-trip test against a fixture captured from the old CLI struct) and content-compatible with the GUI's `phone.yaml` (verified by a content-identical round-trip test against a fixture captured from the old GUI struct — the two pre-unification writers used different field orders for the same record, so only one order could be carried forward byte-for-byte; the GUI's test documents the exception). The GUI's per-device attestation snapshot and policy types (`savedAttestationData`, `attestationPolicy`) move to `pkg/pairing` as `PairedDeviceAttestationSnapshot` and `PairedDeviceAttestationPolicy`; `PhoneService.GetAttestationPolicy` now returns the latter, and its Wails TS bindings (`frontend/wailsjs/go/models.ts`, `frontend/wailsjs/go/services/PhoneService.d.ts`) were hand-edited to match — `wails` is not installed on this host to regenerate them — which also fixes a latent JSON key-casing mismatch: the frontend's own `AttestationPolicy` interface already expected snake_case keys that the old untagged Go struct never sent. Also removed as dead exports while unifying the record: `pairing.DeviceType` and its four constants, `pairing.EnrollmentMethod` and its eight constants, `pairing.TransportType` and its three constants, and the unrelated `pairing.AttestationPolicy` struct (`RequireTPM`/`RequireSecureBoot`/`RequireBiometric`/`MinSecurityLevel`/`AllowedPCRBanks`) — none were ever constructed or enforced anywhere in the module, `sdk/go`, or the Wails TS bindings; their `phone.DeviceType`/`phone.AttestationPolicy` re-exports in `pkg/phone/pairing_reexports.go` are removed with them. Two legacy docs (`docs/device/README.md`, `docs/device/pairing.md`) described these as if implemented and are corrected.

### Removed

- **Two orphaned ACME rate limiter implementations are gone.** `pkg/acme/ratelimits/` (GCRA-based limiter, decision/limit/source/transaction types) had zero importers anywhere in the tree. `pkg/acme/client/rate_limiter.go`'s `NewRateLimiter`/`RateLimiter` token-bucket implementation was reachable only from its own tests — `pkg/acme/client/trustedca.go` wires the ACME server's rate limiting through `server.NewRateLimiter` (`pkg/acme/server/rate_limiter.go`) instead, which is unaffected and stays. Both orphans and their tests are deleted; `pkg/ratelimit` (the general-purpose limiter used elsewhere in the stack) is unaffected and stays, and the option A consolidation onto go-qrdb's rate-limit policy types remains deferred until go-qrdb's SDK re-exports them. Refs #538.
- **`xkey/pkg/agent.ClientConfig.LocalAddress` is gone — BREAKING (config).**
  The field was declared, defaulted to `localhost:19443`, and documented as
  the local reverse-proxy bind address, but nothing read it: `Client.Connect`
  only ever dials `MasterAddress`, and no code in `pkg/agent` opened a
  listener on it — the field had no config-file, environment, or flag path
  to begin with. `ClientConfig`, `DefaultClientConfig` and the `Client` doc
  comment (which claimed the client "exposes its services locally via gRPC
  reverse proxy") are updated to describe what actually exists: an mTLS
  connection to the master with automatic reconnect. Any `local_address` key
  still present in a client config file is now unused rather than silently
  dropped by dead code; remove it. (#513)
- **`ca.TLSConfigOptions.PreferServerCipherSuites` is gone (#224).** The field was
  never propagated to `tls.Config` — Go has ignored
  `tls.Config.PreferServerCipherSuites` since 1.18, so it had been a
  no-op deprecated knob kept only so existing callers compiled. The two
  call sites that set it (`ServerTLSConfig`, `MutualTLSConfig`) are
  updated. This is a breaking removal of an exported field; callers
  setting it must delete the reference, which changes nothing about
  the resulting TLS configuration.

### Fixed

- **`pkg/acme/qrdb` config validation now refuses `barrier.enabled: true` up
  front, instead of letting `New` build an embedded QRDB server that can
  never be unsealed.** `BarrierConfig` (config.go) has no credential or
  auto-unseal source, so enabling it only deferred the failure to the first
  data-plane call, which failed with "data-plane barrier is sealed"
  (service.go). `Config.Validate` now returns the typed
  `ErrBarrierCredentialUnsupported` error as soon as `Barrier.Enabled` is
  true, so `New` fails fast at configuration time. The field is kept —
  existing configuration files with `barrier.enabled: false` still parse —
  and its doc comment states the constraint: encryption at rest for the ACME
  data plane is configured through the parent xkmsd barrier instead (#551).
- **`pkg/storage/qrdb`'s `Backend.CompareAndSwap` no longer builds an illegal
  transaction** (#125). It put an `OpGet` in the transaction's `FailureOps` so
  a failed swap could report the current value, and go-qrdb's transaction
  service rejects any op other than Put/Delete in a success or failure branch
  — a branch executes atomically as a single Raft write with no per-op
  read-result channel, so `service: unsupported transaction operation type 1
  (transaction branches support only Put and Delete)` refused every
  `CompareAndSwap` a caller with a transaction-capable client issued, on every
  engine. The transaction now carries no failure branch — the same shape
  `PutIfAbsent` and `CompareAndDelete` already use in this package — and on a
  refused swap `current` is fetched with a follow-up `Get` instead: the
  contract already documents `current` as advisory for a retry, so nothing is
  lost by reading it a moment later. Files: `pkg/storage/qrdb/backend_compareandswap.go`,
  `pkg/storage/qrdb/backend_compareandswap_test.go`. Verified by tests pinning
  the transaction's shape (`FailureOps` carries no read op, on both the
  success and refusal paths) and the behavioural contract (a stale expected
  value refuses the swap, `current` reports the value actually present via the
  follow-up `Get`, and the stored value is left unchanged).

  This was independent of the rest of #125 at the time it was written: the
  embedded constructors in `pkg/storage/qrdb/factory.go` (`NewMemory`,
  `NewFile`, `NewPebble`) still wired no transaction service at all, so this
  fix alone did not make `CompareAndSwap` or `PutIfAbsent` reachable through
  them. The remainder — preferring `transport.GuardedKVClient` over the
  transaction, which needs no transaction service — is the companion
  "guarded-writes-125" entry in this same unreleased set; together the two
  entries close #125.
- **`pkg/storage/qrdb`'s embedded constructors (`NewMemory`, `NewFile`,
  `NewPebble`) now serve `PutIfAbsent` and `CompareAndSwap`** (#125). Both
  methods dispatched exclusively to `transport.TransactionClient`, and
  `newEmbedded`'s `embedded.New(kvSvc, adminSvc)` wires no transaction
  service, so every embedded constructor failed both verbs identically with
  `embedded: TransactionServicer must not be nil` — even though the same
  client already implements `transport.GuardedKVClient`, which delegates
  straight to the KV service and needs no transaction service at all.
  `CompareAndDelete` already preferred that capability (go-xkms#406, once
  go-qrdb's `FastStateMachine` gained the guarded-delete opcode in
  v0.16.3-alpha); `PutIfAbsent` and `CompareAndSwap` simply never asked for
  it. Fixed by giving both the same GuardedKVClient-first, TransactionClient-fallback
  dispatch order, so a capability refusal (not any other failure) is the only
  thing that falls through to the transaction. `Backend.GuardedWritesAvailable`
  and `NewBackend`'s capability detection are updated to match: a client
  offering either capability now reports guarded writes available, not only
  one carrying a transaction.

  No on-disk layout changed and no data migration is needed: `newEmbedded`
  still builds the same `Storage -> FastStateMachine -> LocalBackend ->
  KVService/AdminService -> embedded.Transport` stack over the same
  `qrdbsdk.NewFileStorage` / `NewPebbleStorage` / `NewMemoryStorage` engines
  it always did, so every directory an existing `NewFile`/`NewPebble` backend
  wrote is read back unchanged (`TestClose_FlushesPendingWrites` reopens a
  file/pebble directory across `Close` and still finds every key). Routing
  these constructors onto `storage.OpenEngine` instead — the option the
  issue's discussion raised — was not taken: `pkg/storage` already imports
  `pkg/storage/qrdb` (`constructors.go` delegates `NewFile`/`NewPebble` here),
  so the reverse import would be a compile-time cycle, and `OpenEngine`'s
  `engineBackend` reaches guarded writes by a different mechanism entirely (a
  process-local mutex over the raw storage engine, never a transaction
  service or the embedded transport). Reaching the same outcome by correcting
  the dispatch order is smaller and avoids both the cycle and a data move.

  Files: `pkg/storage/qrdb/backend_putifabsent.go`,
  `pkg/storage/qrdb/backend_compareandswap.go`, `pkg/storage/qrdb/backend.go`,
  `pkg/storage/qrdb/factory.go`. Verified by tests pinning the dispatch order
  (GuardedKVClient preferred, capability refusals — and only those — fall
  through to the transaction, in `backend_gaps_test.go` and
  `backend_compareandswap_test.go`) and by conformance tests against the real
  constructors (`factory_cas_characterization_test.go`,
  `pkg/storage/constructors_test.go`,
  `pkg/storage/absentkey_contract_test.go`,
  `pkg/storage/kvadapter/atomic_test.go`) confirming `PutIfAbsent`,
  `CompareAndSwap` and `CompareAndDelete` all execute, a stale
  `CompareAndSwap` guard leaves the stored value untouched, and
  `kvadapter.New` now hands the DAO layer an `AtomicKVStore` for these
  backends. This closes #125; the OpGet-in-a-transaction-branch fix on this
  same branch has its own entry above.
- **A discoverable (usernameless) WebAuthn login can now complete (#558).**
  `finishLoginUser` only fell back to the session's own record of the
  ceremony — discoverable or user-identified — when the caller supplied no
  handle at all. A caller that resolves the assertion to a user afterward and
  passes that handle along, as `pkg/auth_factors`'s `Verify` does once qrdb
  has matched the credential to an enrolled factor, was routed into the
  user-identified branch regardless of how the ceremony began. go-webauthn's
  `ValidateLogin` then compared that non-empty handle against the empty
  `session.UserID` a discoverable `BeginLogin` leaves behind and rejected
  every usernameless login with "ID mismatch for User and Session". The
  session, not the caller-supplied handle, now always decides which ceremony
  is in play, matching the comment already written above the check.
- **`xkey` has exactly one governing PIN backend per device, read by the GUI, the headless daemon and `xkey pin` alike (#307, #272).**
  A PIN set through the desktop GUI's TPM2 wizard used to authenticate the
  GUI itself but not `xkey pin` or `xkey extension serve`, which
  hard-coded the software backend regardless of what the GUI had
  persisted (`GUIConfig.PINStrategy`, a GUI-only, cgo config file). A
  value that verified `VALID` against one store answered `invalid PIN`
  against the other, and each failed retry against a TPM-backed store
  spent one of its limited dictionary-attack attempts. The governing
  strategy now lives at `<dataDir>/pin/strategy`, beside the PIN state it
  governs, owned by the new non-cgo `xkey/pkg/pinstrategy` package:
  `pinstrategy.Resolve` auto-selects hardware-first on a fresh install and
  persists the choice, or builds exactly the persisted strategy's backend
  on every later call. `xkey pin` and `xkey extension serve` gained their
  own TPM provider adapter (`pinstrategy.NewTPMProvider` over a
  short-lived TPM open, `openTPMModule`, shared with the barrier
  strategy's `probeTPMSealer`); the GUI's `initPINService` now delegates
  to `services.ResolvePINBackend`, which performs a one-time migration of
  an older install's `GUIConfig.PINStrategy` into the shared file. A
  device whose persisted strategy needs a provider unavailable in this
  build/host (typically `tpm2` probed from a host with no TPM) is refused
  with a typed `*pinstrategy.ProviderUnavailableError` — via `xkey pin
  verify`/`status`, or `xkey extension serve` failing to start — rather
  than silently answering from a different backend. `xkey pin status`
  now always names the strategy that actually governs. `--unified-pin`'s
  help text and docs no longer claim to synchronize a PKCS#11 or file PIN
  store: it only propagates the FIDO2 PIN hash
  (`authenticator.Config.UnifiedPIN`, via
  `qrdbsdk.PINService.SetFIDO2HashSetter`), which is the only thing it
  ever did. `xkey/pkg/pinstrategy` and its callers reach `pkg/pinselect`
  and `pkg/pintpm2` exclusively through new `sdk/go` re-exports
  (`PINSelectConfig`, `ErrPINSelectNoSoftwareProvider`,
  `PINSelectSoftwareStorageError`, `PINTPMBackend`, `NewPINTPMBackend`),
  never by importing `go-xkms/pkg/*` directly, per the SDK boundary
  Architecture Gate.
- **xkey setup wizard: refuses to persist `barrier_strategy: tpm2` when this build/host has no usable TPM sealer.** #510 item 1 (items 2 and 3 landed separately: the app-lock misclassification and the hardware→passphrase fallback firing over an existing barrier). `ApplySetup`'s config-commit switch persisted `updated.BarrierStrategy = choices.SealerBackend` on every failed barrier attempt, including when a barrier already existed and would not unseal because `assembleStrategy("tpm2")` found no TPM sealer wired in (`BarrierService.tpmSealerFn == nil` or `CanSeal() == false`) — the same condition `AppLockService` now classifies as `ErrAppLockUnsealUnavailable`. Writing `tpm2` in that case commits a config this build's GUI can never unseal on its own.

  `SetupWizardService.refuseUnavailableStrategyPersist` is the single guard point: it re-checks tpm2 availability through `BarrierService.ProbeStrategies` and, when unavailable, skips the config write and reports the new `ErrSetupSealStrategyUnavailable` instead — the prior config value (if any) is left untouched rather than cleared or overwritten. It is scoped to `tpm2` only: the passphrase path, a barrier with no service wired at all (the legacy test-only path), and a genuine hardware/credential failure against an *available* tpm2 strategy (`CanSeal() == true` but `Unseal` fails for another reason, e.g. `TPM_RC_BAD_AUTH`) are all unaffected and still persist the requested strategy for retry, matching existing behavior.

  Files: `xkey/pkg/gui/services/setup_wizard_service.go`, `xkey/pkg/gui/services/errors.go`, `xkey/pkg/gui/services/setup_wizard_tpm2_guard_test.go`. Verified with `go test ./xkey/pkg/gui/services/ -run 'RefuseUnavailableStrategyPersist|TestApplySetup_TPM2|TestApplySetup_PassphraseStrategy_UnaffectedByTPM2Guard'`, covering: the guard refusing tpm2 (no sealer wired, and sealer wired but `CanSeal() == false`) and writing nothing; the guard allowing tpm2 once a working sealer is injected; a prior config value surviving a refused write untouched; a genuine hardware failure against an available tpm2 strategy still persisting for retry; and the passphrase path unaffected. Item 1's verification on an actual TPM host, and the re-unseal-in-place runtime half of #510, are still owed — this closes the setup-time persistence gap only.
- **Fixed**: `CopyKey` now wraps key material for the DESTINATION backend's
  own import parameters, so a copy between two independent backend instances
  actually unwraps (#154, #567). `ExportKey` wraps a key under a wrapping
  key the EXPORTING backend mints and tracks for itself, naming the result
  by that backend's own import token; handing that material to a different
  backend instance's `ImportKey` named a wrapping key it had never heard of.
  For the software backend this failed lookup silently (the destination's
  `importTokens` map holds no entry for a token another instance minted); for
  a token-checking backend it surfaced as an unwrap failure. `ExportBackend`
  gains `ExportKeyTo(ctx, attrs, dstParams)`, which wraps under
  caller-supplied `ImportParameters` — obtained from the destination's own
  `GetImportParameters` — instead of parameters the exporting backend mints
  itself. `CopyKey` (both `XKMSService.CopyKey` and the package-level SDK
  `CopyKey`) now calls the destination's `GetImportParameters` first and
  passes the result straight to the source's `ExportKeyTo`, so the material
  the destination's `ImportKey` unwraps was genuinely wrapped under its own
  key, never staged in plaintext in the service in between.

  Every backend implementing `ExportBackend` implements `ExportKeyTo` in this
  change: the software backend and the symmetric key-provider backend
  perform a real re-wrap, because their `WrapKey` is a pure cryptographic
  operation over the `ImportParameters` it is given and touches no backend-
  private state. PKCS#11, TPM2, AWS KMS, GCP KMS, Azure Key Vault, HashiCorp
  Vault, and the phone hardware backend return the new typed
  `backend.ErrExportToUnsupported` sentinel instead: their wrap primitives
  bind to a key object the backend itself manages (an HSM wrapping-key
  handle, a TPM object, a provider's BYOK ceremony), not an arbitrary public
  key a caller hands in, so they refuse rather than emulate a wrap their
  hardware or service does not actually perform.

  `pkg/migration`'s `defaultMigrator.importKey` carried the identical defect
  independently of `xkms.CopyKey`: it called the source's self-minted
  `ExportKey`, then overwrote the resulting `WrappedKeyMaterial.ImportToken`
  with the destination's own token, leaving the ciphertext wrapped under one
  key and named by another. `MigrateKey` (and therefore `MigrateAll`, which
  calls it per key) now calls the destination's `GetImportParameters` first
  and wraps through the source's `ExportKeyTo`, exactly as `CopyKey` does; the
  token-overwrite line is deleted rather than reconciled, since `ExportKeyTo`
  makes it unnecessary.

## [0.14.0-alpha] - 2026-09-20

### Security

- **The `fido2-attestation` profile certifies only authenticator models the
  operator has vouched for (#242).** The profile copied `id-fido-gen-ce-aaguid`
  out of the request verbatim, so any device that cleared the provisioning
  ceremony — physical possession plus the Security Officer PIN — could name any
  AAGUID it liked and the CA would certify it. That made an xkms-issued
  attestation certificate useless as evidence of *model*: a policy such as
  "only this authenticator may register as an administrator" was unenforceable,
  because an insider holding an SO PIN could provision a software device
  claiming a hardware AAGUID and receive a certificate saying so.
  `NewFIDO2AttestationProfile` now takes the AAGUIDs it may certify and refuses
  every other one with `ErrFIDO2AttestationAAGUIDNotPermitted`, naming the
  refused AAGUID in RFC 4122 form and pointing at the profile to register to
  admit it. Both routes into the extension are covered: the device's
  `CSRExtensions` and a direct caller's `ExtraExtensions`, which the issuer
  would otherwise append unchecked.

  Called with no arguments the profile permits exactly `ca.XKeyAAGUID`, the one
  authenticator this project ships, which is what `NewDefaultProfileRegistry`
  installs; there is no argument that permits every AAGUID, so the control
  cannot be switched off by leaving it unconfigured. The listed AAGUIDs are the
  whole policy and `ca.XKeyAAGUID` is not unioned into an operator's list. An
  operator running other models registers a profile built with the full set
  under `ProfileNameFIDO2Attestation` — a deliberate administrative act,
  distinct from provisioning, which is how the first device of a newly approved
  model is admitted. Files: `pkg/ca/profile_fido2.go`, `pkg/ca/errors.go`,
  `pkg/ca/profile_fido2_test.go`, `docs/ca/architecture.md`. Verified by
  `go test ./pkg/ca/...`: the shipped model issues, an unlisted model is
  refused by both routes, an explicit list admits exactly what it names, and
  the refusal text carries the AAGUID.
- **A tenant's MCP key import landed in the untenanted namespace, where the
  importing tenant's own reads could not find it, and every `copy_key` through
  a token-honouring backend produced a key that could not be unwrapped**
  (#222). `handleImportKeyMaterial` passed no `TenantID` to the service at all,
  so the import resolved the unscoped backend and wrote under an identifier
  carrying no tenant prefix — the #162/#163 family, a tenant's write going
  somewhere that tenant cannot read, not a cross-tenant disclosure. The
  withholding was deliberate while an imported key persisted no metadata record
  to be read back from; both key providers have persisted the tenant since
  #163, so the reason had lapsed and only the symptom remained. The import now
  runs under the caller's tenant through `tenantForRequest`, and
  `get_import_parameters` and `copy_key` take their tenant from the same helper
  rather than from `callerTenantID` directly, so a request that names a tenant
  of its own is refused with `ErrTenantIDNotAccepted` instead of having the
  field silently dropped by the decoder. Separately, `XKMSService.CopyKey`
  asked the destination backend for fresh import parameters and overwrote the
  exported material's import token with theirs: `ExportKey` wraps under a
  wrapping key the exporting backend mints for that export and names it by the
  token it returns, so the override pointed `ImportKey` at a different key than
  the material was wrapped under and the unwrap failed. The export's own token
  is now passed through untouched, the destination attributes carry the
  destination store type plus the source's digest and partition, and
  `ExportKeyResponse`/`WrapKeyResponse` no longer drop the import token and
  metadata that must travel with the blob. `pkg/api/mcp/handlers.go`,
  `pkg/api/mcp/types.go`, `pkg/api/transport/types.go`,
  `pkg/xkms/servicer_key.go`, `docs/multi-tenancy/`. Verified by
  `pkg/xkms/servicer_key_tenant_copy_test.go`, which asserts the copy holds the
  source's key material — provable only if the unwrap succeeded — and that it
  is visible to the copying tenant and to no other, and by
  `pkg/api/mcp/handlers_keyops_tenant_test.go`, which pins the import to the
  authenticated tenant and the refusal of a caller-supplied one.
- **A system-tenant identity can no longer reach another tenant's escrow
  records.** The qrdb permission vocabulary xkms consumes gained a fourth
  scope, `ScopeSelfStrict`, which admits a request only when the caller's
  own tenant is the target tenant — for *every* identity, the system tenant
  included. The three existing scopes could not express that: `ScopeSelf`
  admits the caller's own tenant **or** a system-lifted identity acting
  across tenants, `ScopeCross` is system-only by design, and
  `ScopeTenantOnly` excludes the system tenant altogether, so the system
  tenant could not use it for its *own* data. Escrow therefore sat on
  `ScopeSelf` and inherited the system lift, which made a system
  administrator able to read any tenant's escrowed key material. Each
  tenant, including the system tenant, is its own boundary; a system
  administrator administers the system tenant, it does not impersonate the
  others. Taking go-qrdb v0.19.0-alpha activates the new scope — enforcement
  lives entirely in qrdb's permission layer, so no xkms call site changes.
  The bump is purely additive: the qrdb `sdk/go` exported surface went from
  2730 to 2731 declarations with zero removals.

### Fixed

- **`CI / Lint` is green again, which unblocks every other job in the pipeline.**
  The gate was failing on `main` itself, and because `test`,
  `nested-module-test`, `security`, `build-raft` and `race` all declare
  `needs: [lint, ...]`, a red Lint SKIPPED them — and a skipped job is not a
  passing one, so `CI Gate` failed and every open pull request was refused at
  merge with "not all required status checks successful". Two independent
  causes, both fixed here. Thirteen test files had no trailing newline (#561,
  #562); twelve are the ones `gofmt` has always flagged, and
  `pkg/pkcs11/module/module_keygen_quantum_test.go` is flagged only by Go
  1.27's `gofmt`, which indents a multi-value return of composite literals
  differently — so it appears the moment CI moves to 1.27. And four
  golangci-lint findings (#563) sat behind the formatting failure, invisible
  until it was fixed: `registry.Close()` discarded on two error paths in
  `pkg/escrow/factory.go` (its aggregated per-agent close failures are now
  joined into the returned error), gRPC's deprecated `SecurityVersion` in
  `peercred_transport.go` (removed; nothing read it), and the uncalled
  `resolveExportBackend` in `pkg/api/rest/handlers.go` (deleted — the export
  path asserts `backend.ExportBackend` inline, exactly as the dead helper did).
- **The PKCS#11 module's FIPS labels now rest on the artifact's build
  provenance instead of the module state of the process that loaded it**
  (#219). `pkg/crypto/fips/fips.go`, `pkg/pkcs11/module/mechanism.go`.
  `fipsBuild` read `fips.Compiled` — `crypto/fips140.Enabled()` — which is
  runtime module state, not build provenance: `GODEBUG=fips140=off` turns it
  false on a binary genuinely built with `GOFIPS140`, and `GODEBUG=fips140=on`
  turns it true on one that was not. A user reading `CK_INFO.libraryDescription`
  or `CK_TOKEN_INFO.model` to confirm they hold a FIPS module could therefore be
  told the wrong thing in both directions: the shipped `libxkms_pkcs11_fips.so`
  denied being a FIPS build under `fips140=off`, and a stock build claimed to be
  one under `fips140=on`. New `fips.BuildSetting` and `fips.Built` read the
  `GOFIPS140` value the toolchain stamps into the binary at link time (the
  `build GOFIPS140=<value>` line of `go version -m`), which no environment
  variable alters and which survives into a c-shared library a foreign process
  `dlopen()`s; `fipsBuild` now reads `fips.Built`, so the label describes the
  artifact and nothing else. `BuildSetting` returns the selector the build ran
  with — `latest`, `inprocess`, `certified` or `v1.Y.Z` — so a compliance
  manifest can name the module version rather than only the fact of a FIPS
  build. **`AlgorithmPermitted` is deliberately unchanged**: the approved-only
  allowlist still follows `Compiled() || Enabled()`, the crypto actually in
  force, so an operator who sets `GODEBUG=fips140=off` has turned the module
  off and the predicate permits everything, exactly as in a non-FIPS build —
  whether a validated artifact may be talked out of its posture that way is the
  owner's policy call recorded on #219, and changing it means adding `Built` to
  that OR and nothing else. Verified by measuring a probe built both ways
  (`GOFIPS140=latest` records the setting and it persists under
  `GODEBUG=fips140=off`; an unset build and an explicit `GOFIPS140=off` build
  both record nothing, so absent and off read back alike through `Built` while
  `BuildSetting` still distinguishes them), by unit tests driving
  `buildSettingFrom`/`builtFrom` with synthetic build metadata including the nil
  and setting-absent cases, by tests pinning `BuildSetting` and `Built` against
  the `GOFIPS140` environment variable that must not move them, and by the
  PKCS#11 label suite, which re-execs itself under `GODEBUG=fips140=on` and
  `=off` and asserts the labels hold still in both.
- **The ACME client silently ignored a server's `Retry-After` backoff whenever
  the value overflowed a `time.Duration` or used either of the two HTTP-date
  forms besides IMF-fixdate** (#564). `parseRetryAfter` returned a
  `time.Duration` and `RateLimitedTransport.RoundTrip` gated on `duration > 0`,
  so three separate inputs collapsed to "no hold-off" and the client kept
  hammering a server that had just answered `429`: a digits-only value above
  `math.MaxInt64 / int64(time.Second)` (~9.22e9) wrapped negative in
  `time.Duration(seconds) * time.Second` — measured, `"10000000000"` yielded
  `-2346317h47m53s`; the hand-rolled `parseInt` had no overflow check, so
  `"99999999999999999999999"` wrapped to `200376420520689663` rather than being
  detected as out of range; and `time.Parse(time.RFC1123, ...)` rejected the
  RFC 850 and asctime dates that RFC 9110 §5.6.7 requires a recipient to
  accept, returning `0`.

  The parser now follows RFC 9110 §10.2.3: delta-seconds via
  `strconv.ParseUint` (digits only, clamping both the `ErrRange` case and any
  value beyond the representable duration), HTTP-date in all three forms via
  `http.ParseTime`, and an already-elapsed date rejected in the parser instead
  of incidentally by the caller. It returns the absolute instant rather than a
  duration, so the transport hands it to the existing `SetRetryAfterTime`
  unrounded — no round trip through `time.Until` and a second `time.Now()`. The
  parser's clamp composes with `storeRetryDeadline`'s year-2262 clamp, so a
  far-future deadline stays representable and reads back as blocked. The
  now-unused `parseInt` and its test are removed; the deadline storage, the
  overflow clamp and the compare-and-swap clearing in `waitRetryAfter` / `Allow`
  are unchanged and still covered by `rate_limiter_deadline_test.go`.
  `pkg/acme/client/rate_limiter.go`, `rate_limiter_test.go`,
  `docs/acme/client.md`. Verified by table-driven parser tests over
  delta-seconds, each of the three date forms, an elapsed date, an equal-to-now
  date, both overflow paths and malformed input, plus transport tests that an
  HTTP-date header stores the named instant exactly and an unparseable one
  installs no hold-off.
- **Password and PIN changes work again under go-qrdb v0.19.0-alpha.** Every
  password-change path was failing with `passphrase strategy is not a software
  strategy`: PKCS#11 token PIN changes (`pkg/pkcs11/localseal`), the xkey GUI
  password change, and barrier `ChangePassword` on every transport. go-qrdb
  v0.19.0-alpha's `ChangePassword` reads the registered strategy's KDF version
  and work factor so a password change preserves a deployment's tuned factor
  rather than silently resetting it to library defaults; xkms registered a
  95-line wrapper struct around go-quicraft's strategy that forwarded every
  method verbatim but **not** `KDFVersion()`/`KDFParams()`, so the parameters
  the re-seal needs were structurally hidden. `pkg/seal.SoftwareStrategy` is now
  a type alias for the canonical go-quicraft strategy re-exported through the
  qrdb SDK, and `NewSoftwareStrategy` re-exports the **deferred** constructor,
  which binds its passphrase at each Seal/Unseal — never the bound one, which
  ignores the credentials handed to unseal and would make wrong-secret unseals
  succeed for the life of the process (go-qrdb#157). xkms contributes only
  hardware seal strategies (TPM2, PKCS#11, cloud KMS); the barrier and seal
  layer belongs to go-qrdb, and a forwarding-only wrapper was just a place for
  the two sides to drift. A wrong passphrase now surfaces as
  `seal.ErrDecryptionFailed` instead of `seal.ErrInvalidCredentials`, which
  remains the sentinel for the hardware path, so the REST barrier/PIN, REST
  tenant and gRPC error mappers gained matching arms: without them a wrong
  password would have degraded from 401 to 500, and that default branch writes
  the raw error, disclosing the crypto library and strategy name to an
  unauthenticated caller. `TestBarrierUnsealHandler_InvalidCredentials` asserted
  only `NotEqual(200)`, which a 500 satisfies, and is tightened to `Equal(401)`
  so the regression cannot recur unseen. Verified: the five previously failing
  tests pass, `pkg/seal` 90.8%, `pkg/api/rest` and `pkg/api/grpc` suites green,
  build and vet clean across all four modules.

## [0.13.0-alpha] - 2026-09-16

### Security

- **ACME finalize enforces complete CSR identity matching with order authorization.** Per RFC 8555 Section 7.4, the finalize handler now requires the CSR's complete identity set — its CommonName plus all DNS and IP Subject Alternative Names — to correspond exactly to the order's authorized identifiers in both directions: a name the CSR carries that the order did not authorize is rejected, and an authorized identifier the CSR omits is also rejected. Email and URI SANs are rejected wholesale; only DNS and IP identifiers are permitted. This closes the gap that previously allowed issuance of SANs authorized in the order but omitted from the CSR (which the RFC forbids). The authorization check now runs before any certificate work begins, so a CSR that fails matching fails fast. The stored certificate's identity set, never the submitted CSR's, feeds all subsequent authorization decisions.
- **ACME revocation requires byte-exact DER match and invokes canonical CA revocation.** The revoke-cert handler now mandates that the submitted certificate's DER encoding byte-equals the stored certificate before any authorization is checked, closing a gap where a self-signed certificate forged with a victim's serial number would sail through authorization using names the attacker chose. Authorization decisions use the stored certificate's identities exclusively, never the submitted one's. After authorization succeeds, revocation is invoked through the canonical CA revocation entry point (mirroring admin revocation) before the ACME certificate record is touched, so the CA's revocation list and CRL actually reflect the revocation instead of only the ACME bookkeeping. An already-revoked certificate is treated as success; the desired end state — revoked — already holds.
- **google.golang.org/grpc v1.83.2 in every module.** Trivy began failing the
  `Docker Build & Scan` job on every push to `main` from 2026-09-09 05:12Z
  with one HIGH finding in the CLI image's Go binary, CVE-2026-84445 (gRPC-Go
  xDS servers: denial of service via crash) against the pinned v1.83.1. No
  repository change caused it: the advisory landed in the scanner database
  between two identical builds. The pin moves to the fixed v1.83.2 in the
  root, `sdk/go`, `xkey` and `web/desktop` modules, which is the whole diff.
- **gRPC peer-credential authentication is now functional; Unix admin socket denials now work correctly.** The pkg/acme/api/server peer-credential interceptor now extracts real SO_PEERCRED/LOCAL_PEERCRED from Unix domain socket connections via PeerCredentialsAuthInfo on the peer.Peer.AuthInfo. Previously the interceptor was present but credentials were never populated, so the UID-to-role mapper always saw nil and the admin socket denied every request. The interceptor continues to pass through TCP connections without credentials (no SO_PEERCRED equivalent), so remote gRPC clients connect as before. Authorization against UID roles now works as intended for Unix-local admin access.
- **Pairing a phone from the xkey desktop GUI now attests the device, and
  refuses an unattestable one by default (#115, #131).** `PhoneService.Pair`
  ran the Noise handshake, sent the pairing confirmation and wrote the record
  without ever requesting an attestation, so a device that could never
  produce a valid one paired from the GUI while `xkey device pair` refused it
  — and the resulting record carried no device fingerprint, which left the
  reconnect fingerprint check inert for every GUI-paired device. The GUI now
  runs the same decision the CLI runs (`attestation.AttestOverSession`, chain
  verified to a trusted Android hardware root plus a live signature over this
  pairing's challenge) before anything is written, persists the same
  `device_fingerprint`, `attestation_protocol_version`, security level, boot
  state and boot hash the CLI would, and resolves the unattestable-device
  policy through the one shared function, `attestation.AllowUnattestablePairing`,
  over the same two planes: `devices.yaml`'s
  `attestation_policy.allow_unattestable_devices` and the sealed
  `policy:` section's `pairing_allow_unattestable_devices` gated by
  `lock_pairing_attestation_policy`. A refusal returns
  `ErrPhonePairAttestationRefused` and writes nothing; a policy-allowed
  unattestable pairing writes the pairing half of the record and no
  attestation claim, exactly as the CLI does. A missing trust store, or an
  `xkey.yaml` that exists but cannot be read, refuses rather than admits.

  Two mirror defects surfaced with it: the GUI's `devices.yaml` mirror had no
  `attestation_policy` field, so every GUI save erased the user's
  `xkey device pair` settings, and no `device_boot_hash_hex`, so a GUI save
  dropped the boot hash a CLI attestation wrote. Both now round-trip.

  **Upgrade note:** a phone that fails attestation can no longer be paired
  from the GUI unless policy opts in. The in-memory phone responder the
  CLI's interop test used moved to `xkey/pkg/attestation/attesttest` so both
  pairing surfaces are tested against the same reading of the wire contract.
- **`KeyWrapper.Wrap(plaintext []byte)` is replaced by
  `WrapFrom(src *secure.Buffer)`, so the interface can no longer express a
  wrap of key material staged on the ordinary Go heap** (#387). This is the
  mirror of the unwrap transit #291 closed: the plaintext is read through a
  borrow on a protected buffer the caller owns and streamed straight into the
  ciphertext, never copied. `InitializeSOPIN` now generates the Admin Key and
  Credential Master Key directly into mlocked memory and adopts them as they
  are, where previously both spent their first moments on the heap; the
  PKCS#8 attestation encoding, which `x509` can only marshal onto the heap, is
  moved into protected memory by `secure.NewBufferFromBytes`, which wipes the
  heap copy as it does so. `KeyManager.WrapCredentialKey` and
  `KeyManager.WrapAttestationKey` take a `*secure.Buffer` the caller destroys
  afterwards; `WrapFrom` refuses a nil or destroyed source with
  `ErrInvalidWrapSource`. Because protected-buffer borrows must not nest, every
  wrap of one protected key under another goes through `wrapFromProtected`,
  which releases the wrapping-key borrow before the plaintext borrow is taken;
  a regression test drives every wrap path under purge-class contention so a
  re-nested borrow hangs into the test timeout instead of passing by luck.
- **A partial config section keeps the defaults it omits (#114).** The
  loader seeded each section of `xkey.yaml` as one opaque viper default and
  decoded onto a zero `Config`, so the moment a file named a section, every
  key the file did not set in that section landed on its Go zero value
  instead of its `DefaultConfig()` value. A file containing only
  `policy: {min_pin_length: 8}` therefore loaded with `require_user_pin`,
  `require_so_pin` and `require_encrypted_storage` all `false`,
  `pin_max_attempts` 0 and `storage_type` empty: an administrator tightening
  one policy value silently switched off every other gate in the section,
  and a policy sealed after that point sealed the weakened one. The same
  shape affected all thirteen defaulted sections. The loader now decodes
  onto `DefaultConfig()`, so a section merges key by key: an omitted key
  keeps its default, an explicit value — an explicit `false` or `0`
  included — still wins, and a list the file sets replaces the default list
  outright. A deployment whose file names a section and, knowingly or not,
  relied on the omitted keys being zero gains the defaults on upgrade; for
  the `Require*` gates that is a tightening. Pinned by a per-section table
  test that compares the whole loaded `Config` against `DefaultConfig()`
  with the one set key applied.
- **SECURITY: the module's PIV login proves the key is on a smartcard (#200).**
  `POST /api/v1/auth/login/piv` authenticated on a TLS client-certificate
  binding plus an optional issuer-DN string match, and a DN is not evidence:
  a self-signed software key could assert any issuer. The exchange now accepts
  a certificate as hardware-backed only when some certificate the client
  presents chains to the operator-configured PIV attestation anchor
  (`auth.piv_login.attestation_roots`, with optional
  `attestation_intermediates`; `AttestationRoots` / `AttestationIntermediates`
  on `PIVLoginOptions` and the SDK's `ServiceModulePIVLoginOptions`) AND
  carries the login certificate's SubjectPublicKeyInfo, so a genuine
  attestation borrowed from another card launders nothing; presented
  certificates are chain material, never anchors. **BREAKING for
  configuration**: with no anchor the exchange refuses every login, and a
  config with `piv_login.enabled` and neither `attestation_roots` nor
  `allow_unattested: true` no longer validates. The minted token records
  `attest_level` (`hardware` or `unattested`, carried through refresh) and the
  audit event for `auth.login.piv` carries the operator-facing reason for a
  refusal. A bundle that does not load fails the daemon at composition.
- **BREAKING (Go SDK): Refresh-token rotation is now an atomic compare-and-swap with family revocation tombstones; session claiming is atomic.** The pkg/auth/token package implements token rotation through compare-and-swap (CompareAndSwap on the underlying KV store), so a stolen-then-replayed refresh token that races the legitimate refresh request cannot succeed: the race is arbitrated by the store, and the loser reads the marked-rotated state that revokes the entire family lineage. Family revocation is written with PutIfAbsent so the first revoker's tombstone stands and two concurrent revokes cannot write divergent expiries. The WebAuthn session-claiming interface changes (pkg/webauthn) to claim the session before validation. SessionStore.Take is now an atomic get-and-delete operation: two concurrent finish requests for one ceremony cannot both proceed — the loser has nothing to validate against. This surfaces through the web transport and REST/gRPC API; the SDK's token types (Token, TokenPair) and refresh interfaces remain stable. Downstream integrations that work at the SessionStore layer must implement atomic Take.
- **A TCG-CSR-IDEVID whose keys are not TCG Template H-0 keys under the
  §7.3.6.6 IDevID/IAK Key Policy is refused.** The stateless verifier checked
  Restricted, fixedTPM, fixedParent and Sign. It now applies the whole rule the
  provisioning path applies before `TPM2_CreatePrimary`: decrypt CLEAR (§4.1,
  §4.2 "Not-decrypting"), `adminWithPolicy` SET (§7.2.4), and `authPolicy`
  equal to `DevIDKeyPolicyDigest(kind, nameAlg)`. §4 obliges the CA to verify
  "key Attributes and Policies"; a key administered by a policy the
  specification did not write is refused with
  `ErrDevIDTemplateNonConformant`.

  **Upgrade note:** this is the CA half of the re-key the IDevID/IAK key policy
  change already requires. A device provisioned before that change presents a
  public area with no `authPolicy` and is refused at enrollment; it must be
  re-provisioned. There is no separate migration.


  The CA checks the object attributes and the policy, and deliberately not the
  creation-only rules the provisioning path also applies — the §7.3.1 unique
  string and the H-1 through H-4 scheme, symmetric, exponent and kdf. §7.3.1
  fixes the unique field "at the time of key creation"; `TPM2_CreatePrimary`
  consumes it as derivation input and returns an `outPublic` whose unique field
  holds the generated public key, and `outPublic` is what a TCG-CSR-IDEVID
  carries. Demanding the string of a received public area would refuse every
  genuine device. `assertDevIDAttributesConformant` is the shared half, so the
  attribute and policy rules still have one definition.
- **IDevID and IAK certificates now carry the subjectAltName TCG "TPM 2.0 Keys
  for Device Identity and Attestation" v1.00 r12 §8.1 makes a SHALL.** The
  extension holds two otherNames: an RFC 4108 `hardwareModuleName` with the TPM
  2.0 hwType 2.23.133.1.2 and an hwSerialNum of `<TCG TPM manufacturer
  code>:<EK authority key identifier>:<EK certificate serial number>`, and an
  RFC 4043 `permanentIdentifier` whose assigner is `tcg-on-ekPermIdSha256`
  (2.23.133.12.1) and whose identifierValue is `hex(SHA-256(EK certificate
  DER))`. Neither reached a certificate before: the hardware module name
  builder was never called and emitted a standalone extension under the
  otherName's own OID rather than inside subjectAltName, and the permanent
  identifier carried the product model and serial with no assigner. Both are
  now derived from the endorsement key certificate the TCG-CSR-IDEVID carries;
  a request without one, or whose TPM manufacturer code cannot be determined
  from that certificate or from the new `CertificateRequest.TPMManufacturer`,
  is refused rather than certified with a name that identifies the wrong TPM.

- **The §8.2 TCG assertions are issued as certificate policies only, and the
  fixed and restricted assertions are no longer combined.** §8.2 defines
  `tcg-cap-verifiedTPMResidency`, `-Fixed` and `-Restricted` as policy
  identifiers carrying "No data"; the boolean-valued standalone extensions that
  also claimed them are removed. §8.2 further makes each of the fixed and
  restricted assertions a MUST NOT beside the other: an IAK certificate now
  carries residency and restricted, an IDevID residency and fixed. The extended
  key usage gains "the one TCG OID most appropriate for the type of key used"
  per §8.1 — the restricted OID on an attestation key, the fixed OID on an
  identity key — beside the TLS usages.

- **`ErrTCGMandatoryExtension` refuses issuance when an extension TCG DevID
  §8.1 requires cannot be built.** Extension construction discarded its errors
  (`if ext, err := ...; err == nil`), so a certificate could be issued
  asserting less than the CA had verified with nothing reporting why.

- **An IDevID's key usage is `digitalSignature` alone.** §8.1 Table 22 reserves
  the encryption usages for a Combined key, which the TCG-CSR verifier refuses
  to accept. The device model
  moves from `tcg-at-tpmModel` to `tcg-at-platformModel` and the device serial
  number out of `tcg-at-tpmVersion` into the subject's `serialNumber`
  attribute, where §8.1 asks for it; the two TPM OIDs name the TPM's own model
  and firmware version, not the platform's.
- **IDevID and IAK delegation through the TCG Policy NV Index, and
  `platform-policy` on an identity key now means what the specification says
  it means.** TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12
  §7.3 delegates use of a recoverable IDevID/IAK through a reserved NV index
  (§7.3.2: `0x01C90010`/`0x01C90018` for SHA256) whose Name is the fourth
  branch of the key policy. `DefineDevIDPolicyNV` defines that index to NV
  Policy Template I-0/I-1..I-3 under Owner authorization (§7.3.5),
  idempotently, and refuses with `ErrDevIDPolicyNVIndex` any index whose Name
  is not the specification's Table 18 — one attribute bit off can never
  delegate the key. `WriteDevIDDelegationPolicy` writes a Delegation Policy as
  a `TPMT_HA` (hash ID, then digest; §7.3.5 NOTE) under a
  `PolicySecret(TPM_RH_ENDORSEMENT)` session, so only the Privacy
  Administrator chooses it (§7.2.4). `DevIDDelegatedSession` satisfies a
  `DevIDDelegation`, executes `TPM2_PolicyAuthorizeNV` and completes the key
  policy's `PolicyOR`; the TPM refuses it whenever the index holds a different
  policy, and the TPM's response code stays in the error chain. The
  specification's example Delegation Policies (`DevIDSigningDelegation`,
  `DevIDAttestationDelegation`) are pinned to Table 20 in
  `devid_policy_test.go`; the simulator suite defines, writes, signs through
  the delegation, and proves a foreign index, a wrong authorization, a replaced
  policy and a moved platform are each refused.

  Previously `platform-policy: true` on an IDevID or IAK was ignored for the
  key's USER role (the key's policy is fixed by Template H-0, so a
  platform-policy session could never satisfy it). Now `CreateIDevID` and
  `CreateIAK` provision the key's Policy NV Index with
  `DevIDPlatformDelegation` — `TPM2_PolicyPCR` over the platform PCR in the
  key's nameAlg — and, for a key with no authValue, `CreateKeySession` hands
  out the delegated session, so signing stops when the platform state moves and
  resumes once the Privacy Administrator rewrites the delegation for the new
  state. The key and its certificates never change. A configured authValue is
  still used in preference (§7.2.4 keeps it as a USER path on Template H-0):
  making platform state the only path means an authValue nobody knows, which
  is the Owner's decision, not this library's. The IDevID signing path in
  `Sign` now takes its authorization from `CreateKeySession` like every other
  key instead of presenting the password directly.

  **Upgrade note:** no re-key. The default configuration sets
  `idevid.platform-policy`, so a device provisioned with it now defines and
  writes NV index `0x01C90010` (34 bytes) during provisioning; provisioning
  fails closed if the Owner or Endorsement authorization is refused. A device
  provisioned before this change is not touched: its IDevID keeps signing with
  its (empty) authValue exactly as before, and the index is defined and
  written only by re-provisioning or by the Owner calling
  `DefineDevIDPolicyNV` / `WriteDevIDDelegationPolicy` through the SDK.
- **IDevID and IAK keys are created to TCG "TPM 2.0 Keys for Device Identity
  and Attestation" v1.00 r12, Template H-0, with the specification's
  IDevID/IAK Key Policy as their `authPolicy`.** Previously `adminWithPolicy`
  was CLEAR and no policy was attached, so the key's authValue — empty on the
  default configuration — authorized *administration* of the device identity
  as well as use of it. Now `userWithAuth` and `adminWithPolicy` are both SET
  (§7.2.4): the authValue can sign, and only the Privacy Administrator, holding
  `endorsementAuth`, can certify the key or release a credential against it,
  through the §7.3.6.6 `PolicyOR` of PolicyUser, PolicyCertify,
  PolicyActivateCredential and PolicyDelegationNV. `TPM2_Certify` and
  `TPM2_ActivateCredential` on these keys now run under `DevIDAdminSession`,
  which authorizes exactly one command; the authValue is refused for them
  with `TPM_RC_AUTH_TYPE`. Every policy digest is computed through go-tpm's
  trial-policy calculator and pinned to the digests TCG publishes in
  Tables 14–19 (`devid_policy_test.go`). The specification is checked in
  under `docs/references/`.

  **This re-keys every IDevID and IAK.** `adminWithPolicy` and `authPolicy`
  are inputs to a primary key's derivation, so a device provisioned before
  this change holds identity keys that `CreateIDevID`/`CreateIAK` can no
  longer derive. The key-template change in this same release moves further
  derivation inputs, so the two share **one** upgrade note: see *Upgrade
  note* under "IDevID and IAK key creation templates now match TCG …" in
  `changed-tcg-devid-key-templates-1.md`. Re-provision once, for both.
  `ErrDevIDTemplateNonConformant` refuses, before `TPM2_CreatePrimary`, any
  template whose attributes or policy depart from Template H-0.

- **One naming rule for both device identity keys.** `DevIDCommonName`
  resolves an IDevID or IAK Common Name as: explicit `cn`, else the device's
  configured model and serial number as `model-serial` (the Platform Identity
  Information the TCG-CSR-IDEVID carries, §7.2.3 step 4a), else
  `ErrDevIDCNUnresolved`. The IAK previously took `iak.cn` verbatim and was
  left empty when unset, while the IDevID already derived `model-serial`;
  the two keys of one device could therefore be named by different logic.
  **Upgrade note:** an IAK provisioned with no `iak.cn` was stored under an
  empty name and is now named `<model>-<serial>`; artifacts written under the
  empty name are not found by the new name and must be re-imported or the
  device re-provisioned. A configured `iak.cn` is unaffected.

- **`store.FileBackend` refuses an empty Common Name (`ErrEmptyKeyCN`).**
  The storage key is the CN plus an extension, so an empty CN degenerated to
  the bare extension — `.key`, `.crt` — one slot shared by every nameless key
  in the backend, last writer wins. `Get`, `Save` and `Delete` now refuse
  rather than compose that key (#440).
- **BREAKING: Tenant-bound certificate issuance fails closed; no fallback to global CA.** When an ACME order is bound to a tenant, the finalize handler must resolve that tenant's signing CA. Previously, resolution failures silently fell back to the global CA, which is a safety violation: a tenant whose CA is misconfigured should not issue certificates using the system CA. Tenant-bound orders now fail outright with a typed error (one of ErrTenantStorageUnsupported, ErrTenantDAOUnavailable, ErrTenantSignerUnavailable, ErrTenantCATypeUnsupported, ErrTenantIssuerCertUnavailable, or ErrTenantSignerIssuerMismatch) rather than falling back. The only legitimate way to sign a tenant-bound order with the global CA is explicit SigningCAInfo.UseGlobalDefault from GetSigningCA, which reflects the tenant's own configuration rather than a resolution failure. ErrTenantSignerIssuerMismatch is new: it is returned when the CA signer's public key does not match the issuer certificate it would be paired with, which would produce a certificate chain that never verifies.
- **Vault Transit symmetric keys are no longer created exportable by default.** When GenerateSymmetricKey or ImportKey creates a key in Vault Transit, the backend now respects attrs.Exportable instead of hardcoding exportable=true for every symmetric key. The default stays secure: an attrs.Exportable left unset creates a non-exportable key. Only keys explicitly marked Exportable=true can expose their raw material through ExportKeyMaterial; all other operations (SymmetricEncrypter, etc.) work with non-exportable keys exactly as before. This brings Vault in line with the convention every other backend observes (CKA_EXTRACTABLE-equivalent).
- **Enterprise policy is consumed only once it verifies (#118).** `config`
  had the integrity machinery — `VerifyPolicyHMAC` over
  `PolicyCanonicalJSON`, keyed from the SO PIN — but no CLI path called it,
  so every policy field the CLI read was, in security terms, a value from a
  file any local user could edit. `xkey device pair` had been mitigated in
  #110 by consuming the section monotonically (it could refuse, never
  permit), which closed the fail-open Codex found but could not honour a
  deployment that legitimately locks pairing of unattestable devices open.
  New: `config.LoadVerifiedPolicy(cfg, configDir, soPIN)` returns the policy
  with its state — `PolicyUnsealed` (no HMAC file, the section is the user's
  own) or `PolicySealedVerified` — and fails closed with the typed
  `ErrPolicyUnverifiable`, joined with the cause, whenever the directory is
  sealed and the section cannot be authenticated: no SO PIN, an unreadable
  HMAC file, or a mismatch. No policy is returned with the error, so an
  unverified sealed section cannot be consumed by accident. `xkey device
  pair` now takes the SO PIN through the same three sources as the user PIN
  (`--so-pin-stdin`, `XKEY_SO_PIN`, `--so-pin`) and honours a verified
  policy in both directions; without an SO PIN a sealed policy is not
  consulted and an unattestable device is refused whatever `devices.yaml`
  says; a sealed policy that does not verify refuses the pairing outright
  (`ErrPairingPolicyRefused`). `xkey extension serve` accepts the same
  sources: verified, the policy is honoured; unverifiable with an SO PIN
  supplied, the server does not start (`ErrServePolicyRefused`); with no SO
  PIN it applies `DefaultPolicy()` for the extension gates instead of the
  file, and says so. A log-only read of the unverified section at PIN
  service start-up is gone. The shared pairing decision,
  `attestation.AllowUnattestablePairing`, now takes the `VerifiedPolicy`
  rather than a raw section, so the desktop GUI's `PhoneService.Pair`
  resolves the enterprise plane exactly as the CLI does: honoured in both
  directions in personal mode, and not consulted -- refuse -- in a sealed
  deployment, since a GUI pairing has no SO PIN to verify it with. The GUI's start-up readers of the FIDO2 and
  extension fields are not yet converted and remain tracked under #118.

### Added

- **CTAP 2.1 authenticatorLargeBlobs in the xkey authenticator.** The xkey (pkg/xkey) CTAP2 authenticator now supports the authenticatorLargeBlobs extension (RFC 8959, Section 2.2.3 / CTAP 2.1 Section 11.4.8.2) for storing and retrieving opaque large objects (up to 2^32 - 1 bytes) on the authenticator. The extension is integrated into registration and assertion ceremonies; clients can write and read credentials' associated blobs atomically as part of the ceremony.
- **Key import can now say whether the key may leave again (#160).**
  Every import path hardcoded `Exportable=true` for symmetric material, so
  no transport could import a non-extractable secret key, and the plaintext
  stayed recoverable through `export-material`; REST set nothing at all, so
  a symmetric key imported over REST was stored non-exportable while the
  same import over gRPC or MCP was exportable. `ImportKeyRequest` gains
  `exportable` (optional; absent keeps the write-once default, symmetric
  exportable and asymmetric not) and `sensitive`, on the transport type,
  the gRPC proto (new fields 12 and 13), the MCP params, the REST body and
  `xkmsctl key import --exportable/--sensitive`. The three attribute
  builders apply the choice through one helper, `xkms.ApplyImportExportability`.
- **Key escrow: a complete KMIP agent plus factory, daemon configuration, service layer and embedded transport wiring.** The pkg/escrow/kmip package now exports a production KMIP 2.0 client agent (kmip.NewAgent), coupled with factory and configuration (pkg/escrow with Config, Factory, Registry), service-layer plumbing (pkg/xkms servicer_escrow.go), and transport integration (pkg/api/transport types_escrow.go and each transport's escrow endpoints). Daemon configuration accepts escrow backends (e.g., KMIP=true in the config or DaemonEscrowConfig). Network transports (TCP, TLS, client authentication certificates) are not yet exposed to callers — KMIP agent operations run embedded-only or over internal channels for now.
- **PKCS#11 gained CBC, CBC-pad and ECB symmetric modes, matching the software backend.** The pkg/backend/pkcs11 symmetric provider now supports CBC, CBC-PKCS7-pad and ECB mode envelopes in addition to the GCM and KWP modes it already offered. All three modes are available on all PKCS#11 tokens that expose the corresponding mechanisms (CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_ECB).
- **The PKCS#11 remote state plane gains a guarded delete (#142).**
  `PKCS11StateCAD` removes a token-state record only if it still holds the
  value the caller observed, with the guard evaluated by xkmsd on its own
  store, where the writes of every host sharing one server-side token
  serialise. It is the release half of `PKCS11StatePutIfAbsent`'s guarded
  create. Wired end to end: transport DTOs `PKCS11StateCADRequest` /
  `PKCS11StateCADResponse`, the gRPC RPC (`keys:write`), the REST and QUIC
  route `POST /api/v1/pkcs11state/compare-and-delete` (keys resource,
  `delete` action), the gRPC, Unix, REST and QUIC client transports,
  `XKMSService.PKCS11StateCAD`, and `pkcs11state.Store.CompareAndDelete`,
  which refuses with `ErrCompareAndDeleteUnsupported` rather than emulating
  the guard on a backend that lacks it. The module's remote storage backend
  now implements `storage.CompareAndDeleter` over the RPC and is held to the
  shared conformance suite; its `PKCS11StateClient` contract gains the method,
  so a transport that does not carry it fails the build. An absent key or a
  different value answers `deleted=false` without an error; a nil `expected`
  is never a wildcard, matching a stored empty value only.
- **`tofu` verifies an endpoint on the TLS path (#139).** The strategy was
  implemented purely as a CA-bundle fetch, so it could not verify the one
  thing it is most natural for: first contact with a device that presents a
  self-signed certificate and serves no bundle, such as a BMC.
  `bootstrap.NewTOFUTLSConfig(ctx, pinStore, "host:port", confirm)` is the
  endpoint verifier, mirroring `NewSPKIPinTLSConfig` and `NewDANETLSConfig`:
  the first connection captures the leaf's SPKI pin, offers it to the
  confirm hook, and persists it; every later connection must present it,
  session tickets are disabled so resumption cannot bypass the check, and a
  pin store that fails for any reason other than "no pin" is an error, never
  a fresh capture. The pin record is the one truststrap's bundle-fetching
  TOFU bootstrapper writes, so both paths share a store. The resolver's TLS
  dispatch for `tofu` now uses it, with the endpoint (or the scope's
  server-url) as the key, while the PEM path keeps fetching a bundle: the
  same split `dane` and `spki` already have. Re-exported through
  `sdk/go/bootstrap` with typed errors `TOFUEndpointError`,
  `TOFUPinStoreError`, `TOFUPinMismatchError` and `ErrTOFUPinStoreRequired`.

### Changed

- **transport: `BeginAuthenticationRequest.Username` and `FinishAuthenticationRequest.Username` are now `Email` (#518).**
  Both carried the canonical email login key under a name that said
  otherwise, the same defect the registration request had. The Go fields,
  the gRPC/Unix proto fields (numbers unchanged, binary-compatible) and the
  REST/QUIC JSON keys are now `email`. For one release the JSON decoders
  still accept the legacy `username` key and the Go client sends both keys
  with the same value; a body carrying both keys with different values is
  refused with `transport.ErrAuthenticationLoginKeyConflict`. The three
  ceremony requests resolve their login key through one shared decoder
  path. The legacy key is removed in the following release.
- **No host literal in the build system.** The in-house Gitea server was
  written into the Makefile, the devcontainer and every integration compose
  file, so a server move broke all of them at once. `scripts/gitea-host.sh`
  now derives `GITEA_HOST` from the environment, from `.devcontainer/.env`,
  or from the checkout's own origin remote (an SSH origin maps its port to
  the HTTP port), the Makefile exports it so every compose file interpolates
  `${GITEA_HOST}` (failing with the variable's name when it is unset), and a
  GitHub origin with no override takes the public resolution path with no
  `insteadOf` rewrite at all. `make gitea-host` prints the resolved value.
  The review workflow's model endpoint is likewise a knob (the `OLLAMA_URL`
  Actions variable or a runner-injected value) that fails naming itself
  when neither is configured.
- **CI: gosec findings are printed to the job log.** The Security Scan wrote
  its findings only to a SARIF file that is uploaded on GitHub and skipped
  on Gitea, so a failing scan ended with exit code 1 and nothing in the log
  naming the finding (#334). gosec now also writes the
  findings to standard output.
- **CI runs the whole `sdk/go` test suite (#333).** The nested-module job
  ran three package trees of the public SDK module, 130 of its ~1,000 test
  functions, leaving 23 test directories, including the whole
  `acme/client` family, the module root and `errors`, outside the gate. It
  now runs `go test -race -v ./...` from `sdk/go`. Measured before widening:
  26 packages, all green with no build tags, about one minute of wall time
  under the race detector on a development host, so the addition is
  cheaper than the xkey steps in the same job. A deliberately failing test
  in a formerly dark package turns the step red.
- **CI runs `cmd/xkey/cmd` and `pkg/gui/services` whole.** The two packages
  held 8,282 test functions, and the named-selector steps ran 27 of them: a
  renamed test was a red job, but a test added to either package arrived
  dark and stayed dark. Both now run as whole packages in the unprivileged
  xkey unit step, under `-tags ble` so the CLI's fail-closed fingerprint
  tests and the logins harness guard are included. The "pre-existing
  failures" that justified naming were CI running as root; as an
  unprivileged user both packages are green (1,761 and 6,521 tests). The
  one stale test found on the way, which pinned the pre-xhome behaviour of
  refusing a missing `~/.xkey`, now asserts the current contract: the home
  is created 0700 on first use, and an unwritable one fails with
  `ErrSharePolicySetFailed` carrying the permission error. `require-tests.sh`
  has no remaining caller and is removed (#332, #111).
- **CI runs every xkey unit package.** The Nested Module Tests job ran 6 of
  the xkey module's package trees and compiled the rest, so 2,987 test
  functions in 41 packages -- truststore, tokenstore, luks, ca,
  secretservice, nssdb, pivcert, pkcs11mgr, sshstore, sshlocal, config,
  audit among them -- could not fail. The job's stated reason, that ten
  packages failed identically on main, was a missing `codec_json` build tag:
  with it, all 41 pass under `-race`. Forty of them now run on every PR in
  one step that also records each deliberate exclusion with its reason;
  `xkey/pkg/pkcs11`, 37% of the set's cost for 34 tests, runs nightly
  instead. Whole-package runs for `cmd/xkey/cmd` and `pkg/gui/services` are
  #332 and `sdk/go` is #333 (#147).
- **The desktop apps serve their REST API in-process and open no listener.**
  Both Wails applications bound a TCP listener on `127.0.0.1:0` and served
  their API from it: the ACME client's 18 routes and — with no guard at all —
  the admin app's 37, including tenant, user, role and CA creation. A loopback
  port is reachable by every local process and, through the user's browser, by
  every page the user visits, so the only consumer of that port was the app's
  own webview while the audience was the whole machine. Wails' `AssetServer`
  takes an `http.Handler` alongside `Assets`, so the existing router is now
  mounted there: a GET is served from the frontend bundle first and falls back
  to the router, every non-GET goes straight to it, and the webview reaches
  `/api/v1/...` same-origin. The listener, the per-launch bearer token minted
  for it, the `Host` allow list that defended it against DNS rebinding and the
  token plumbing through `GetApiBaseUrl` and the frontend transport are all
  gone; `GetApiBaseUrl` now returns an empty, same-origin base. The router
  stays transport-agnostic and `trusted-acme-client serve` keeps serving it
  over TCP, where the same-origin check still applies.
- **`xkey device pair` is testable end to end without a phone (#120).**
  `runDevicePair` opens its transport, reads and writes the devices file and
  loads its attestation trust through `pairingSeams`, wired to the BLE
  transport, `devices.yaml` and the trust store in production and replaced
  in tests. Three command-flow tests drive the whole command against a
  simulated phone: a failed attestation under the default policy returns
  before anything is saved, an opted-in policy saves a record with no
  attestation claim, and a verified attestation is recorded. No pairing
  behaviour changes.
- **DNS-01 challenges now drive the configured provider (Route53, Cloudflare, Azure, Cloud DNS) instead of logging manual setup required.** The pkg/acme/server challenge solver for dns-01 now dispatches to the configured DNS provider backend instead of logging that manual setup is required and returning a no-op response. Route53, Cloudflare, Azure DNS, and Cloud DNS backends now all drive DNS record creation and cleanup atomically as the certification flow runs. For ACME clients where dns-01 is the only feasible authorization method, this eliminates the separate manual publishing step.
- **BREAKING (implementors): Import/export capabilities are now separate interfaces.** The pkg/backend package splits the key ceremony into ImportBackend (GetImportParameters, WrapKey, ImportKey) and ExportBackend (ExportKey, ExportKeyMaterial), replacing the monolithic ImportExportBackend interface. ImportExportBackend now embeds both halves and is stable for callers, but a backend missing one half (AWS KMS, which does not support export) can now implement only ImportBackend without stubbing or sentinel errors. A backend that is import-only or export-only for hardware reasons does not block the half it does support. Callers that only need one half should assert ImportBackend or ExportBackend instead, so a backend missing the other half does not break the half it provides.
- **BREAKING (Go SDK): types.NewPassword and TPM2 store equivalent now return an error instead of silent fallback.** NewPassword and NewPasswordFromString now return ErrEnclaveUnavailable if enclave allocation fails (previously they would silently substitute an empty password), because silently downgrading a caller-supplied non-empty UserAuth into passwordless TPM authentication is a security violation. A non-empty input that fails to allocate returns an error, making the failure explicit rather than latent. Empty or nil input still returns a ClearPassword with no enclave backing and nil error (intentional "no authentication" case). The TPM2 GeneratePassword store equivalent now returns the same error instead of falling back.
- **PKCS#11 sessions whose authentication state cannot be restored are discarded rather than returned to the pool.** The pkg/backend/pkcs11 session manager no longer caches sessions that lose their login state when a concurrent thread logs out from the same token. A session returned to the pool must have the same authentication state as when it was checked out; if restoration fails, the session is closed and a fresh one is checked out on the next use. This prevents subtle bugs where later callers inherit unexpected authentication context from a borrowed session.
- **transport: `BeginRegistrationRequest.Username` is now `Email` (#192).**
  The field carried the canonical email login key under a name that said
  otherwise, and a caller that read the name literally enrolled a credential
  against the wrong account. The Go field, the gRPC/Unix proto field
  (field 1, binary-compatible) and the REST/QUIC JSON key are now `email`.
  For one release the JSON decoder still accepts the legacy `username` key
  and the Go client sends both keys with the same value, so old clients
  and old servers both keep working across a rolling upgrade; a body
  carrying both keys with different values is refused with
  `transport.ErrRegistrationLoginKeyConflict` instead of a silently chosen
  value. The Go SDK re-export follows the rename; the TypeScript SDK never
  exposed this request. The legacy key is removed in the following release.
- **The Shamir ceremony test fixture keeps shares in protected memory.** The
  four copies of `testCaptureDistributor` in the xkms service, MCP, gRPC and
  REST barrier tests split the barrier secret with quicraft's deprecated
  string-share `Split` and retained every share as a Go string, which cannot
  be wiped, until the test process exited. They are replaced by the one
  `internal/shamirtest.CaptureDistributor`, built on `SplitProtected`: shares
  live as `ProtectedShare` in mlock'd guard-paged memory, a rekey destroys the
  previous round instead of dropping it, and the test's cleanup destroys the
  last one. The base64 text a request carries is materialised only where the
  request is built and is not retained. The eight `//nolint:staticcheck`
  directives that #45 added against the deprecated API are gone (#46).
- **IDevID and IAK key creation templates now match TCG "TPM 2.0 Keys for
  Device Identity and Attestation" v1.00 r12 field for field**, §7.3.4
  Templates H-0 through H-4, built in one place (`DevIDTemplateSpec`,
  `pkg/tpm2/devid_template.go`) that both `CreateIDevID` and `CreateIAK`
  derive from. `CreateIAK` previously built its own inline copies of the
  templates the package exports, so the two could — and did — disagree.

  - **`unique` carries the required string of §7.3.1 Table 2** — `'IDEVID'`
    (49 44 45 56 49 44) or `'IAK'` (49 41 4B), unpadded and not NUL
    terminated — where both keys previously zero-filled it. The MUST exists
    so that a device's identity keys are reproducible by anyone following the
    specification; a zero-filled `unique` produced keys nothing else could
    recreate. The optional per-device string is the new `tpm.device-string`
    configuration key: printable ASCII, appended to the required string, the
    same value for both keys because §7.3.1 describes a property of the
    device. Where it is stored is the OEM's choice (§7.3.3 reserves NV Index
    0x01C90020 for it); this library reads it from configuration.
  - **An RSA IDevID names no signature scheme** (`TPM_ALG_NULL`), as H-1
    requires of a signing DevID, instead of pinning RSASSA or RSAPSS with
    SHA-256. The padding and digest are chosen per `TPM2_Sign` command, so one
    device identity key can now produce both the PKCS#1 v1.5 signature a
    certificate is signed with and the RSA-PSS a TLS 1.3 handshake requires.
    An IAK keeps RSASSA or RSAPSS with a hash: a Restricted signing key may
    not name `TPM_ALG_NULL` (TPM 2.0 Library Part 1, §25.2.3).
  - **`symmetric->algorithm`, `exponent` and `kdf->scheme` are stated
    explicitly** on every DevID template rather than left to Go's zero value.
  - **P-384 and P-521 suites** (Templates H-3 and H-4, with nameAlg SHA-384
    and SHA-512) are added and reachable from an `idevid.ecc.curve` /
    `iak.ecc.curve` configuration: `ECCIDevIDP384Template`,
    `ECCIDevIDP521Template`, `ECCAKP384Template`, `ECCAKP521Template`,
    re-exported through `sdk/go`. Template H-5 (SM2 P-256) is **not**
    implemented: it requires nameAlg `TPM_ALG_SM3_256`, which the TPMs this
    library is tested against do not implement (the reference simulator
    refuses such a template with `TPM_RC_HASH`), and `crypto/elliptic` has no
    SM2 curve. A configuration naming it is refused rather than substituted —
    `types.ErrUnknownCurve` from `types.ParseCurve`, and
    `ErrDevIDTemplateSuiteUnsupported` for any curve that reaches the template
    builder without one.
  - **`assertDevIDTemplateConformant` now covers `unique`, scheme, symmetric,
    exponent, KDF and curve** in addition to the H-0 attributes and the key
    policy, so any departure is refused with
    `ErrDevIDTemplateNonConformant` before `TPM2_CreatePrimary` rather than
    baked into a key that cannot be repaired. New errors:
    `ErrDevIDUniqueString`, `ErrDevIDUniqueStringTooLong`,
    `ErrDevIDTemplateSuiteUnsupported`.

  **Known departure from Table 5, deliberate, and the specification's own
  resolution.** Templates H-2, H-3 and H-4 state both `scheme->scheme =
  TPM_ALG_ECDSA` and `scheme->details = NULL`. No TPM can carry that pair: the
  details of an ECDSA `TPMT_ECC_SCHEME` are a `TPMS_SIG_SCHEME_ECDSA`, whose
  `hashAlg` is a `TPMI_ALG_HASH` with no `+` decoration, so `TPM_ALG_NULL` is
  not admissible there, and `TPM2_CreatePrimary` answers `TPM_RC_HASH` for
  P-256, P-384 and P-521 alike (measured; `devid_template_simulator_test.go`
  pins the refusal). The scheme stays `TPM_ALG_ECDSA` — the constraint Table 5
  actually states — and the details name the template's own nameAlg, which is
  the pairing §14 (Annex B, Table 24) uses when it names the conformance
  suites: "the ECDSA P-256/SHA-256 signature suite" and "the ECDSA
  P-384/SHA-384 signature suite". Dropping to a `TPM_ALG_NULL` scheme would
  create, but would discard the stated constraint and widen the key's grant.

- **`SignValidate` resolves an RSA signature scheme instead of copying the
  key's.** It sent the key's own scheme field as `inScheme`, which is a
  `TPM_ALG_NULL` for a Template H-1 IDevID, and `TPM2_Sign` refuses a
  `TPM_ALG_NULL` `inScheme` on a key that names no scheme with
  `TPM_RC_SCHEME` — for a key that constrains nothing, the command must say
  what to sign with. It now uses the same `rsaSignScheme` resolution the
  `crypto.Signer` path uses, and unpacks the response as the shape it asked
  for rather than deciding that separately.

- **Upgrade note — this re-keys every IDevID and IAK, and supersedes the
  upgrade note of the Template H-0 / key policy change in this same
  release.** Both changes move inputs to a primary key's derivation:
  `adminWithPolicy` and `authPolicy` from that change, and `unique` and the
  RSA scheme from this one. A device provisioned before this release holds
  identity keys that `CreateIDevID` / `CreateIAK` can no longer derive.
  There is no in-place migration — that is what a primary key is. Those
  devices must be re-provisioned and their IDevID/IAK certificates re-issued;
  the existing certificates remain valid for the old keys, which the new code
  cannot reproduce. Setting `tpm.device-string` later re-keys again, for the
  same reason, so choose it before provisioning a fleet. Do this once, for
  both changes, rather than twice.
- **BREAKING (Go SDK): `IAKAttributesFromConfig`, `IDevIDAttributesFromConfig` and `LDevIDAttributesFromConfig` no longer take a policy digest (#398).**
  The `*tpm2.TPM2BDigest` parameter only ever fed an EK template nothing
  read, and since the dead assignment went it was blank-named and documented
  as retained for signature stability. It is gone from the three builders in
  `pkg/tpm2` and therefore from their `sdk/go` re-exports; platform policy
  is still conveyed by the `PlatformPolicy` field and applied by
  `CreateIAK`/`CreateIDevID`, which compute the digest themselves. The two
  in-repo callers no longer compute a digest they did not use. Consumers
  that pass a digest (go-trusted-platform) drop the argument when they adopt
  the release that carries this.
- **BREAKING: Vault ciphertext now preserves the full versioned envelope; key names use injective escape.** The Vault backend's import/export cycle now preserves Vault Transit's internal versioned envelope in the ciphertext format instead of only the raw ciphertext blob, so the wrapped material returned by ExportKey can be passed back to ImportKey against any backend in the usual cross-system format. Key names are escaped using an injective scheme (e.g., slashes → hyphens, colons → underscores) so illegal characters in a key's CN do not corrupt the Vault Transit key name nor collide with other keys. Any existing Vault-stored ciphertext from an earlier release will not decrypt with this release: the format changed at the wire level. Any imported Vault KMS keys whose CNs contained special characters will need renaming to use the new escape scheme.
- **xkey: go-luks2 v0.1.10 with a kernel-keyring preflight before any LUKS2 volume is created or unlocked (#188).**
  A container that blocks the `add_key`, `keyctl` and `request_key`
  syscalls used to fail
  only when dm-crypt refused the volume key, after the image file or the
  device had already been partitioned and formatted. `luks.EnsureKeyringAvailable`
  now probes the keyring before each of them and refuses with the typed
  `luks.KeyringError` (`errors.Is(err, luks.ErrKeyringUnavailable)`, the
  go-luks2 cause reachable) before `luks2 seal`, `luks2 unseal`, `luks2 migrate` and `usb
  create` touch anything, so a refusal leaves no file, no partition table,
  no half-provisioned device and no renamed source container. The probe runs before every
  operation and is never cached, so a key quota exhausted between two
  operations of a long-lived process is caught before anything is touched,
  and fixing the profile and retrying works.

### Removed

- **An unused persistent ACME nonce store is gone.** The pkg/acme/common nonce_store.go held an in-memory nonce store that was never wired into production and carried a check-then-delete race where a validly-used nonce could be double-spent in certain race windows. The ACME server's actual nonce management is in pkg/acme/server and uses the configured KV store; nonce_store.go had no callers. The dead code and its tests are removed.
### Removed

- The `pkg/acme/server/ratelimit` package. It was a second `TenantRateLimiter` beside the one in `pkg/acme/server` that the ACME server actually wires, and nothing in the tree imported it. (#538)
- **The uncalled backend factory is gone (#173).**
  `pkg/server/backend_factory.go`'s `Initialize`, its `BackendConfig` /
  `BackendFactoryConfig` types, `createBackend` and the seven
  `backend_factory_<backend>.go` constructors (with their `_stub.go`
  siblings) had no production caller: the live path is `server.go`'s
  `initializeBackends` calling `initXBackend` in `backend_<backend>.go`.
  The dead factory modelled backends with operator-supplied names and a
  randomized default that the live server never had, and three readers
  reasoned from it to wrong conclusions in one review. Its tests go with
  it; the two live storage helpers it housed, `createStorage` and
  `createStorageAt`, move to `storage_factory.go`, and the docs now point
  at the real construction path.
### Removed

- **The in-repo PR review automation is gone; review orchestration lives in
  go-quicbaas.** `.github/workflows/opencode-review.yml`,
  `claude-review.yml` and `automerge.yml` are deleted — the label-driven
  reviewer routing (`agent:*` / `model:*` / `effort:*`), the verdict parsing
  and the Gitea auto-merge arming all went with them. Two implementations of
  the same control were conflicting; this repository now hosts none of it.

  `ci.yml`, `coverage.yml`, `docker-tests.yml`, `nightly.yml` and
  `release.yml` are unaffected — none referenced the review workflows except
  one comment, which is updated. `.github/scripts/apt-deps.sh` and
  `require-tool.sh` are CI dependency helpers, not review automation, and stay.

  The `agent:*`, `model:*`, `effort:*`, `code-review` and `review:*` labels are
  left in place: they are Gitea data rather than automation, and whatever
  drives reviews next may want the same vocabulary.
- **BREAKING: The SDK's qrdb database-plane re-exports are gone (about 253 identifiers).** The go-xkms SDK (sdk/go) formerly re-exported low-level qrdb storage internals from pkg/config, pkg/kv, pkg/dao, pkg/state, pkg/storage, pkg/watch, pkg/lease, pkg/index, pkg/timeseries, and pkg/mvcc. Downstream consumers that relied on these re-exports now import them directly from go-qrdb/sdk/go instead, which is the canonical source and the boundary xkms is converging toward. Callers using only the high-level xkms API surface (services, transports, authenticators) are unaffected.
- **The threshold key provider is gone.** The pkg/backend/threshold backend advertised non-exportable threshold keys but generated and reconstructed a whole private key in one process, which is a threat model violation. The layer that threshold issuance belongs to (if needed at all) is quicbaas, not xkms; xkms owns split-key mechanisms only when hardware enforces the split (TPM, HSM). The threshold backend, its tests, and its KMS service integration are removed.
- **The xkey YubiKey PKCS#11 provider is gone, superseded by the canonical backend.** The pkg/xkey/cli/pkcs11 directory contained a specialized YubiKey provider that was never wired into the xkey CLI or GUI. The canonical PKCS#11 backend (pkg/backend/pkcs11) already supports YubiKeys via the standard YKCS11 libary; this shadow implementation is removed to prevent divergence and confusion.

### Fixed

### Fixed

- `TestFileAuditLogger_ProcessEvents` waited a fixed fifty milliseconds for the background writer and failed on a loaded CI runner; it now synchronises on `Flush`, which returns only after the buffer is drained and the writer synced.
- **The ACME challenge listeners bind a configured host (#140, cluster 2).**
  The client's http-01 challenge server and the three enrollment listeners
  (enroll-01, endorse-01, device-attest-01) built their address as `":"+port`,
  so every one bound every interface whatever the operator configured.
  `acmeclient.EnrollmentConfig` gains `ListenHost`, and xkmsd passes its
  `server.host` through `clusterca.ACMEOptions.ChallengeHost`, so a joining
  node serves the enroll-01 exchange on the interface every other daemon
  listener binds. The standalone client gains `challenge.http01.host`
  (`ACME_CLIENT_CHALLENGE_HTTP01_HOST`; `challengeHost` on the GUI config
  API), joined with the port through `net.JoinHostPort`. `enroll01.Setup`
  takes a listen address (a bare port still means every interface). Empty
  remains the defaults-layer value everywhere: every interface.
- **`pkg/acme/client`'s tests no longer carry a path to Let's Encrypt
  production (#152).** `golang.org/x/crypto/acme` substitutes the Let's
  Encrypt directory for an empty `DirectoryURL`, so every test literal that
  omitted it was an outbound HTTPS call waiting for the validation ahead of
  it to regress; the ones that did reach the network failed on a ten-second
  TLS timeout instead of on the defect (CI run 7429), and one sibling test
  passed on that same timeout because its assertion could not tell the two
  apart. The remaining eleven literals point at a loopback port that refuses
  immediately, and a grep gate (`TestACMEClientLiteralsAreHermetic`) fails
  the suite on any `acme.Client` literal in the package's tests that omits
  `DirectoryURL`.
- **ACME orders are no longer stranded in processing when a CSR fails to parse or validate.** The finalize handler now validates the CSR (parsing and checking identity matching) before updating the order to processing status; a CSR parse error or identity mismatch returns a 400 error and leaves the order in ready state, where the client can resubmit with a corrected CSR. Previously a malformed CSR would place the order in processing state with no way to recover except manual intervention.
- **Advertised URLs are configuration, never a host glued to a bind address (#140, cluster 4).**
  `trusted-acme-client serve` built the API base URL it hands the browser as
  `scheme + "://localhost" + addr`, so the command's own `--addr 0.0.0.0:9443`
  example advertised `https://localhost0.0.0.0:9443/api/v1`; the standalone
  `TrustedCA` did the same for the ACME directory's external URL, served to
  every ACME client. The client gains `serve.api_base_url` (`--api-base-url`,
  `ACME_CLIENT_SERVE_API_BASE_URL`), advertised verbatim once it parses as an
  absolute http(s) URL not ending in `/api/v1`, which the UI appends itself;
  the Wails `GetApiBaseUrl` bindings return the origin for the same reason,
  and `pkg/webui` renders the value into the page as an escaped JavaScript
  string literal. With nothing configured both derive the URL through the new
  `acmeclient.AdvertisedURL`, which splits host and port: a wildcard bind
  advertises `localhost`, a named or literal bind advertises itself, and an
  address with no port is an `AdvertisedURLError`. `DefaultExternalURLPrefix`
  is gone with the gluing it existed for.
- **The ACME audit end-to-end tests no longer fail on a contended runner.**
  `awaitEvents` polled the audit trail under a five-second wall-clock
  budget; the trail's `Flush` is synchronous (it hands the drain to the
  writer goroutine, waits, and syncs the file) and every handler records its
  event before answering, so the loop could never turn a wrong answer into a
  right one — it only measured how long an fsync and a file scan take on a
  saturated host, and failed reporting a page it never read when the first
  evaluation outlived the budget. The helper is now one flush and one query
  with no budget to expire, proven green under a full-core load generator.
- **AWS KMS signers honour the hash and padding requested per call instead of a fixed algorithm chosen at construction.** The signer was storing only the hash algorithm chosen when the signer was created, then ignoring the hash and padding parameters passed to each Sign call. Now the signer respects the caller's choice on every invocation, so TLS and other protocols that expect PSS or PKCS#1v15 padding or a specific hash get the algorithm they requested rather than whatever was selected at startup.
- **`make build` no longer needs a Gitea token on a host with a warm module
  cache.** The builder container mounted the host module cache at
  `/root/go/pkg/mod`, but the golang base image keeps its cache at
  `/go/pkg/mod`, so the mount sat unused and every `xkmsd` and `xkey` build
  refetched the whole module graph from Gitea. A checkout without
  `.devcontainer/.env` then failed on the first private module (`go-codec
  v1.4.0: Failed to authenticate user`) even though the host had every module
  cached. The container's `GOMODCACHE` is now pinned to the mount path for the root
  builder containers (`build-server`, `build-xkey`, `lib`, `docker-ci`), so a
  host cache that already holds the graph serves the build with no fetch and
  no token; `docker-run` and `docker-test`, which run as `testuser`, keep
  resolving modules inside the image.
### Fixed

- CI's nine per-job `apt-get install` steps now go through one script that skips packages the runner image already carries, fetches only what is missing over IPv4 with a bounded retry, and fails naming any package dpkg still lacks. An archive outage no longer reddens a pull request that had no defect, and baking a package into the runner image makes its step a no-op without a workflow edit.
### Fixed

- The nightly xkey race suite installed its cgo packages with a raw `apt-get install` after the pull-request workflow had moved to the idempotent, retrying dependency script; it now uses the same script, so an archive outage no longer reddens the nightly run either.
- **The authoritative DNS pre-check queries a configurable port (#140, item 14).**
  `CheckDNSFromAuthoritative` appended a literal `:53` to every nameserver the
  zone's NS records named, with no way to query a zone served elsewhere. The
  pre-check gains `WithNameserverPort`; `DefaultDNSPort` (`"53"`) is the
  defaults-layer value, an empty port keeps it, and a caller-supplied
  `WithNameserverLookup` still returns complete addresses untouched.
- **The authenticated wrap verbs reported the `GODEBUG=fips140=only` GCM
  restriction as an internal fault (`CKR_FUNCTION_FAILED`) instead of an
  unavailable mechanism** (#292, FIPS conformance).
  `pkg/pkcs11/module/module_authwrap.go`, `pkg/crypto/aead/gcm_usable.go`.

  Under `fips140=only` Go's `crypto/cipher` refuses arbitrary-IV GCM — the
  construction every parameter form of `C_WrapKeyAuthenticated` /
  `C_UnwrapKeyAuthenticated` depends on, including the token-generated-IV
  form, which still hands `cipher.NewGCM` an IV from the module's own RNG.
  The refusal surfaced from inside the wrap as `CKR_FUNCTION_FAILED: failed
  to create GCM`, telling the application the token malfunctioned rather
  than that the regime withholds the operation. The verbs (wrap, size query
  and unwrap) now refuse at the mechanism check with
  `CKR_MECHANISM_INVALID`, before any handle is resolved, and the size query
  answers with the same code the wrap itself would.

  The gate is a runtime probe, `aead.ArbitraryIVGCMUsable` — a throwaway
  arbitrary-IV seal, performed once and cached — not a FIPS predicate,
  because no exported predicate separates `fips140=only` from `fips140=on`,
  where the identical construction works; gating on `fips140.Enabled()`
  (true under both) would have withdrawn a working mechanism. Same
  disposition as #303's `HashUsable`. The `CKM_AES_GCM` descriptor is
  deliberately still advertised: its `C_Encrypt`/`C_Decrypt`/`C_WrapKey`
  surface performs GCM in the service process, whose own FIPS posture
  governs it, so only the verbs that build GCM locally refuse. No ciphertext
  framing changed — `NewGCMWithRandomNonce` was ruled out in the issue
  because it cannot honour a caller-supplied IV and cannot open existing
  wrapped blobs. This closes the last of #292's three instances (the jwk
  thumbprint and the KDF hash set were fixed by #300 and #303).

  The one genuine panic the sweep recorded for this package was not in
  production but in a test oracle (`crypto_wrapnonce_test.go`), which
  panicked on the GCM construction error and aborted the test binary
  before every test after it ran; it now returns the error through the
  mock transport, so the suite under `fips140=only` reports the remaining
  non-approved-mechanism expectations as ordinary failures instead of
  hiding them.

  Verified by re-exec'd subprocess tests in both activated modes:
  `fips140=only` gets `CKR_MECHANISM_INVALID` from all three verbs with zero
  panics, and `fips140=on` completes the full wrap/size/unwrap round trip;
  the only-mode test fails against the unfixed code with
  `CKR_FUNCTION_FAILED`.
- **A raw PKCS#1 v1.5 RSA signature (hash `NONE`) under `GODEBUG=fips140=only`
  now returns a typed error instead of panicking** (#486, fourth instance of
  the #292 class). `pkg/types/rawpkcs1v15.go`, `pkg/xkms/servicer_crypto.go`,
  `pkg/testing/pkcs11test/crypto_mock_client.go`.

  `Sign` and `Verify` accept the hash name `NONE` to sign or check caller-built
  bytes verbatim — what PKCS#11's `CKM_RSA_PKCS` sends for `C_Sign` and
  `C_SignRecover`. In the only mode `crypto/rsa` admits a PKCS#1 v1.5
  signature solely under a digest it can classify as approved, and at that
  site it calls `crypto.Hash(0).New()`, which *panics* ("requested hash
  function #0 is unavailable") rather than returning an error. The sweep found
  it in the `pkcs11test` mock backend, where it aborted the module conformance
  binary; the production service reaches the identical call for an in-process
  RSA key, on both the signing and the verifying side (verification is always
  in-process). The PKCS#11 backend is not affected: it builds its own
  `DigestInfo` and never enters `crypto/rsa`.

  `types.CheckRawPKCS1v15(key, hash)` refuses first with
  `types.ErrRawPKCS1v15Enforced` when the digest is `crypto.Hash(0)`, the key
  is an in-process `*rsa.PrivateKey` / `*rsa.PublicKey`, and
  `crypto/fips140.Enforced()` is set. That predicate — new in Go 1.26 — is the
  very variable `crypto/rsa` reads at the panicking site, so it cannot
  disagree with the runtime; it is not `fips140.Enabled()`, which is also true
  under `fips140=on`, where the raw form works and is left alone. The service
  wraps the refusal in `ErrSigningFailed` / `ErrVerificationFailed`; the mock
  returns it directly, and the module surfaces it as `CKR_FUNCTION_FAILED`.

  Verified by re-exec'd subprocess tests in `pkg/types`, `pkg/xkms` and
  `pkg/testing/pkcs11test`: under `fips140=only` all three get the typed error
  with zero panics and the SHA-256 form still round-trips; under `fips140=on`
  the raw form signs and verifies. Each package's in-process test asserts the
  check against the operation itself, so it holds in whichever mode the suite
  is run. Removing the guard in either the mock or the service brings the
  panic back in the corresponding test.
- **GCP KMS operations resolve the current primary key version instead of always version 1.** The GCP KMS backend's Encrypter and Decrypter operations were hardcoded to use version 1 of the key, so key rotations (which create new versions and promote them to primary) took effect only after a process restart. Key resolution now queries the key's metadata and uses the current primary version for all operations, so rotation takes immediate effect. Azure and Vault signers similarly pin the version resolved at signer construction so Public() matches the signing key, ensuring consistency across the key's lifecycle.
- **`make test` no longer dirties the working tree, and the web dependency
  trees install from the lockfiles (#454).** The vitest coverage reports of
  `sdk/ts`, `sdk/ts/svelte-auth` and `web/app` (132 files, HTML and
  `lcov.info`) were tracked and rewritten by every `npm run test:coverage`;
  they are untracked and ignored, along with `node_modules/`. Every
  `npm install` in the build and test paths is now `npm ci`, which installs
  exactly the lockfile and refuses to rewrite it, so the tested dependency
  set is the pinned one; all seven lockfiles were verified in sync. The
  embedded `xkey/frontend/dist` stays tracked: `//go:embed all:dist` reads
  it at compile time, so untracking it would break every plain `go build`
  of xkey; with `npm ci` the Vite build is reproducible, which is what
  removes that churn.
- **In-house Go module resolution follows the Gitea move.** The `insteadOf`
  rewrite that resolves `github.com/jeremyhahn/*` against the internal Gitea
  instance was pinned to the old host in eleven places — the root `Makefile`
  (both the container env block and the generated runner export), the
  devcontainer compose file, and eight `test/integration/*/docker-compose.yml`
  files. Every devcontainer build and integration-test target that fetches an
  in-house module failed to reach the server. The review workflow's
  `OLLAMA_URL` is deliberately unchanged: that service did not move.
### Fixed

- The xkey GUI no longer applies a sealed enterprise policy it has not verified. Before SO login the FIDO2 authenticator and the browser-extension gates run on `DefaultPolicy()`; the file's values, including any relaxation of a secure default, apply only after the SO PIN authenticates the section. (#495)
- **Hardware certificate storage can release one record of a cert/chain pair (#143).**
  `HardwareCertStorage` gains `DeleteCertChain`; `DeleteCert` on PKCS#11
  now releases only the certificate object and leaves the `id-chain-<n>`
  objects, which `DeleteCertChain` releases on their own; on TPM2 the one
  NV index per id records its kind (`SaveCertChain` stamps a `Record: chain`
  PEM header), so every method addresses the record only when it is of
  its kind — a certificate read or delete of a chain record, and a chain
  read or delete of a certificate record, is `ErrNotFound`, as is an absent
  record. The storage adapter routes
  `certs/{id}-chain.pem` and `certs/{id}.pem` to their own releases; it
  still does not claim `storage.CompareAndDeleter`, now because a token or
  NV index has writers its lock cannot serialise, and the absence is
  pinned. The hybrid store and the external adapter follow.
  The hybrid store's deletes report a real failure on either side as an
  error instead of masking it behind the other side's absence. PKCS#11 object searches now page through `C_FindObjects`
  until the token returns an empty page, so a chain member past the first
  page is neither invisible to the delete nor to its verification.
  With the kind in the TPM2 record, a chain that overflowed to the external
  side is released there while the hardware certificate stays, and a stale
  one-member hardware chain behind a newer external chain goes with the
  chain instead of reappearing on the next read. A PKCS#11 object whose id
  cannot be read fails the search as an unknown outcome instead of being
  skipped.
  A PKCS#11 listing classifies chain members by the exact `<id>-chain-<n>`
  shape rather than any `-chain-` infix, so a certificate whose id merely
  contains the infix no longer disappears from `ListCerts`. Ids of the
  shapes the chain encoding reserves, `<id>-chain` and `<id>-chain-<n>`, are
  refused on every path that accepts a certificate id, on every store
  (`ErrIDReservedForChain`), so `certs/<id>-chain.pem` can only ever name
  `<id>`'s chain.
- **`xkey backup` and `xkey device` address the xKey home through `xhome`
  (#442).** Two home-root literals survived #381's data-dir adoption because
  they are of a different shape: the default backup directory was
  `$HOME/.xkey/backups` and the shared devices file `$HOME/.xkey/devices.yaml`
  whatever `XKEY_HOME` or portable mode said, so a backup written under a
  configured home was not where the operator would look for it. Both now
  resolve through the same four-strategy chain as every other command, and a
  home that cannot be resolved is an error rather than a path under `$HOME`.
  `xhome.ResolveForUser(homeDir)` is new: the per-user strategy evaluated
  against a given home, which is how `sudo xkey device pair` keeps sharing
  the invoking user's devices file with their GUI session while `XKEY_HOME`
  and portable mode still take precedence. The `cmd` package's grep gate
  gains a home-root pattern (`TestNoAdHocHomeRootLiterals`) so the shape
  cannot regrow.
### Fixed

- The go-qrdb KVStore adapter and the ACME tenant-scoped store no longer drop the guarded operations. Both forward `PutIfAbsent`, `CompareAndDelete` and `CompareAndSwap` when the store they wrap can perform them, and neither claims the capability when it cannot, so a DAO built over them no longer loses atomic conditional writes at run time while still compiling. A backend now reports whether its guarded writes can execute (`storage.GuardedWriteReporter`), because declaring the methods is not the same as performing them: the QRDB backends from the embedded constructors declare all three and fail every one for want of a transaction service. (#89)
- **`make build` works on a host whose Go is older than the module declares.**
  The module has required Go 1.26.7 since 2026-08-27 and the fleet pins
  `GOTOOLCHAIN=local` on hosts, so a host on 1.26.4 refused every Make target
  (`go: go.mod requires go >= 1.26.7`) while the Docker builder, running
  under `GOTOOLCHAIN=auto`, downloaded the right one. The Makefile now
  selects the toolchain go.mod declares for every recipe, so the host go only
  bootstraps that exact version and the build is the same on every host and
  in CI. `make GOTOOLCHAIN=local ...` restores the host's own go.
- **The MCP `copy_key` tool no longer refuses every key at the export step
  (#155).** `handleCopyKey` built the source key's attributes by hand with
  the common name and store type only, so `Exportable` was always false and
  the backend refused every copy with "key is not exportable", whatever the
  key's real exportability; the error read as the caller's fault and the
  test that covered it passed for non-exportable and exportable keys alike.
  The handler now delegates to `XKMSService.CopyKey`, which resolves the
  source key's stored attributes from the backend's own listing, so what the
  key is decides whether it may leave, and a request cannot assert
  exportability of a key that has none (`CopyKeyParams` deliberately has no
  such field). A copy still does not complete: the software backend's
  `ExportKey` wraps under a wrapping key it mints itself while the service
  replaces the import token with the destination's (#154); that is now
  pinned by type as the only step allowed to fail for an exportable key.
- **MCP `getImportParameters` can name the algorithm, so `key_spec` is no longer always `UNKNOWN` (#164).**
  The params gain `key_type`, `key_size` and `curve`, the vocabulary the
  import already takes, and the handler resolves the request through the
  service like the import does, so the backend names the spec the import
  will check the material against. The MCP client transport builds the
  params by name and decodes the PEM wrapping key in the result back to the
  DER the contract carries; it used to marshal the contract request and
  decode the contract response, so the caller's key type went nowhere and
  the wrapping key came back empty.
- **MCP "invalid backend" refusals carry a sentinel and accept configured names (#176).**
  Five handlers refused a backend name with a bare message, so a caller could
  only tell that refusal apart from any other failure by matching its text;
  and they judged the name with `types.ParseStoreType`, which refused every
  configured backend name that is not a store-type keyword. The five sites now
  resolve the name through the service's `LookupBackend` and refuse with
  `mcp.InvalidBackendError`: `errors.Is` finds `mcp.ErrInvalidBackend`, the
  service's reason (`xkms.ErrBackendNotFound`, `xkms.ErrBackendNameValidation`)
  is the cause, the message is `invalid backend: <name>: <reason>`, and the
  JSON-RPC code is invalid-params. A registered name such as `token-a` is
  accepted; an upper-case or padded spelling, which the old gate normalised
  away, is refused like everywhere else.
- **Test: `TestHandler_Decrypt_OAEPHashArrives` no longer fails one run in
  ~700.** Its last assertion required PKCS#1 v1.5 decryption of an OAEP
  ciphertext to error, but v1.5 unpadding accepts the uniform bytes such a
  decrypt produces whenever they happen to carry its `00 02 … 00` frame
  (measured 432 of 300,000 attempts). The assertion now states the property
  that matters, that the paddings are not interchangeable: a v1.5 decrypt
  either fails or does not return the plaintext.
- **`DeriveNoiseAddr` no longer mangles IPv6 literals (#140).** The Noise
  bootstrap address derived from a server URL was cut at the last colon, so
  `https://[fd00::1]` became `[fd00::8445` and a userinfo prefix survived
  into the dial. The host is now taken from a parsed URL and joined with
  `DefaultNoisePort`; a bare IP literal, bracketed or not, is joined whole; a
  URL with no host derives nothing and surfaces as `ErrServerURLRequired`.
- **A Noise bootstrap server that finished draining as the shutdown deadline
  expired is no longer reported as an incomplete shutdown, and its static keys
  are destroyed rather than retained** (#83). `pkg/server/server.go`.

  `noiseStopDrained`, the one decision that licenses freeing the bootstrap
  static keys' protected pages, required both a nil from
  `noiseboot.Server.Stop` and an unexpired caller context. The second conjunct
  was the only signal under go-truststrap v0.2.0-alpha, whose `Stop` returned
  nil on its own timeout path too. The pin is now v0.4.0-alpha
  (go-truststrap#13): nil is returned only after the run's WaitGroup has
  emptied, the caller's deadline expiring first is `ErrShutdownIncomplete`,
  and upstream re-checks its drained channel before ever saying so, precisely
  so that a server that finished is not reported as incomplete. Reading the
  expired context over that nil undid the re-check: a drain that completed as
  the deadline expired retained a key that was safe to wipe and put
  "noise bootstrap handshake workers" into xkmsd's `ErrShutdownIncomplete`
  when nothing was still running. The decision now reads the error alone;
  concurrent `Stop` callers may still see different outcomes, each under its
  own deadline, and nothing here assumes otherwise — the two call sites
  already derive their own contexts.

  Held against the pinned server, not its description:
  `TestNoiseStop_NilIsAuthoritative` completes a handshake and leaves the
  worker blocked, then shows eight concurrent `Stop` callers (short and
  already-expired deadlines) all get `ErrShutdownIncomplete` and never nil,
  and that once the worker exits `Stop` returns nil under an already-expired
  context too. Passes 200 of 200 under `-race`. The decision table now names
  upstream's sentinels, so a future pin that changes them turns it red.
- **Password store moves and renames write the destination before deleting the source; migration no longer deletes legacy records it has not confirmed migrated.** The password store's Move operation was deleting the source before confirming the destination write succeeded, so a crash between delete and write would lose the record. The operation now writes the destination first and verifies the read succeeds before deleting the source. Password migration (from plaintext to hashed) now deletes a legacy record only after confirming the migration wrote a new hashed record and the read-back verified it.
### Fixed

- **PKCS#11: `C_UnwrapKey` and `C_GenerateKeyPair` now agree about which EC
  curves the module accepts.** The module recognises the Edwards and Montgomery
  OIDs so `CKA_EC_PARAMS` can identify their own key types, but an ECDSA key
  cannot live on them. An unwrap naming one — the X25519 OID is the shape older
  implementations such as NSS emit for Curve25519 — used to resolve as
  recognised, reach the backend, and come back as a generic `invalid curve`
  several layers down, while an OID the module does not carry at all was
  refused at the module with `CKR_CURVE_NOT_SUPPORTED`. One condition, two
  answers, and only the second is one a PKCS#11 caller can act on. Both verbs
  now resolve the curve through one predicate and return
  `CKR_CURVE_NOT_SUPPORTED`.

  `templateCurveName` no longer reports "attribute absent" and "attribute names
  something unusable" with the same value: it returns the name, a presence
  flag, and the `CK_RV` separately. An omitted `CKA_EC_PARAMS` still reaches the
  backend and takes the service default, which PKCS#11 v3.2 Table 13 footnote 6
  requires for an unwrapped EC private key.
- **Test: `TestCryptoManager_Sign_ECDSA_ProducesVerifiableRawSignature` no longer
  fails one run in 256.** It rejected any raw `r || s` signature whose first
  byte was `0x30`, the DER SEQUENCE tag, but `r` is uniform so that byte is
  `0x30` in one signature of every 256 (measured 82 of 20,000; the test failed
  4 of 600 runs on an unchanged tree). The 64-byte length already rules DER
  out, and the verification that follows proves the halves are the signature.
- **`PKCS8Backend.ListKeys` reports an X25519 key as X25519 and an
  unrecognised algorithm as unknown (#154).** The listing had no `x25519`
  case, and its defaults block rewrote every algorithm it did not recognise
  to RSA-2048, so an X25519 agreement key was described as an RSA key and a
  re-import driven off that listing failed for the wrong reason. An X25519
  key is now listed with `X25519Attributes` set and `KeyAlgorithm` unset,
  the shape `GenerateKey` accepts and the software backend's key-type
  validation requires; an algorithm the backend does not produce is listed
  with `KeyAlgorithm` unset and logged, never renamed. The `CopyKey` token
  mismatch the same issue records is separate and is not in this change.
- **`PlatformKeyStore.IsProvisioned()` reports what the SRK handle actually
  holds after a failed PIN change (#448).** A PIN change evicts the persistent
  SRK before recreating it; when the recreate or re-persist failed, the
  store kept reporting provisioned over an empty handle, so the retry through
  `Initialize` took the verify-existing-SRK branch and failed at `ReadHandle`
  instead of recreating the key. The failure path now re-probes the handle,
  the same probe the constructor runs, and sets the provisioned state from
  what is there: gone means unprovisioned and the next `Initialize`
  recreates; present means provisioned but, as before, not auth-ready.
  Recovery stays with the retry; the failure path reports, it does not
  re-provision.
- **`make test` no longer fails on a loaded runner because the release-assets
  stub server was slow to start.** `test/scripts/release-assets.test.sh` gave
  its stub Gitea API 5 s to publish a port; past that, an empty `PORT` silently
  became port 80 and every assertion failed with `Failed to connect to
  127.0.0.1 port 80`. The wait is now 60 s, and a server that never binds
  fails the suite by name with its own stderr instead of by side effect.
- **`release.yml` survives a flaked matrix leg (#447).** The asset upload
  deleted an existing asset and re-uploaded it, which Gitea answers with
  404, so re-running a release after one leg flaked failed every leg that
  had already succeeded; `Create Master Checksums` then never ran and the
  tag, which cannot be re-cut, lost its checksums file for good. Uploads
  now go through `scripts/release-assets.sh`, which leaves an asset that is
  present with the same SHA-256 alone, replaces one whose digest differs
  and adds one that is absent. The checksums job runs whenever the release
  exists, verifies the release carries every asset the build matrix
  produces (failing on what is genuinely missing, not on how many runs it
  took), assembles `checksums.txt` from the per-asset `.sha256` files it
  downloads through the Gitea API, and uploads it the same idempotent way;
  the `gh` CLI it used before does not speak to Gitea, so that download had
  been silently empty on every release cut here. The announcement is gated
  on the verified release rather than on this run's matrix.
- **The release workflow always reaches a terminal state.** A build leg
  that hung ran into the runner's three-hour default and left the run
  `in_progress` while the release page showed only the legs that had
  finished, with no master checksums. Every job now carries a
  `timeout-minutes` sized from the healthy runs (75 minutes for a binary
  leg, which builds arm64 under QEMU in 20–33), the matrix no longer
  cancels its other legs when one fails, and the checksums job is a bare
  `always()` gate that fails the run naming every expected asset the
  release lacks, so a partial release is a red run rather than a
  green-looking page.
- **Import, wrap, unwrap and import-parameters work over the REST and QUIC transports (#522).**
  The two client transports marshalled `transport.ImportKeyRequest`,
  `WrapKeyRequest`, `UnwrapKeyRequest` and `GetImportParametersRequest`
  straight onto routes whose handlers decode the REST body, which spells
  the material `wrapped_key` and carries the wrapping key as PEM: the
  material arrived under a name the handler never read, the wrapping key
  arrived as base64, the import-parameters response came back with no
  wrapping key, and `partition`, `metadata` and `key_spec` were dropped,
  so no step of the ceremony over REST or QUIC could succeed. The REST
  bodies now live in the leaf package `pkg/api/rest/wire`, aliased by the
  handlers and built by name by both transports, which translate the
  wrapping key between DER and PEM and refuse a key that is not DER with
  the typed `wire.ErrWrappingPublicKeyNotDER`. The REST bodies gain
  `partition`, `metadata` and `key_spec`, `GenerateKeyRequest` gains
  `partition`, and a contract test pins every field against the transport
  contract.
- **The Noise server's lifecycle sentinels reach the SDK (#498).**
  `NoiseServer.Stop` returns `ErrShutdownIncomplete` when the caller's
  deadline expires before the handshake workers drain, and `Start`/`Stop`
  return `ErrServerAlreadyStarted`/`ErrServerNotStarted`, but neither
  `pkg/trust/bootstrap` nor `sdk/go/bootstrap` re-exported them, so an SDK
  consumer orchestrating the server had to import go-truststrap to dispatch
  on them, which the layer ownership forbids. Both layers now carry
  `ErrNoiseShutdownIncomplete`, `ErrNoiseServerNotStarted` and
  `ErrNoiseServerAlreadyStarted` as the upstream values.
- **The Go SDK aliases the failure-class parse error (#391).**
  `sdk/go` gains `PeerFailureClassError = peer.FailureClassError`, the typed
  error `PeerFailureClass.UnmarshalText` returns for a name that is not
  `none`, `absence` or `cryptographic`. A consumer that persists a verdict's
  class as text can now parse it back through the alias type's own method and
  `errors.As` the rejection, instead of reimplementing the mapping or
  importing `pkg/attestation/peer` across the layer boundary.
- **The server certificate's SANs are configuration, not literals (#140,
  cluster 3).** Every auto-issued server certificate carried `localhost`,
  `127.0.0.1` and `::1` unconditionally, and the CA-issued one an
  unconditional `0.0.0.0` IP SAN as well; no configuration could remove them.
  `tls.include_localhost_sans` (`XKMS_TLS_INCLUDE_LOCALHOST_SANS`,
  defaults-layer `true`) now governs the loopback names for both the
  bootstrap and the CA-issued certificate through one shared builder, and
  the wildcard address is gone: no client dials it, and a wildcard is not a
  name a certificate should present. A certificate issued under an earlier
  configuration is reissued at the next start rather than served stale. The
  CA-issued certificate, shared by every node, no longer carries the issuing
  node's hostname; list a name clients dial in `tls.extra_sans`.
- **`server.host` binds the listeners it names, through one configuration
  chain (#140, cluster 1).** The REST listener configuration was built
  without a host, so `server.host` validated and was then discarded on the
  listen path, and the library gRPC server had no host field at all and bound
  the wildcard from a literal. `pkg/config.Load` now resolves defaults → file
  → environment through viper (`XKMS_<SECTION>_<KEY>` works for every key,
  the optional `acme`, `trust`, `webauthn` and `backends.*` sections
  included, whether or not the file declares them; `XKMS_HOST` stays as an
  alias below the canonical `XKMS_SERVER_HOST`), a
  `Defaults()` layer holds the one allowed literal, `xkmsd --host` sits on top
  with `Changed()` semantics, and both `rest.Config.Host` and the new
  `grpc.ServerConfig.Host` consume the resolved value. A value that cannot
  decode into its field now fails `Load` rather than being dropped. The
  legacy environment ladder cedes to the canonical names: where both
  `XKMS_SERVER_REST_PORT` and `XKMS_REST_PORT` are set the canonical form
  wins, as documented, for every name the ladder still owns. A SIGHUP
  re-applies the command-line flags over the reloaded file, so
  `xkmsd --host` is not silently dropped on reload. New feature folder
  `docs/xkmsd-configuration/`.
- **Removed a stray xkey SSH store from the repository root (#453).** A manual
  `xkey ssh` run with the data directory set to `ssh` had written its profile
  and key-record store to `ssh/ssh/` inside the checkout, and the directory was
  committed. The two records were a host profile carrying a LAN address and an
  account name, and a key record holding only a public key and a backend
  reference — no private material. Nothing in the build or the tests referenced
  the directory. `/ssh/` at the repository root is now ignored so a local run
  cannot recommit it.
- **Device identity provisioning fails closed.** `Install` used to discard
  the EK certificate lookup error (`ekCert, _ :=`), log a failed
  `CreateIDevID` as "continuing without it", ignore every IDevID lookup
  answer other than TPM_RC_HANDLE, and return success — a device with no
  IDevID reported itself provisioned. Under TCG "TPM 2.0 Keys for Device
  Identity and Attestation" v1.00 r12 the ceremony either completes or the
  device has no identity: the TCG-CSR-IDEVID carries the EK certificate
  (§6.2.2 step 4b) and the CA verifies it before issuing (step 6b). Each site
  now refuses with a typed error — `ErrDevIDProvisionEKCert`,
  `ErrDevIDProvisionIDevID`, `ErrDevIDProvisionIAK`,
  `ErrDevIDProvisionLookup` — with the cause reachable through `errors.Is`.
  A platform whose EK certificate is not in NV RAM or the certificate store
  must provision it (`ProvisionEKCert`) before asking for an IDevID, or
  install without the `IDevID` option. A quote the TPM refuses while building
  the CSR's `prodCaData` is likewise refused (`ErrTCGCSRAttestation`) instead
  of being dropped from the CSR; absence of a transport to quote over is
  still reported as an absent field, as §13.1 allows.

- **TCG-CSR-IDEVID emitted to §13.1.** Three departures fixed in the
  structure the device sends to the CA: `TCG_CSR_IDEVID.structVer` is now
  `0x01000100` ("Version 1.0 = 0x01000100"; the leading `0x01` identifies an
  IDevID CSR) where the content structure's `0x00000100` was written before;
  the pad is `padSz` bytes of random data from the TPM's RNG, not a `=`
  filler; and `hashAlgoId`/`hashSz` both describe the signer's hash — the
  IAK's under the IAK strategy, the IDevID's under single-pass — where they
  were taken from two different keys and agreed only while both used SHA-256.
  Exported as `TCGCSRIDevIDStructVer`, `TCGIDevIDContentStructVer` and
  `TCGCSRAlignment`. The parser (`UnmarshalIDevIDCSR`) is unchanged and
  accepts both structure versions, so a CA on this release still enrolls
  devices on the previous one. Pinned by a reader written from the
  specification's field list (`tcg_csr_structure_simulator_test.go`) that
  never consults the packer under test.

- **`pkg/tpm2` runs in CI.** `make test` greps `pkg/tpm2` out of its package
  list, so no simulator suite — the TCG policy vectors, the CSR structure
  test, the provisioning tests — had ever run in CI. New targets
  `test-tpm2-simulator`, `coverage-tpm2-simulator` and
  `bench-tpm2-simulator` run the package under the
  `codec_cbor codec_json codec_msgpack tpm_simulator` tags, and the CI job
  `tpm2-simulator` invokes the first. The job is not yet in the `ci-gate`
  needs list.
- **A device identity key's configured authValue survives a restart, and an
  IAK with one can be provisioned at all.** The cold-cache rebuilds
  `IDevIDAttributes()` and `IAKAttributes()` reconstructed the key from the
  TPM and configuration but never restored `idevid.password` /
  `iak.password`, so a key provisioned with an authValue signed in the
  process that provisioned it and answered `TPM_RC_BAD_AUTH` to every
  USER-role command from the next boot on. Separately, `CreateIAK`
  authorized the IAK's self-certification (`TPM2_CertifyCreation`) with the
  EK's password instead of the IAK's, invisible while both were empty and a
  provisioning failure the moment `iak.password` was set. The
  configuration-derived fields of both keys -- CN, key type, platform
  binding, signature algorithm and authValue -- are now assigned by one
  function on the provisioning and restart paths, so a fourth field cannot
  drift the way the CN (#337), PlatformPolicy and KeyType (#466) and the
  password did. The simulator harness also registers the simulator's close
  before provisioning can fail, so a failed harness reports its failure
  instead of hanging every later test on the simulator lock (#467).
- **A FIPS-built client can bootstrap over the Noise transport (#269, #436).**
  `ModeNoise` reached the wire through go-truststrap's `NewNoiseBootstrapper`
  facade, which carries one Curve25519 key and no suite selector, so a FIPS
  client could only ever offer Noise_NK and failed at the handshake under
  both mechanisms (`-tags fips` and `GOFIPS140` + `GODEBUG=fips140=only`),
  even against a server that #435 had already taught to serve the approved
  P-256 suite. `pkg/trust/bootstrap` now composes go-truststrap's
  suite-negotiating `noiseboot.Client` directly. `NoiseConfig` gains
  `ServerP256StaticKey` (the server's uncompressed P-256 point, as printed by
  `xkmsctl bootstrap noise show-p256-key`) and `Suite`; the suites offered
  are resolved by the same probe the listener uses, `EnsureSuiteAvailable`,
  never by a build tag. Resolution fails closed: an unavailable suite is
  skipped, a configured key that will not decode is a `SuiteError`, a pinned
  suite this build cannot run is a `SuiteError` rather than a fallback, a
  pinned suite reads only its own key (the other suite's key is never
  consulted), and
  nothing left to offer is a `NoSuiteError` naming the build as the
  constraint. The Curve25519 path is unchanged for every existing
  configuration. `xkmsctl bootstrap auto` takes `--p256-key`, the resolver's
  `noise:` scope takes `server-p256-static-key`, and the new errors are
  re-exported through `sdk/go/bootstrap`. `ModeAuto` now walks
  go-truststrap's method order over this package's own single-mode
  fetchers, so its Noise arm is the same suite-negotiating client and
  `xkmsctl bootstrap auto --p256-key` alone completes the approved
  handshake; go-truststrap's dispatcher built that arm from its facade and
  a P-256-only client failed under it with a misleading "mode not
  configured". The order, per-method timeout and aggregate error shape are
  unchanged.
- **The WebAuthn user store no longer decides "no such user" by substring
  (#183).** `isUserNotFound` matched any error whose text contained
  "not found", "ErrCodeNotFound" or "no rows", so a transport failure such
  as "connection not found" or "tenant not found" was reported as
  `ErrUserNotFound`: the registration ceremony then created a duplicate
  account, and a consumer's rollback guard could delete a credential it did
  not create. Classification is now typed, per go-qrdb#286's measured
  contract: `*transport.UserNotFoundError` (REST),
  `*transport.KeyNotFoundError` (gRPC, MCP, embedded) and the embedded DAO
  not-found are absences; QUIC's opaque `*transport.RequestError` is
  recognised only when its message is, by exact prefix, one of the user
  service's own canonical forms. Everything else is an error. The credential
  store was already typed; the two classifiers now agree.
- **`SSHProxy.Stop` waits for the accept loop.** It closed the listener and
  waited for the connection handlers, but never for the accept goroutine
  itself, and the `done` channel it closed was read by nobody, so `Stop`
  could return while that goroutine was still winding down. The race
  detector reported the caller's next write against the goroutine's last
  read, and once #481 began running `xkey/pkg/agent` under `-race` on every
  PR that became a gate flake (`TestSSHProxy_StartStop`, reproducible within
  300 runs on `main`). The accept loop now owns its listener, closes `done`
  when it returns, and `Stop` waits on it before removing the socket:
  0 races in 300 runs and in the full package.
### Fixed

- **xkey GUI: an unlock that fails because the barrier seal strategy is
  unavailable no longer reports "invalid PIN".** On a TPM host configured with
  `barrier_strategy: tpm2`, unlocking after the idle auto-lock failed with
  `qrdb/seal: requested strategy not registered` and the CLI printed
  `app_lock: invalid PIN`. The PIN retry counter never moved, which is the
  proof that no PIN check ran — the unseal never reached the credential. An
  operator told a correct PIN is wrong will retry it, and on a backend that
  does count attempts that is a path into a lockout over a fault no PIN could
  fix.

  `AppLockService.Unlock` now classifies `ErrStrategyNotFound` and
  `ErrStrategyMismatch` (including wrapped) as the new
  `ErrAppLockUnsealUnavailable`, whose message states that the PIN was not
  checked. The GUI's own `*ErrBarrierStrategyUnavailable` — what
  `BarrierService.Unseal` returns on a host with no usable TPM sealer, and the
  shape that actually produces the reported failure — is classified with it;
  that type wraps no cause, so it needs `errors.As` and one shared predicate
  covers both. A corrupt barrier root key is now `ErrAppLockStorageCorrupt`
  rather than an invalid PIN, matching the data-loss classification gRPC and
  REST already give `ErrCorruptRootKey`. An unseal that genuinely failed on the
  credential still reports `ErrAppLockPINInvalid`.

- **xkey setup wizard: the hardware→passphrase barrier fallback no longer fires
  over a barrier that already exists.** The fallback is for a hardware strategy
  that cannot *initialize* a barrier, where nothing is stored yet and a retry
  costs nothing. It was also firing when a barrier already existed and would
  not unseal — where the retry reaches a different strategy than the one the
  data was sealed with, discards the real error on its way past, and reports
  either a bogus credential failure or a silent downgrade to a software
  barrier. On the reported host that ended the run with `setup_complete: false`,
  and the next launch re-ran the wizard and minted a **new User PIN**, pushing a
  new hash to the authenticator. `initBarrier` now reports the two failures
  distinctly and the fallback is gated on "nothing is stored yet".
- **xkey: `XKEY_*` environment variables reach every leaf key (#140, xkey mechanism gap).**
  The loader registered each config section as one opaque struct default, so
  viper knew `xkmsd` but not `xkmsd.address`, and `AutomaticEnv`, which only
  consults the environment for keys viper knows, never looked `XKEY_XKMSD_ADDRESS`
  up; no `XKEY_` variable took effect, while the configuration reference said
  all of them did, and the one test hedged between the two outcomes. The loader
  now walks the config struct and registers every leaf with its default and its
  `XKEY_<KEY>` binding, so environment wins over file wins over default at leaf
  granularity, lists of scalars split on commas, and an environment value is
  validated like a file value. `backends.local`, `backends.remote`,
  `backends.defaults` and `fido2.extensions` cannot be expressed by one
  variable; a variable set for one of them fails the load instead of being
  ignored.
- **xkey GUI: the OIDC login callback listener binds the configured host (#140, item 8).**
  The desktop GUI's OIDC login listened on `":"+port` with `SO_REUSEADDR`,
  every interface, for a browser redirect that only arrives on loopback, and
  defaulted the redirect URL from a literal `8085`. The callback listener
  logic now lives once in `xkey/pkg/oidc` (`Callback`, `ListenAddrs`,
  `BindCallback`, `ServeCallback`), shared by the CLI and the GUI; the GUI
  service takes `oidc.callback_host` / `oidc.callback_port` from the unified
  config through `SetCallback`, binds the loopback pair for `localhost` (with
  `SO_REUSEADDR` kept), refuses a callback host that cannot serve the
  provider's redirect host before opening the browser, and, as the CLI now
  does too, answers on exactly the redirect URL's path (a literal
  comparison, never a ServeMux pattern) rather than a fixed one. A unified
  config that fails to load disables the GUI login with the cause instead of
  binding the built-in callback in place of the operator's.
- **xkey: the agent server and the pairing relay bind configured addresses (#140, xkey mechanism gaps).**
  `xkey agent start` bound `:9443` with `--listen` as its only path, and
  `xkey device relay` bound `:8444` from a flag default no config file or
  variable could reach. The xkey config gains `agent.listen_address` and
  `phone.relay_listen_address` (each validated as host:port;
  `XKEY_AGENT_LISTEN_ADDRESS`, `XKEY_PHONE_RELAY_LISTEN_ADDRESS`), and each
  command resolves flag over configuration over the built-in default, which
  is unchanged. The audit's third xkey gap, the agent client's
  `LocalAddress`, is a declared field nothing reads; it gets no
  configuration path until the client binds it.
- **xkey: the OIDC and AWS login callback listeners bind a configured host and port (#140, items 7 and 13).**
  `xkey oidc login` listened on `":"+port`, every interface, for a browser
  redirect that only ever arrives on loopback, and `xkey oidc aws` hard-coded
  port 8085 with no flag, variable or config path. The xkey config gains an
  `oidc` section (`callback_host`, default `localhost`, which binds both
  loopback families since the browser may resolve the redirect host to either;
  `callback_port`, default 8085; `XKEY_OIDC_CALLBACK_HOST` /
  `XKEY_OIDC_CALLBACK_PORT`), and both commands gain `--callback-host` and
  `--callback-port` (held to 1-65535). The default redirect URL follows the
  callback host, so the browser is always sent where the listener is. The
  listener binds the callback host on the redirect
  URL's port, so an explicit `--redirect-url` or a saved provider's keeps the
  port registered with the provider; the default redirect URLs and the AWS
  refresh worker take the port from configuration. AWS's redirect host is
  fixed at `127.0.0.1`, so its listener serves `127.0.0.1`. The OIDC listener
  binds addresses that serve the redirect URL's host (the loopback pair for
  `localhost`, an IP literal itself, the configured address for another
  name, every interface for the empty host); a callback host that cannot
  serve the redirect host is a typed `OIDCCallbackHostError` before any
  browser opens rather than a five-minute timeout, and a redirect URL the
  listener cannot serve, an https one included (the listener is plain http),
  is a typed `OIDCRedirectURLError`.
### Fixed

- **xkey GUI: a failed PIV certificate delete is no longer read as "no
  certificate" on any error whose text happens to contain "not found".**
  `PIVService.DeleteCertificate` removes both the certificate and the key, and
  decided whether a failed certificate delete should block the key delete with
  `strings.Contains(err.Error(), "not found")`. A permission error naming a
  path, a missing *backend*, a missing key and an unknown slot all satisfy
  that, so any of them read as "carry on" — and the slot was reported empty
  while it still held a certificate, which is the opposite of the method's
  contract.

  The in-process path now classifies on the sentinel alone
  (`errors.Is(err, xkms.ErrPIVCertificateNotFound)`), which every local backend
  produces: the file backend wraps it in a `PIVStorageError` and the tpm2
  backend maps `storage.ErrNotFound` onto it. The remote path matches the
  sentinel, or the sentinel's own rendered text — which is what the server
  actually sends, since the error message goes into the response body — and
  nothing looser. Anything else now fails closed.

- **xkey GUI: deleting a PIV slot no longer reports success when the key was
  never inspected.** `DeleteCertificate` removes both the certificate and the
  key. When the certificate delete succeeded and the subsequent key listing
  failed, it logged the failure and returned `nil`, so the GUI reported the
  slot cleared while the backing key may still exist. Both paths now return the
  listing error, wrapped, naming that the key may remain.

## [0.11.0-alpha] - 2026-09-06

### Security

- **The OATH TOTP shared secret and the FIDO2 key-unwrap transit are moved
  into protected memory: the secret is no longer an unwipeable Go string at
  rest or through normalization, and unwrapped keys no longer cross the
  ordinary Go heap on their way into protected buffers** (#210, #291). `xkey/pkg/oath/credential.go`, `xkey/pkg/oath/generator.go`,
  `xkey/pkg/oath/dao_store.go`, `xkey/pkg/authenticator/key_wrapper.go`,
  `xkey/pkg/authenticator/key_manager.go`, plus the consumers in
  `xkey/cmd/xkey/cmd/`.

  **#210** — `Credential.Secret` was an immutable Go string, copied through
  three more strings on every normalization (`strings.ToUpper`,
  `strings.Map`, `strings.TrimRight`); none of the intermediates could ever
  be wiped. The field is now an mlocked `secure.Buffer` behind
  `SetSecret`/`SecretString`/`HasSecret` accessors, normalization runs
  byte-wise IN PLACE on a caller-owned slice (the Base32 alphabet is ASCII,
  so the fold needs no rune decoding and mints no copies), and every scratch
  decode is wiped. The persisted JSON keeps the historical `"secret"` key via
  marshal hooks, so existing stores load unchanged; `SecretString` is
  documented as serialization-boundary-only, since a handed-out string is the
  caller's residue. An equivalence corpus proves the byte normalization
  computes exactly what the string implementation computed (one deliberate
  divergence, U+017F-style Unicode folds, is asserted as rejected).

  **#291** — `KeyWrapper.Unwrap(wrapped) ([]byte, error)` returned decrypted
  plaintext on the heap, and #285 then copied it into protected memory,
  leaving the transit copy for the GC. The interface can no longer express
  that: `UnwrapInto(wrapped, dst []byte)` decrypts in place into
  caller-owned memory (asserted, failing closed with a wipe if the cipher
  ever relocates), and `unwrapIntoProtected` sizes the destination from the
  ciphertext alone — `len(wrapped) − nonce − tag` — so the `secure.Buffer`
  is allocated BEFORE the borrow on the wrapping key, honouring go-qrdb's
  purge-lock nesting rule that made the heap hop look load-bearing. Every
  unlock path (SO, user, attestation, SO-PIN change) now decrypts straight
  into mlocked memory; the plaintext never exists on the ordinary Go heap.

  Verified by wipe tests (adoption zeroes the source; a replaced or cleared
  secret's buffer is destroyed; a failed unwrap leaves an all-zero
  destination), by round-trip tests through the new seam, and by deadlock
  regression tests that re-run every borrow-crossing path under the test
  timeout — re-introducing the nested-borrow allocation hangs them, which
  the timeout turns into a failure. Closes #210, #291.
- **The setup wizard no longer stores the generated SO PIN in the device's
  own password store** (#290). The SO PIN is the recovery credential that
  resets a forgotten User PIN, and the password store is unlocked by the
  User PIN, so the copy was unreachable in every situation the SO role
  exists for (a forgotten User PIN after a lock or restart, a sealed
  barrier, a wiped store) and readable by anything that could drive the IPC
  socket once the store was open. Quick setup now shows the generated SO PIN
  once on the Generated Credentials step (masked, with reveal and copy) and
  requires the operator to acknowledge recording it out of band; `ApplySetup`
  refuses a quick setup without that acknowledgement with the new typed
  `ErrSetupSOPINNotRecorded`, before any step runs. Only the PIN service's
  verifier persists; the User PIN copy in the `xKey` folder is unchanged.
  Frontend contract: `SetupChoices` gains `so_pin_recorded` (bool);
  `save_pins_to_store` now saves the User PIN only. No reader of the stored
  entry existed to migrate. New feature folder `xkey/docs/setup-wizard/`.
  Files: `xkey/pkg/gui/services/setup_wizard_service.go`, `errors.go`,
  `xkey/frontend/src/views/SetupWizard.svelte`, `lib/types/setup.ts`,
  `lib/stores/wizard.ts`, `tests/e2e/global-setup.ts`. Verification:
  `setup_wizard_so_pin_test.go` asserts the store holds no `SO PIN` entry
  and no entry with the value after a quick-setup and a manual opt-in run,
  with the User PIN entry as positive control; reinstating the write turns
  both red, deleting the gate turns the acknowledgement test red.

### Added

- **`AgentOptions.SocketDir` lets the caller of the SDK's ephemeral SSH signing
  agent choose where its socket goes.** `StartAgent` bound its socket under a
  directory of its own choosing in the OS temporary directory, which is exactly
  the location a sandbox mount policy will not admit — so a consumer that runs
  the signing client in a container (go-quicbaas's `sdlc` job runner mounts the
  socket read-only and names it `SSH_AUTH_SOCK`, with no credential in argv or
  environment) could not use the agent at all. Setting `SocketDir` puts the
  socket inside a tree the caller's own policy already allows, and
  `SockPath` is `<SocketDir>/agent.sock`, computable before the call, because a
  mount specification has to name the socket before there is a session to ask.

  It gives the caller the **location**, never the directory. The session
  creates `SocketDir` itself with `os.Mkdir` (mode 0700 — never more
  permissive, since the process umask can only clear bits), binds the socket
  inside it with mode 0600, and removes the directory with the socket on `Stop` or
  context cancellation. That is what keeps the reason a 0600 socket is safe — no
  other user can traverse into its directory — a construction rather than a
  claim inherited from whoever made the directory first. An existing path is
  refused with `*SocketDirExistsError` (`*AgentSocketDirExistsError` through the
  SDK, unwrapping to `fs.ErrExist`), whether it holds a directory, a file or a
  socket from a crashed run: adopting one puts a signing oracle somewhere this
  package cannot vouch for, and clearing one would delete whatever the caller
  keeps there, up to and including another live agent. `os.Mkdir` makes the test
  and the claim the same syscall, so nothing can slip between them.

  The parent is checked and never created, by the same rule a supplied
  `WorkDir` passes — an existing, non-symlink, self-owned directory that is not
  group- or world-writable, else `*InsecureWorkDirError`. Creating the socket's
  own directory closes the substitution window inside it; nothing closes one in
  a parent another user can write to, where the whole directory can be renamed
  away and the container would then sign through somebody else's agent.
  `SocketDir` and `WorkDir` are mutually exclusive, since they say opposite
  things about who owns the directory and therefore about whether it survives
  shutdown. A relative `SocketDir` resolves against this process's directory
  on entry, once, so `SockPath` stays absolute and means the same thing to a
  process with its own working directory and PID namespace.

  Default behaviour is unchanged: an empty `SocketDir` still lands in the OS
  temporary directory. Sixteen tests across `pkg/ssh/agent` and the SDK cover
  the honoured path and its modes, every refusal, removal on both exit paths,
  and a client signing from a different working directory;
  `pkg/ssh/agent` coverage is 94.4%. Documented in
  `docs/ssh-agent-sessions/`. (#444)
- **`/api/v1/auth/me` returns the canonical email login key.** Since #190 made
  email the tenant-unique key the stack resolves accounts by, a client asking
  "who am I" got back a username it cannot re-authenticate with — a UI
  pre-filling a WebAuthn re-auth prompt had to display one identifier while the
  ceremony required another. `authMeResponse`
  (`pkg/api/rest/handlers_auth.go`) and the TypeScript `AuthMeResponse`
  (`sdk/ts/src/types/auth.ts`) now carry `email`, fed from
  `Identity.Metadata["email"]`. Every path that establishes an identity
  populates it alongside `username`: the qrdb-backed mTLS user projection
  (`pkg/auth/mtls.go`, `pkg/auth/qrdb_userstore.go`), the PIV certificate
  login, the WebAuthn token adapter (`pkg/api/rest/host.go`) and JWT generator
  (`pkg/webauthn/jwt_generator.go`), and the JWT authenticator's claim
  extraction (`pkg/auth/jwt.go`). The token issuer
  (`pkg/auth/token/issuer.go`) mints and re-reads an `email` claim on both
  halves of a pair — through one shared claim builder rather than two copies of
  the same block — so the key survives a refresh. OIDC already mapped the
  standard `email` claim and needed no change. An absent email stays absent: a
  principal with none (a service or bootstrap account bound only by
  certificate) yields no field rather than a value fabricated from the
  username. Verified by `make test-rest` (1046 passing), `./pkg/auth/...`,
  `./pkg/webauthn/...` and the TypeScript SDK suite; documented in
  `docs/webauthn/api.md`. (#194)
- **`xkey fido2 init-token` establishes the authenticator's Security Officer
  PIN, and `xkey fido2 change-so-pin` changes it.** The whole token lifecycle
  was already implemented — #306 shipped `Authenticator.InitializeToken` and
  `ChangeSOPIN`, xKey's `C_InitToken` and `C_SetPIN` as SO (PKCS#11 v3.0 §5.6)
  — but their only caller was the CTAP `authenticatorConfig` vendor dispatch
  (`xkey/pkg/authenticator/cmd_config.go`), which nothing on the host could
  reach. A device therefore stayed permanently uninitialized, and every
  SO-gated capability refused: `xkey fido2 provision-attestation` stopped at
  "this device has no Security Officer PIN", `replaceAttestKey`,
  `setAttestCert`, the user-PIN reset and the per-RP policy writes were all
  gated behind a credential nothing could establish. `xkey pin set-so` looked
  like the missing verb and is not — it drives the qrdb host PIN service over a
  file store under the data directory, an unrelated credential (#233).

  The two commands (`xkey/cmd/xkey/cmd/fido2_init_token.go`) call
  `InitializeToken` and `ChangeSOPIN` directly, the way `--set-pin` drives
  `SetInitialPIN` for the user PIN (#411): the in-process counterpart of the
  wire ceremony, not a second establishment mechanism. The vendor handlers pass
  straight through to the same two methods, so there is exactly one path to a
  Security Officer credential and one place its preconditions hold.
  `init-token` establishes and never replaces — an initialized token is refused
  with `ErrTokenAlreadyInitialized`, before the operator is prompted, and the
  authoritative guard under the state lock still refuses a race. After that the
  PIN changes only through `change-so-pin`, which proves the current one by
  authenticated decryption of the wrapped Admin Key and spends a persisted
  retry when it is wrong.

  The SO PIN is not written to the device's own password store. That store is
  unlocked by the *user* PIN and the SO PIN's job is to reset a forgotten user
  PIN, so keeping one inside the other would make the recovery credential
  recoverable only by the credential it recovers (#290, #432). It is typed at
  the prompt and held nowhere else, and it is never echoed into output.

  `init-token` names the control that actually applies. `InitializeToken`
  bounds first initialization with CTAP 2.1 §6.9's post-power-up window and a
  user-presence check, and neither constrains a local operator: the command
  constructs the authenticator, so it opens the window itself, and the presence
  prompt asks the same person who just typed the PIN. The banner says so and
  names the file permissions on the state directory instead — a bound that
  cannot fire must not be reported as one that held. The presence handler is
  still explicit and interactive rather than an auto-grant, so a denial refuses.

  The offline-device plumbing both verbs share with `provision-attestation`
  moved to `xkey/cmd/xkey/cmd/fido2_offline_device.go`: the daemon-liveness
  refusal (`ErrFIDO2DaemonRunning`, `ErrFIDO2DaemonCheckFailed`, renamed from
  their `ErrAttestProvision*` spellings because the probe is not
  provisioning-specific) and the authenticator construction. Verified by
  `make test-xkey`; ten new tests drive the real CLI end to end, and the
  mutation checks confirm each is non-vacuous — removing the establishment call
  reddens six, removing the already-initialized refusal reddens exactly its
  own, and substituting an auto-grant presence handler reddens the denial test.
  Documented in `xkey/docs/virtual-authenticator/`. (#233)

### Fixed

- **`CHANGELOG.md` is one document again, and every release's notes are now
  bounded by the right heading.** The file held two concatenated changelog
  documents — the go-trusted-ca history imported at the 2026-04-16 merge kept
  its own `# Changelog` H1, "Keep a Changelog" header block and
  `## [Unreleased]` — so `## [Unreleased]` matched twice and every tool that
  splices on it picked a different occurrence. `make release` extracts a
  version's notes as everything between its heading and the next line
  beginning `## [`, and because that `sed` range *restarts*, the duplicate
  `## [0.1.0-alpha]` heading meant `v0.1.0-alpha` published 141 entries: its
  own 97 plus 44 belonging to go-trusted-ca. It now publishes 97.
  The imported sections are retained verbatim under
  `## [go-trusted-ca] - merged 2026-04-16` with their headings demoted one
  level, so they bound the oldest go-xkms release instead of being swept into
  it and can never be read as a go-xkms version. The duplicate header block is
  gone, the surviving one cites Keep a Changelog 1.1.0, and the colliding
  `[0.1.0-alpha]:` link definition is now an inline link. All 734 entries keep
  the exact heading path they had; `scripts/changelog-assemble.sh` now refuses
  a file that does not carry exactly one `## [Unreleased]` heading (#356).
- **Compliance-gate comments no longer promise a development-mode opt-in that does not exist**: The `Config.ComplianceGaps` doc comment, the cluster CA key-protection and `ca_key_protection: "none"` comments in `pkg/config/config.go`, and the `ACMEAuditConfig` comment in `pkg/config/acme.go` all said the daemon refuses an insecure start "unless the operator explicitly opts into development mode". No such opt-in exists: `cmd/xkmsd` refuses to start and to reload on any reported gap, with no flag, environment variable, or build tag that relaxes it (the `--insecure` / `XKMS_INSECURE` override was removed with the v0.3.0-alpha secure-by-default work and the daemon has said "there is no override" since). A documented escape hatch that is not there sends an operator looking for a switch and then concluding the gate is broken. The comments now state the actual behaviour, and `TestComplianceGate_NoDevelopmentBypass` pins it in the three places an opt-in could be introduced — package comments, environment variables, and `Config` field names — so the wording cannot drift back without the code changing with it. Files: `pkg/config/config.go`, `pkg/config/acme.go`, `pkg/config/acme_audit_test.go`, `pkg/config/config_test.go`, `pkg/config/compliance_gate_bypass_test.go`. Verified with `make test-config`; each of the three pinned surfaces was mutated in turn (stale comment restored, an `XKMS_INSECURE` early return, a `DevMode` field) and the test went red for each. The same sweep rewrote every operator-facing reference to the removed `--insecure` / `XKMS_INSECURE` override in `docs/` (acme audit, rbac, auth bootstrap and layering, configuration/auth, cluster, seal, pkcs11 mechanisms) and `examples/config.example.yaml`, the `pkg/server` cluster CA and `pkg/trust/clusterca` comments that called the library's `AllowInsecure` field a development mode, and four test doc comments in `pkg/server`, `pkg/xkms`, and `pkg/tpm2/store` that repeated the claim. The two integration compose files that still said they opt into "the sanctioned development escape hatch" were corrected as well: `test/integration/cluster/docker-compose.yml` mounts a `config.node.yaml` that passes the gate on its own, and `test/integration/bootstrap/docker-compose.yml` now records that its generated config (auth disabled, no CA) is refused by the gate and needs an authenticator and a CA before the suite can start the daemon. Fixes #389.
- **The `extension`, `trust` and `auth` command groups resolved
  `~/.xkey/data/<feature>` by hand, so under `XKEY_HOME`, portable mode or
  `XKEY_DATA_DIR` they read and wrote a different location than the GUI,
  the wizard and every other CLI group** (#381, split from #295). Each
  group built its path from `os.UserHomeDir()` with no override at all
  (trust honoured only `trust.store_path`); the segment was correct on a
  default install and silently wrong everywhere else. The browser
  launcher carried a second spelling of the trust store path, and the
  `agent` and `backup` groups kept private `~/.xkey/data` fallbacks
  beside the root-resolved home — `agent` even fell back to a temporary
  directory when the home was unresolvable.

  All of them now delegate to the one CLI chain from #295
  (`xkey/cmd/xkey/cmd/datadir.go`) through two new helpers,
  `featureDataDir` / `featureDataDirExisting`, which return
  `<dataDir>/<feature>` so a group spells only its feature segment:
  `extension host` resolves creating and remains the only extension
  command that creates the pairing directory, while `unpair` and
  `pair-status` resolve non-creating and fail with a typed error (new
  `ErrExtensionPairStatusFailed`) instead of rendering an unresolvable
  home as "Not paired"; `trustStoreDir` is the single trust-store
  resolver shared by `openTrustStore` and `browser launch`;
  `authStoragePath` drops the `data/` prefix from its constant; and
  `agentDataDir`/`agentStoreDir`/`agentCertDir`/`agentStateFile` return an
  error rather than a temporary directory. **Deliberate behaviour
  change:** these groups now honour `XKEY_HOME`, the portable
  `.xkey-home` marker, `XKEY_DATA_DIR` and the `data_dir` config key
  exactly as `pin` and `barrier` do; a device that had been relying on
  the hand-built default while running under one of those overrides will
  now address the overridden location. Verified by per-group truth-table
  tests (flag-less chain: `XKEY_DATA_DIR` > `data_dir` > `XKEY_HOME` >
  `~/.xkey/data`), read-side tests proving `pair-status`/`unpair` create
  nothing and read a pairing placed under `XKEY_DATA_DIR` or `XKEY_HOME`,
  and a grep gate (`TestNoAdHocDataDirLiterals`) that scans the command
  sources and fails on any hand-spelled data-directory literal outside
  `datadir.go`; restoring the old `auth` and `extension` literals turns
  the gate and the truth tables red.
- **The DNS-01 provider unit tests no longer query the internet, so their
  result depends on the code rather than on the runner's network** (#418).
  `pkg/acme/challenges/dns-01/providers/{util_coverage_test,propagation_test}.go`.
  `TestDNSQueryNoNameserversResponded` asserted that a query to `192.0.2.1`
  (RFC 5737 documentation space) fails — an assertion about the network, not
  about `DNSQuery`: anything that answers or synthesizes a reply, as the
  runner's network did on PR #414, turns "no nameserver responded" into a
  successful query and fails the test while the code is correct. Five tests in
  the package queried `8.8.8.8`/`8.8.4.4` from the unit suite, four of them
  discarding their own error (`_ = err`) and so asserting nothing while still
  blocking on a live lookup, and a sixth asserted on the host's
  `/etc/resolv.conf`. Every one now runs against a local `miekg/dns` server on
  `127.0.0.1:0` — the `testDNSServer` the package already had, extended with a
  silent mode, A/CNAME records, empty-NOERROR answers, a helper for a loopback
  address with nothing bound to it, and a UDP-truncating server paired with a
  TCP server on one port — and asserts the response instead of discarding it,
  so the UDP-to-TCP fallback, the nameserver-fallthrough loop, CNAME chasing,
  CNAME loop detection and the default-port rule are covered for the first
  time. The whole package now passes in a loopback-only network namespace, and
  with a resolver answering `192.0.2.1:53` inside that namespace — which
  reproduces the CI failure exactly against the old tests
  (`util_coverage_test.go:219`, "An error is expected but got nil"). Mutating
  `DNSQuery` to return a nil error on nameserver exhaustion, to drop the TCP
  fallback, or to stop appending the default port each turns the matching test
  red. New `make test-dns01` target.
- **`release-alpha.sh --dry-run` no longer assembles the changelog against the
  real tree**: a rehearsal folded `.changelog/unreleased/*.md` into the real
  `CHANGELOG.md`, deleted every entry file it spliced, staged both, and then
  printed `release-alpha: nothing was changed` — so the command an operator
  runs *because* it is safe was the one that consumed the release notes, and
  the real cut that followed died on its own clean-tree precondition. The
  changelog assembly now runs where the pin rewrite always did: in a
  `mktemp -d` copy of `VERSION`, the four `go.mod` files, `CHANGELOG.md` and
  `.changelog/unreleased`, so a dry run leaves the working tree byte-identical
  and the index empty however it exits, while still previewing the assembled
  `## [X.Y.Z-alpha]` section in the diff and naming each entry a real cut would
  consume. `scripts/changelog-assemble.sh` grew the `--root DIR` option that
  makes this expressible — assembly is destructive, so a caller must be able to
  point it at a copy. The pin set is now validated before anything is written,
  so a tree that will be refused is refused with its entries intact. Relatedly,
  a run that dies at the tag-signing check now names the *release commit* as
  well as the tags in its cleanup hint (`git tag -d ... && git reset --hard
  <base>`): the commit is created before the tags are signed, so the tag-only
  hint left the operator standing on an unsigned `chore(release)` commit, to
  discover it at the push where `main` enforces signed commits. Verified by an
  end-to-end case in `test/scripts/release-alpha.test.sh` that asserts a
  before/after manifest of `.changelog/` and `CHANGELOG.md` is identical across
  a `--dry-run`, and that the run issues no git write subcommand at all. The
  irony is noted: the release-notes tooling ate the release notes, and this
  entry is one of the files a dry run would have deleted. Fixes #415, #416.
- **A FIPS build now serves a bootstrap handshake instead of binding no
  listener at all.** #296 brought go-truststrap to `v0.4.0-alpha` and re-exported
  the approved suite (`SuiteP256AESGCM` / `TSBOOT1_P256_AESGCM_SHA256`) plus
  `EnsureSuiteAvailable` from `pkg/trust/bootstrap`, but nothing consumed them:
  `pkg/server` still imported `noiseproto` directly and loaded a Noise_NK static
  key unconditionally. Noise_NK mandates X25519, which SP 800-56A Rev. 3 does not
  approve, so in a FIPS build `loadNoiseStaticKey` failed and
  `startNoiseBootstrap` logged the error and returned — no listener on the port,
  no refused handshake, nothing for an operator to see but a connection timeout
  on every client. The approved suite was available in the same binary and needed
  only a key.

  **Measured before the change**, in `pkg/server`: built `-tags fips`,
  `loadNoiseStaticKey` returns `noise: X25519 is unavailable in FIPS build`;
  built `GOFIPS140=v1.0.0` with `GODEBUG=fips140=only` — the mode
  `.github/workflows/release.yml` actually ships, which passes no `fips` tag —
  it returns `noise: invalid key size: crypto/ecdh: use of X25519 is not allowed
  in FIPS 140-only mode`. `p256proto.GenerateStaticKey()` succeeded in both. The
  two mechanisms produce different errors and the same answer, which is why
  availability is derived by attempting the operation rather than by a FIPS
  predicate.

  The listener now resolves which suites the binary can run **while it is being
  configured**, loads a static key for each, and passes both to
  `noiseboot.ServerConfig`, which dispatches per connection on the suite byte in
  the client's first frame (go-trusted-platform#209's acceptance criterion). A
  suite the build cannot run is skipped; a suite that is configured but whose key
  will not load fails the whole listener rather than silently downgrading to the
  other one; a build that can run neither fails with the new typed
  `*server.ErrNoBootstrapSuite`, which names both rejection reasons and unwraps
  to `bootstrap.ErrSuiteUnavailable`.

  New configuration under `bootstrap.noise`: `p256_static_key_file` and
  `p256_static_key_hex`, alongside the existing Noise pair. New CLI verbs
  `xkmsctl bootstrap noise generate-p256-key` and `show-p256-key`, reusing the
  Noise verbs' file handling (mode 0600, refuses to overwrite, cleans up a
  partial write). Both keys are claimed, destroyed and retained together on
  shutdown under the rule the Noise key already had — only a confirmed drain
  permits destroying protected pages a handshake may still alias — and the
  incomplete-shutdown accounting now counts both.

  Files: `pkg/server/bootstrap_suite.go` (new), `pkg/server/server.go`,
  `pkg/server/errors.go`, `pkg/config/config.go`,
  `cmd/xkmsctl/bootstrap_p256.go` (new), `cmd/xkmsctl/bootstrap.go`; docs in
  `docs/trust-bootstrap/` (all five files); `Makefile` gains `test-server`,
  `test-server-fips` and `test-config`.

  Verified by `pkg/server/bootstrap_suite_test.go`, which runs under **both**
  sets of build tags and asserts the same invariants in each: the approved suite
  is always offered, the Noise key is loaded exactly when the build can run
  Noise, and a real `noiseboot.Client` completes a P-256 handshake against the
  listener and receives the CA bundle — an executed handshake, not a compile
  check. `make test-server-fips` is the lane that compiles go-truststrap's
  refusal; it did not exist before, so the FIPS half of this code had never been
  built by any target. Mutation-checked three ways, each turning its tests red:
  disabling the P-256 arm reproduces the exact pre-fix "no handshake suite"
  failure under `-tags fips`; letting a broken configured key fall through
  defeats the silent-downgrade guard; removing `P256StaticKey` from the listener
  config leaves a FIPS build with no server published.

  Four pre-existing `loadNoiseStaticKey` tests and the `newMinimalServer` helper
  were corrected rather than skipped: the helper left `s.ctx` nil, which no
  `New()` can produce, so a subject that ran far enough to reach a shutdown-race
  check paniced instead of failing its own assertion; the four Noise tests now
  assert the build's actual contract (the loader must refuse and return no key)
  instead of presuming the suite exists.

  Also fixed, in the same feature and the same defect class:
  `pkg/trust/bootstrap`'s `TestReExportsCompose` called `GenerateNoiseStaticKey`
  and failed the test on error, so the package was **red under `-tags fips` on
  `main`** before this branch (measured at 73ff6280) — nothing ran it that way,
  because no target passed the tag. It now asserts the refusal in a build that
  cannot run Noise, and composes the re-exports in one that can.

  **Not addressed here:** the bootstrap *client*. `pkg/trust/bootstrap`'s
  `fetchNoise` goes through `truststrap.NewNoiseBootstrapper`, whose
  `truststrap.NoiseConfig` carries no suite or P-256 field, so a FIPS client
  still cannot offer the approved suite through `Fetch`. The lower-level
  `noiseboot.ClientConfig` does support it; adopting it means replacing the
  high-level facade in a live path, which is an architectural call, not a bug
  fix. Tracked upstream as go-truststrap#44. Refs #269.
- **The `logins` integration harness could not start its virtual
  authenticator: it still exec'd `--auto-uv`, a flag removed from the xkey
  CLI** (#409). `test/integration/logins/fido2_test.go` ran
  `xkey fido2 --require-touch=false --auto-uv --pin=false`; #365 removed
  `--auto-uv`, so Cobra rejected the unknown flag and every fido2 leg of the
  suite was dark. No CI job noticed, because the suite runs only inside the
  devcontainer.

  Nothing replaces the flag, because nothing in this ceremony needs it. The
  relying party's `user_verification` defaults to `preferred`, so the xkey
  client sets `options.uv=false` (`webauthn_ceremony.go`) and the
  authenticator's `deriveRPUVPolicy` reads the request as `discouraged`; the
  server applies no UV check of its own. What CTAP2 does require is user
  presence, and the harness already supplies it with its `xkey touch` pump.
  A no-PIN ceremony therefore completes and simply carries no UV — which is
  the honest outcome #280 removed `--auto-uv` to get.

  The exec argv moves to `test/integration/logins/argv.go`
  (`VirtualAuthenticatorArgv`). That file carries no build tag on purpose:
  the rest of the package is behind `integration && logins`, so the argv was
  unreachable to every test that runs in CI. Untagged, it is reachable from
  `xkey/cmd/xkey/cmd`, whose new `fido2_harness_test.go` resolves it against
  the real Cobra command tree — the subcommand must resolve to `fido2`, every
  word must be a registered flag, every value must be one the flag accepts,
  and the live flags are restored afterwards so the guard cannot leak state
  into the package's other tests. A flag removed or renamed on the CLI is now
  a red unit test instead of a suite that will not start. The four tests are
  named in CI's existing `require-tests.sh` list for `cmd/xkey/cmd`, the only
  step that runs that package.

  The `doc.go` and `integration-test-logins` Makefile comments no longer
  document the removed flag. `CHANGELOG.md`'s `--auto-uv` mention is the
  entry recording its removal and is left alone; the remaining `.md`
  references belong to the #376 docs sweep.
- **`TestProcessHMACSecretExtensionDecryptionFailure` no longer feeds random
  bytes to a PKCS7 check, so it stops failing about one run in 256** (#417).
  `xkey/pkg/authenticator/ext_hmac_secret_test.go`. The "invalid padding in
  decrypted salts" case built `saltEnc` as raw randomness and relied on it
  decrypting to something PKCS7 rejects; AES-CBC decryption of random
  ciphertext yields random plaintext, which PKCS7 accepts whenever the final
  byte is an `n` in 1..16 whose last `n` bytes all equal `n` — dominated by
  `n = 1`. On those runs the request reached the salt-length check instead and
  failed with `ErrHMACSecretInvalidSaltEnc`, landing on unrelated PRs (#414)
  and reading as their regression. The test now encrypts a chosen plaintext
  under the established shared secret with the protocol-v1 zero IV, so the
  trailing byte — the one unpadding reads as the padding length — is fixed:
  `0x00` is not a legal length and must fail the padding check, while `0x01`
  is legal padding that leaves 47 bytes, neither one salt (32) nor two (64),
  and must fail the length check. That second case is a new subtest for a
  branch previously reached only by accident. Measured over 5120 consecutive
  runs of the test: 20 failures before, 0 after; swapping the two error
  returns in `decryptSalts` turns both subtests red. New `make
  test-authenticator` target.
- **The IAK CN no longer diverges between provisioning and restart: an
  unconfigured CN is empty on both paths instead of becoming
  `"default-device-id"` after a cold-cache rebuild** (#337).
  `pkg/tpm2/key.go`.

  `IAKAttributesFromConfig` — the path provisioning uses — assigns
  `config.IAK.CN` verbatim, but `IAKAttributes`' cold-cache rebuild (every
  fresh process attaching to an already-provisioned TPM) fabricated
  `"default-device-id"` when the configured CN was empty. The same TPM
  therefore described its IAK differently depending on whether the process
  provisioned it or attached to it, and certificate-store lookups keyed on
  the CN missed artifacts written at provisioning time. The fallback occurred
  exactly once in the repository, was documented nowhere, and provisioning
  never produced it — no artifact created by the normal path carries it, so
  removing it changes only the rebuild path's fabricated value. The rebuild
  now assigns `config.IAK.CN` verbatim, exactly as provisioning and the
  IDevID sibling do. No consumer requires a non-empty CN: the certificate
  store keys on whatever CN the attributes carry (consistent again), and
  `pkg/ca`'s `attestationBlobKey` already derives a stable key for an empty
  CN. Verified by `TestIAKAttributes_ColdCacheEmptyCNStaysEmpty`, which
  provisions, clears the cache, rebuilds from the simulator TPM and asserts
  the two paths agree (it fails against the removed fallback), alongside the
  existing configured-CN cold-cache test.

  Nothing about sealing or unsealing changes: `Seal` and `Unseal` default to
  the Platform SRK and the CN `platform-sealing-key`, never to the IAK
  attributes.

  Upgrade note, for a deployment that leaves `iak.cn` unset (no shipped
  configuration sets it): an IAK certificate or attestation blob that a
  *restarted* process wrote was stored under the fabricated
  `"default-device-id"`, while everything the provisioning process wrote was
  stored under the empty CN. The store was already split between the two.
  Both paths now use the provisioning value, so anything written under
  `"default-device-id"` is no longer found and must be re-imported or
  re-published.
- **`CreateIDevID` no longer carries a guard that could set `adminWithPolicy`
  on a key with no `authPolicy`, and now refuses to create one that would**
  (#278). `pkg/tpm2/key.go`, `pkg/tpm2/types.go`, `pkg/tpm2/tpm.go`. With
  `adminWithPolicy` SET the TPM authorizes ADMIN-role commands only through a
  policy session satisfying the object's `authPolicy` and refuses the auth
  value with `TPM_RC_AUTH_TYPE` (TCG TPM 2.0 Library Part 1, section 19.6); an
  empty `authPolicy` is satisfiable by no session, because a session's policy
  digest starts at zero and can never equal a zero-length value. The pair
  therefore closes the ADMIN role — `TPM2_Certify`, which `CreateIDevID`
  itself issues — permanently, and cannot be undone afterwards, since the
  attribute is an input to a primary key's derivation. The guard that set it
  (`idevidAttrs.Password == nil && idevidAttrs.PlatformPolicy`) never ran:
  `CreateIDevID` builds those attributes from `IDevIDAttributesFromConfig`
  alone, which sets `Password` from `types.NewPassword`, and that constructor
  documents that it never returns nil — so **no created key changes and no
  deployed device identity is re-keyed**. Per TCG section 3.10 the attribute
  is mandatory only for applications administering a key by policy alone, and
  the platform policy cannot serve: it is a `PolicyOR` of `PolicyPCR` and
  `PolicyAuthValue` built for USER-role signing and unsealing, carrying no
  `TPM2_PolicyCommandCode` term, without which no session can authorize an
  ADMIN-role command. The dead guard is replaced by `assertAdminAuthorizable`,
  which runs on the selected template before `TPM2_CreatePrimary` and returns
  the new `ErrAdminWithPolicyNoAuthPolicy` rather than minting an
  unadministrable key — so the obvious tightening of the dead predicate now
  fails loudly at provisioning instead of bricking the ADMIN role of every
  device it touches. A stale comment in `Sign` that described the attribute as
  set is corrected. Verified on the TPM simulator: a `platform-policy: true`
  IDevID is read back from its persistent handle with `adminWithPolicy` CLEAR
  and an empty `authPolicy`, and a `TPM2_Certify` against it under password
  auth succeeds, proving the ADMIN role is reachable; reviving a live guard
  makes the same test fail with `TPM_RC_AUTH_TYPE`.
- **The xkey PKCS#11 embedded transport now reports an exported key's
  algorithm family through the one canonical resolution instead of a private
  formatter** (#402, split from #336). `xkey/pkg/pkcs11`'s `getAlgorithmString`
  was the fourth copy of the family question #336 reduced to one method, and
  the last one outside the root module. It was kept out of #336's scope on the
  possibility that it was a PKCS#11-edge mapping whose spellings a consumer
  depended on; it is not. Nothing at that edge reads the field — the module's
  only consumer of the response (`pkg/pkcs11/module/module.go`
  `secretKeyValue`) takes `KeyMaterial` and ignores `KeyType`, and the value is
  never compared against a `CKK_*` or any other constant — while the
  daemon-side producer of the same wire field (`pkg/xkms/servicer_key.go`)
  answers with the key's symmetric algorithm, with neither the `"unknown"`
  default nor the `KeyTypeSecret` gate the xkey copy carried. Those two
  branches were unreachable at the one call site anyway: a backend releases raw
  material only for a single-family symmetric key, refusing a descriptor that
  names two families (#158) and refusing anything asymmetric outright. So the
  formatter is deleted and `ExportKeyMaterial` calls
  `KeyAttributes.AlgorithmString()`, whose agreement with `ID()` is already
  pinned in `pkg/types`. The one reachable output is unchanged; the divergence
  that could have reappeared is gone. `xkey/pkg/pkcs11/service.go`,
  `xkey/pkg/pkcs11/service_exportkeymaterial_test.go`. The new tests assert the
  reported family against a literal and against the family segment of the key's
  own `ID()`, so a transport that grows a private opinion again fails rather
  than agreeing with itself, and cover the refusals that produce no family at
  all.

## [0.10.0-alpha] - 2026-09-06

### Changed

- **Published to correct the version of `v0.9.5-alpha`, which carries added
  API and was cut as a PATCH.** `v0.9.5-alpha` exports nine new symbols from
  the published `sdk/go` module (#379), adds the configuration key
  `cluster.raft_enrollment.advertise_noise_host` (#406) and adds the
  `xkey fido2 provision-attestation` command (#231). Under
  release-versioning.md §1 for pre-1.0 modules, added API moves MINOR, so the
  version that ships those three is `0.10.0-alpha`. **This release contains no
  functional change over `v0.9.5-alpha`** — no code differs between the two
  tags beyond `VERSION`, the nine reciprocal `go.mod` pins and this file.
  `v0.9.5-alpha` remains published and immutable; consumers should pin
  `v0.10.0-alpha`, which is what its contents should have been called.


## [0.9.5-alpha] - 2026-09-06

### Security

- **Two SO policy controls that were recorded but never enforced now fire: the `enterprise` attestation override requires the RP's entitlement, and a tampered policy locks user-mode operations.** #216 D reported that `RPPolicy.AttestationOverride` — a WebAuthn conveyance *preference* — was written into the attestation *statement format* slot, so `direct`, `indirect` and `enterprise` all produced `fmt: none`. The vocabulary translation itself is already on main from 03c9c9ab (#215): `resolveAttestationOverride` maps the preference to the configured format and refuses with `ErrAttestationOverrideUnsupported` rather than degrading. What this adds is the one preference 03c9c9ab left fail-open: `enterprise` resolved to the configured format for any RP, so an SO mandate for enterprise attestation was honoured with the ordinary statement for an RP that was never entitled to it. `resolveAttestationOverride` now takes the policy and applies the entitlement the request path already demands — `enable-enterprise-attestation` on the authenticator **and** `Enterprise` on the RP's policy — refusing with the new typed `ErrEnterpriseAttestationNotEntitled` (`CTAP2_ERR_OPERATION_DENIED`), checked before the configured format so the refusal names the real reason. #216 E1: `Authenticator.TamperDetected` had one writer and no reader, so a device booting with a policy whose HMAC failed served makeCredential, getAssertion and credential management normally while its doc comment promised a lock. One predicate, `requirePolicyIntegrity`, now refuses every user-mode CTAP command in `ProcessCBORWithContext` before the request is decoded, and the Go API `MakeCredential` and `GetAssertion` that bypass the dispatch, with the new typed `ErrPolicyTamperLocked` (`CTAP2_ERR_INTEGRITY_FAILURE`). `getInfo` and `selection` stay answerable so a locked device remains discoverable, and `getInfo` reports the state under the vendor option `policyTamperLocked: true`, present only while locked. **What sets the flag:** the authenticator opens with a policy integrity provider and the stored HMAC tag does not verify over the current signed field set; a schema change from a routine upgrade does not set it. **Cost of a false positive:** the device serves no user until the Security Officer recovers it; credentials and PINs are untouched and no reflash or reset is needed. **Recovery:** the SO re-signs the policy over the device's actual configuration (`PolicyManager().Sign` on the current state, persist it) and re-opens the authenticator, after which verification passes and user-mode commands are served again. The flag is never cleared at runtime. Files: `xkey/pkg/authenticator/authenticator.go`, `cmd_makecredential.go`, `cmd_getassertion.go`, `cmd_getinfo.go`, `errors.go`; docs in `xkey/docs/fido2/authenticator-security.md`, `xkey/docs/fido2/authenticator-api.md`, `xkey/docs/configuration/enterprise-mode.md`. Verified by `so_policy_controls_test.go`: `direct`/`indirect` produce a packed statement, an entitled `enterprise` override produces one, each half of the entitlement removed is refused with the typed error, every user-mode command and both Go API paths refuse while locked, discovery still answers and reports the lock, and an SO re-sign clears the flag, drops the getInfo option and restores registration over CTAP. Mutation-checked: removing the entitlement check, the dispatch gate, the Go API gates, the getInfo option, or the re-sign's tag update each turns its test red. Addresses #216 D (enterprise remainder) and E1; E2 landed with 03c9c9ab, E3 is recorded as a constant that cannot mismatch, and F was retracted as dead schema.
- **The HID no-credentials deferral answer now respects credProtect.** `HasMatchingCredentials`, which decides whether a getAssertion is answered at once or deferred to another authenticator, reported that a credential existed for an RP regardless of its protection level. That decision is observable on the HID interface, so any process that could reach it learned whether the device held a credential for `rp.example` — the existence oracle #217 closed for `excludeList` and #215 closed for assertions, surviving on a third path. The heuristic now establishes the request's user-verification state with the same non-consuming pinUvAuthToken check getAssertion uses and applies the CTAP 2.1 §12.1 rules through one shared filter (`usableCredentialsForAssertion`): a level-3 credential is invisible without user verification and a level-2 credential is invisible to an RP enumeration without it. The indexed storage backend keeps the discoverable fast path at zero storage I/O by carrying each credential's protection level in its in-memory index — recorded on every `Store`, rewritten on update, rebuilt from stored credentials on load — and `CredentialIndexer.HasDiscoverableForRP` now takes the user-verification state. An index entry whose level was never recorded is treated as level 3, so a missing level fails closed. **Behaviour change for multi-authenticator deployments:** a request this authenticator could only answer with user verification is now deferred exactly as if it held nothing; a platform that wants the protected credential obtains a pinUvAuthToken first, which already commits it to this authenticator and ends deferral. Files: `xkey/pkg/authenticator/authenticator.go`, `cmd_getassertion.go`, `config.go`, `storage_backend.go`; docs in `xkey/docs/fido2/authenticator-security.md`. Verified by `credprotect_deferral_test.go`, which runs every scenario on both the scan and the indexed path and fails on the previous code, plus index tests proving the level survives a rebuild and that an unrecorded level is protected. Closes #261.
- **`xkey fido2 --set-pin` seeded the daemon's PIN through
  `SetPINForTesting`, a helper documented as not-for-production, which wrote
  the PIN hash straight into state** (#377). `xkey/pkg/authenticator/
  cmd_clientpin.go`, `errors.go`, `xkey/cmd/xkey/cmd/fido2.go`.

  Measured against the CTAP `setPIN` path (`handleSetPIN`), the helper
  skipped four things: the "no PIN currently set" precondition, so a restart
  with `--set-pin` against a file or barrier store silently **replaced** the
  stored PIN; the retry-counter reset became a way to clear a partially
  exhausted counter without proving the PIN; the outstanding-`pinUvAuthToken`
  invalidation that #322 added to the real path (a token minted against
  built-in UV before any PIN existed stayed usable); and the typed
  `ErrStorageError` on persistence failure. Only the minimum-length check was
  shared. The wire-level `pinUvAuthParam` proof was also skipped, and that one
  is legitimate for an in-process caller — it exists to authenticate a remote
  platform.

  A first PIN now has one establishment path, `establishPINLocked`: the CTAP
  `setPIN` subcommand reaches it after its wire proof, and the new production
  API `Authenticator.SetInitialPIN` reaches it directly. Both enforce the
  minimum length, reset the retry counter, invalidate and wipe any outstanding
  `pinUvAuthToken` before persisting, and report persistence failure as
  `ErrStorageError` with the cause joined. `SetInitialPIN` refuses an
  authenticator that already has a PIN with the typed `ErrPINAlreadySet` — an
  existing PIN is replaced only by `changePIN`, which proves the current one.
  The daemon's `--set-pin` seeding calls `SetInitialPIN` and surfaces the
  already-set case as the distinct `ErrFIDO2PINAlreadySet`, telling the
  operator to drop the flag or change the PIN through a FIDO2 client, rather
  than starting with a rewritten PIN. `SetPINForTesting` is deleted; every
  test used it on a fresh authenticator, which is exactly `SetInitialPIN`'s
  contract, so the tests migrated to the production API.

  Verified by tests that fail with the defect re-introduced: removing the
  precondition turns the refused-when-set test and the daemon's file-store
  restart test red; dropping the shared invalidation turns the
  `SetInitialPIN` token test **and** #322's wire `setPIN` token test red,
  which is what proves the path is shared rather than duplicated. Also
  covered: establishment persists and the real `getPinUvAuthToken` ceremony
  accepts the PIN; a policy-violating PIN is refused and leaves no state or
  token damage; a storage failure is typed; the daemon seeds on a first start,
  refuses a short PIN, and comes back up with the persisted PIN when
  `--set-pin` is omitted.
- **A partial RP policy write silently cleared the SO's UV, attestation,
  enterprise and block settings, and concurrent policy writers silently lost
  updates** (#321, #326). `xkey/pkg/authenticator/rp_policy.go`,
  `rp_policy_update.go` (new), `rp_policy_entity.go`,
  `dao_rp_policy_store.go`, `rp_policy_memory.go`, `rp_policy_backend.go`,
  `cmd_config.go`, `xkey/cmd/xkey/cmd/fido2_policy.go`.

  `RPPolicyStore.SetPolicy` replaces the whole record, and both partial-field
  callers — the CTAP `SetRPPolicy` vendor command and `xkey fido2 policy set`
  — built the record from only the fields the request carried. Changing one
  setting cleared every other one to its **permissive** zero value:
  `UVOverride: "required"` reverted to "use the RP's request", the forced
  attestation override vanished, and an RP block was lifted by any write that
  omitted `blocked`. The wire could always express presence (the CBOR map's
  key set, cobra's `Changed`); the domain type discarded it.

  Presence now has a home of its own: `RPPolicyUpdate` carries a pointer per
  field (nil = leave stored value unchanged, pointer-to-zero = explicit
  clear), and `RPPolicyStore.UpdatePolicy` applies it onto the freshly-read
  stored record in every store implementation. The stored `RPPolicy` and
  every enforcement read stay plain, non-pointer values — no new nil checks
  on the block-enforcement path. Both partial-field callers now build an
  `RPPolicyUpdate` from the presence they observe while decoding; `SetPolicy`
  remains the full-record replace used by migration and the GUI's
  fully-populated policy form.

  The read-modify-write is also no longer a racy Get-then-Save (#326):
  `RPPolicyEntity` implements the DAO's `Versioned` contract, every save goes
  through `SaveWithCondition` guarded on the observed version with a bounded
  retry, and a writer that loses every retry receives the typed
  `ErrRPPolicyConflict` instead of reporting success over a lost update.
  Because the pinned SDK documents `SaveWithCondition` as a read followed by
  a write rather than an atomic CAS, the store additionally serializes its
  own writers on a mutex — the version condition catches writers using a
  separate store instance over the same records.

  Verified by regression tests that fail with the defect re-introduced: a
  two-key CBOR vendor request and a `--blocked`-only CLI invocation against a
  populated RP preserve every other field; blocking an RP survives unrelated
  writes; an explicit `blocked=false` still unblocks; two concurrent
  updaters carrying different fields both land under `-race` (100
  iterations); and a writer that keeps losing the version race gets
  `ErrRPPolicyConflict` after exactly the bounded number of re-reads.
- **`XKMSService.ImportKey` dropped the request's `TenantID`, so a tenant's
  key import bypassed tenant isolation and landed in the untenanted
  namespace** (#163; the read-path half of #162 for symmetric keys).
  `pkg/xkms/backend_importexport.go` (new), `pkg/xkms/backend_tenant.go`,
  `pkg/xkms/servicer_key.go`, `pkg/xkms/service.go`,
  `pkg/xkms/piv_keygen_backend.go`, `pkg/keyprovider/symmetric/metadata.go`,
  `pkg/keyprovider/symmetric/backend.go`.

  The service resolved a `TenantScopedBackend` from `req.TenantID` and then
  discarded it one line later: the import/export capability was only reachable
  through `KeyProvider()`, which returns the *base* provider and drops the
  wrapper — and with it `scopeAttrs`, the only thing that stamps the tenant.
  The one operation that takes key material from outside was the one the
  tenant wrapper did not cover: a tenant's import stored under the untenanted
  identifier (where it could collide with, and before #165 silently destroy,
  an untenanted key of the same name), and was invisible to the importing
  tenant's own `ListKeys`.

  The fix closes the seam once for every transport rather than per-caller.
  `TenantScopedBackend` now offers the capability itself — a new
  `ImportExporter` interface carrying the operational surface of
  `backend.ImportExportBackend` (the wrapper cannot satisfy the full
  interface: `Backend.RotateKey` and `types.KeyProvider.RotateKey` share a
  name with different signatures) — scoping every attribute set exactly as
  `GetKey`/`GenerateRSA` always have, and refusing with the existing typed
  `ErrBackendUnsupported`/`ErrImportExportNotSupported` when its base lacks
  the capability. All eighteen `KeyProvider().(backend.ImportExportBackend)`
  unwrap sites in `servicer_key.go`, `service.go` and `piv_keygen_backend.go`
  now resolve through one `importExportFor` helper that prefers the wrapper's
  own implementation; unscoped backends resolve through their provider
  exactly as before, so untenanted callers are byte-for-byte unchanged.

  The metadata half: an imported symmetric key's tenant was still lost on the
  way out, because the symmetric provider's metadata record carried no
  `TenantID`/`Partition` and its `ListKeys` reconstructs them from identifier
  segment count — which cannot tell `acme:software:secret:k:aes256-gcm` (a
  tenant) from a partition, and read the tenant back as a partition. The
  record gains both fields at schema version 3 and `ListKeys` prefers a v3
  record over the segment guess, mirroring what the PKCS#8 provider's record
  has done since its v1 (the asymmetric leg of #162 was fixed by ff630179;
  this change makes the tenant actually reach that record on import).

  Verified by tenant/untenanted same-name collision, tenant-visibility,
  asymmetric metadata round-trip, unsupported-provider and legacy-record
  tests in `pkg/xkms` and `pkg/keyprovider/symmetric`; each fix test was
  mutation-checked by re-introducing the unwrap, dropping the asymmetric
  metadata write, and ignoring the v3 record — every mutation turns the
  matching test red.

### Added

- **`cluster.raft_enrollment.advertise_noise_host` — the bind host for the
  Noise NK enrollment listener the first node of a multi-node cluster starts**
  (#406). go-qrdb#167 made `AdvertiseOptions.NoiseHost` required: that listener
  is the one socket a joining node reaches before it holds any credential, so
  clusterenroll refuses to choose a bind host, and a node contained to one
  interface must not have it quietly opened on every interface. xkms never set
  it, so multi-node first-node startup failed on the bump. The new setting is a
  bind host in the same sense as `server.host` and defaults to it; it is
  resolved once, by `Server.raftNoiseBindHost`, and reaches both the plain
  cluster path and the ACME enrollment path. It is deliberately not
  `cluster.advertise_host`, which is the address clients dial and is not a bind
  address.
- **`xkey fido2 provision-attestation` turns on the device attestation
  identity, which was fully implemented at the CTAP layer with no path from
  an operator to it** (#231). The `replaceAttestKey` and `setAttestCert`
  vendor commands had no caller outside the authenticator package, so every
  device registered with `fmt: "none"` no matter how the subsystem was
  configured. The command drives the exchange as real CTAP2
  `authenticatorConfig` CBOR: SO PIN unlock → CA connect → CSR from the
  device → `SignCSR` at the xkms enterprise CA → chain install → read-back
  verification. The private key never leaves the device, a CA failure never
  touches it (the connect happens before key generation), re-provisioning is
  refused without `--rotate`, and the read-back proves the stored leaf
  certifies the key the device still holds — resolved through
  `KeyManager.AttestationSigner()`, since the persisted state carries only
  AES-GCM wrapped key copies. `xkey/cmd/xkey/cmd/fido2_provision_attestation.go`,
  `xkey/docs/configuration/README.md`. Verified by end-to-end tests driving
  the real authenticator and an in-process CA, including the CA-unreachable,
  CA-refuses, mis-issuance, rotation and locked/uninitialized-token paths.

- **The client-side http-01 challenge responder is now an SDK surface**
  (#379). `pkg/acme/challenges/http-01` implemented both halves of the
  challenge, but `sdk/go` exported only the ACME *server* half
  (`ACMEVerifyHTTP01`), so a consumer reaching go-xkms exclusively through its
  SDK — as go-quicbaas and go-trusted-platform are required to — could not
  answer an http-01 challenge at all.

  `sdk/go/acme` now exports `NewHTTP01Responder` and `HTTP01Responder`
  alongside `HTTP01ResponderConfig` and the typed errors
  `HTTP01ResponderConfigError`, `HTTP01ResponderBindError` and
  `HTTP01ResponderShutdownError`. The responder is an instance rather than
  process-global state, which fixes three defects the raw functions would have
  carried into every consumer had they simply been aliased:

  - **The bind is eager and its failure is returned.** `Setup` ran `net.Listen`
    in a spawned goroutine and sent the error to a package-level log handler, so
    a caller lacking `CAP_NET_BIND_SERVICE` for port 80, or colliding with an
    existing listener, saw setup succeed and learned of it only as a generic
    "authorization status is not valid". `NewHTTP01Responder` returns
    `HTTP01ResponderBindError`, which unwraps to the underlying `net` error.
  - **There is no readiness race.** `Setup` returned before the listener bound,
    while the ACME client accepts the challenge immediately after provisioning
    it, so validation could be requested before anything was listening.
    `NewHTTP01Responder` returns only once the responder is accepting
    connections.
  - **Concurrent orders are safe.** `server` and `shutdownOnce` were package
    variables, so a second order replaced the first order's listener and the
    first `Shutdown` then stopped the second order's. Each responder now owns
    its listener.

  `Addr()` reports the bound address and `Done()`/`Err()` report the serve
  loop's fate. `Shutdown(ctx)` stops the responder gracefully and `Close()`
  stops it immediately; once stopped, either call is a no-op returning nil, so
  `defer responder.Close()` stays correct after an explicit `Shutdown`, while a
  `Shutdown` that misses its deadline leaves the responder running so `Close`
  can force the teardown. Documented in `docs/acme/challenges.md` and
  `docs/acme/sdk/`.

### Changed

- **Changelog entries are now per-PR files under `.changelog/unreleased/`,
  assembled into `CHANGELOG.md` when a release is cut** (#354). Editing the
  top of `[Unreleased]` made every merge conflict with every other open PR —
  measured at one forced rebase plus a full CI cycle per open PR per merge —
  and let entries land in a released section that did not ship them (#361's
  failure class, which occurred twice). A PR now adds one
  `<section>-<slug>.md` file; `scripts/changelog-assemble.sh` (called by
  `release-alpha.sh` at cut time) groups the files under the new version
  heading in fixed section order and deletes them in the same commit. A file
  naming no known section fails the cut loudly rather than dropping the entry.
  `## [Unreleased]` remains in `CHANGELOG.md` and stays empty by convention.
- **go-qrdb pinned to `v0.16.3-alpha`, and every in-tree `transport.RoleClient`
  now implements `ReconcileBuiltInRoles`** (#406). go-qrdb#354 added the method
  to the interface, which is a breaking change for every implementor: go-xkms
  stopped compiling against the current qrdb release, and because
  `pkg/acme/qrdb` is reachable from `sdk/go/acme`, so did every consumer that
  bumped qrdb (go-quicbaas#573). All four modules — root, `sdk/go`, `xkey`,
  `web/desktop` — move to `v0.16.3-alpha` together.

  The method is implemented, not stubbed. `pkg/qrdbrole` holds ONE
  implementation of qrdb's reconciliation semantics over the `RoleClient` seam
  — seed a built-in the tenant does not hold, replace a drifted one's
  permission set, leave a converged one completely alone (zero writes), repair
  Owner when present and never create it, and never touch a custom role — read
  from `qrdbsdk.BuiltInRoles` and `qrdbsdk.AllPermissions` so the definition is
  qrdb's rather than a copy. `pkg/acme/qrdb`'s `memoryRoleClient` and
  `pkg/testutil`'s `QRDBFakeTransport` delegate to it; the three narrow
  handler-test mocks report the verb as unexercised exactly as their sibling
  methods do.

- **`transport.UserNotFoundError` is populated per go-qrdb#343** in the
  in-memory user fakes (#406): `ID` carries the numeric id for an id lookup and
  `Lookup` carries the descriptor for a lookup by username, email or SPKI
  thumbprint, formatted through `transport.UserLookupKey`. The field became a
  `uint64` upstream, so the previous string assignment no longer compiled.

- **The absent-key characterization narrowed to Delete** (#406, #252).
  go-qrdb v0.16.3-alpha fixed `Exists` and `Get` for a key that was never
  written, so `storagetest.Config.AbsentKeyDivergence` — which asserted the
  wrong answer on purpose and was written to fail the day it became right —
  did. Both verbs are now held to the correct answer on every backend, and the
  flag is `AbsentDeleteDivergence`, covering the one verb still divergent.

- **`CompareAndDelete` is available from every embedded constructor**, and the
  characterization that recorded its absence is now a conformance test (#406).
  The `FastStateMachine` gained the guarded-delete opcode (go-qrdb#175), so the
  guarded path answers and nothing falls through to the transaction the
  embedded transport still does not wire. `PutIfAbsent` and `CompareAndSwap`
  are unaffected and remain unavailable (#61, #125). The availability note on
  `Backend.CompareAndDelete` was re-derived by measurement, which is what the
  characterization existed to force.

### Deprecated

- **`http01.Setup` and `http01.Shutdown`** (#379). They keep working and now
  delegate to a single `Responder`, so there is one implementation rather than
  two, and setting up a second responder retires the first instead of leaking
  its listener. New code uses `NewHTTP01Responder`, which the deprecation notes
  point at.

### Fixed

- **The algorithm string the REST, MCP and gRPC transports display now
  resolves the key's family in the same order as `KeyAttributes.ID()`**
  (#336). Presentation-only: `getAlgorithmString` was a pure formatter, could
  not address or route a key, and no production path builds the two-family
  descriptor that would expose the divergence — but it was a third resolution
  order (`SymmetricAlgorithm` before `KeyAlgorithm`, the opposite of `ID()`),
  and #158 exists precisely because contradictory family resolution silently
  picks sides. The three identical per-transport copies are deleted and
  replaced by one canonical `KeyAttributes.AlgorithmString()` in `pkg/types`,
  directly below `ID()` and mirroring its switch arm for arm (X25519, quantum,
  asymmetric, symmetric); as a side effect X25519 and quantum keys now display
  their family instead of an empty string. `pkg/types/types.go`,
  `pkg/api/rest/handlers.go`, `pkg/api/mcp/{handlers,utils}.go`,
  `pkg/api/grpc/service.go`, `docs/key-management/engineering.md`. The two
  tests that pinned the divergent order now compute their expected value from
  `ID()` itself, and a property test in `pkg/types` iterates two-family
  descriptors asserting `AlgorithmString()` agrees with `ID()`'s family, so a
  fourth order cannot reappear silently.
- **The IAK, IDevID and LDevID attribute builders no longer assign a dead
  Endorsement Key template into `TPMAttributes.Template`** (#355).
  `pkg/tpm2/config.go`. `IAKAttributesFromConfig`, `IDevIDAttributesFromConfig`
  and `LDevIDAttributesFromConfig` copied `RSAEKTemplate`/`ECCEKTemplate`
  (Restricted, `SignEncrypt: false`) — plus the platform-policy `AuthPolicy` —
  into a field nothing on those key types' creation paths ever reads:
  `CreateIAK` builds its restricted signing template from scratch and
  `CreateIDevID` selects the dedicated unrestricted IDevID/LDevID template
  constants, while only the EK and SRK creation paths consume
  `TPMAttributes.Template`. No key was ever created from the stale value, but
  the contradiction between descriptor and code is exactly what produced the
  #355 misdiagnosis of restricted, non-signing identity keys — this closes
  that misdiagnosis vector. `EKAttributesFromConfig` keeps its template, which
  `CreateEK` genuinely consumes; function signatures (including the now
  compatibility-only `policyDigest` parameters) and the `PlatformPolicy`
  field are unchanged. Verified by tracing every `TPMAttributes.Template`
  reader in the repository to EK/SRK/seal-path attributes only, by a new
  regression test asserting the three builders leave `Template` as the zero
  `TPMTPublic` (red when the assignment is re-introduced) while the EK builder
  still bakes the policy digest into its template, and by the full `pkg/tpm2`
  simulator suite.
- **The integration harness identified the devcontainer by `/.dockerenv`, so
  any containerised caller — including the Gitea act_runner job container —
  impersonated it and the devcontainer was never started** (#19). That is why
  Integration Tests was red on 39 of 40 CI runs: `run_with_server` skipped the
  start-the-devcontainer branch, built nothing, and `devcontainer-server-wait`
  then probed for the socket inside a devcontainer that did not exist while
  the server was serving perfectly well. Devcontainer identity is now a
  positive marker: `XKMS_DEVCONTAINER=1` is baked into the devcontainer image
  (`.devcontainer/Dockerfile`) and set in its compose environment
  (`.devcontainer/docker-compose.yml`), and all four Makefile probe sites
  (`run_in_devcontainer`, both branches of `run_with_server`,
  `integration-test-xkey-ssh`) test that marker instead of the ambient
  `/.dockerenv` / `$DEVCONTAINER` side effects. Verified by evaluating both
  predicates in all three contexts — host shell, marker-carrying container,
  and a plain container standing in for the act_runner job: the old predicate
  wrongly selects run-in-place inside the plain container, the new one selects
  start-the-devcontainer there and on the host, and run-in-place only when the
  marker is present — plus `make -n` renders and shell syntax checks of every
  changed target. `test/integration/api/testutil.go`'s `isRunningInDocker` is
  untouched: it genuinely asks "am I in any container" (and has no callers).
- **`xkey device enroll-phone` requested certificate profile "idevid", which
  no registry entry matches, so phone enrolment could not issue a certificate
  at all** (#241). `xkey/cmd/xkey/cmd/device_enroll_phone_ca.go`,
  `xkey/cmd/xkey/cmd/ca.go`.

  The string travelled untouched from `enrollmentCertProfile` through
  `SignCSRRequest.Profile` to `ca.Profiles().Get`, which correctly fails
  closed with `ErrProfileNotFound` — there is no fallback profile, so the
  command errored instead of issuing something wrong. The path is behind
  `//go:build ble`, which is why no default build caught it.

  The constant now names the `client` profile. The credential is an LDevID in
  the IEEE 802.1AR sense presented by the phone as a client of the enterprise
  CA, and `client` supplies exactly what that needs: DigitalSignature key
  usage, ClientAuth EKU, finite validity — the device identity travels in the
  CSR subject and the re-attestation cadence in `ValidityDays`. `tcg-idevid`
  was rejected deliberately: it stamps TCG policy OIDs asserting TPM residency
  a phone's Android Keystore key does not have, and models a never-expiring
  manufacturer IDevID where this credential's expiry is the re-attestation
  cadence. `fido2-attestation` certifies an authenticator attestation key, not
  an identity key. Registering a new "idevid" profile would have duplicated
  `client` under a second name.

  The audit of the other profile names `cmd/` hardcodes found one more dead
  one: `xkey ca issue --help` advertised "idevid" as an available profile, so
  a user who followed the help hit the same `ErrProfileNotFound`. The help
  now lists only registered profiles.

  Tests now resolve `enrollmentCertProfile`, every profile `ca issue` help
  advertises, and the `cert request` / `agent` profile defaults against the
  same default registry the CA constructs, so an unregistered profile name in
  this package can never again survive to runtime; a semantics test pins
  DigitalSignature + ClientAuth + CA:false on the phone credential. The
  ble-gated tests are named in the CI gate that runs `cmd/xkey/cmd` under
  `-tags ble`, since that package is otherwise compiled but never run there.
- **`make lint` gave golangci-lint a 10m wall-clock budget that the root
  module exceeds whenever the shared runner is loaded, reddening whichever PR
  is in the queue** (#360; closes #363, the same defect observed on PR #362).
  `--timeout` measures wall clock from process start, so on the oversubscribed
  fleet it measured fleet load rather than linter work: the root module took
  11m57s at load ~30 on 24 cores and was killed at 10m, and run 11456 printed
  "0 issues." before tripping the deadline on the way out. The budget now
  lives once, as `run.timeout: 30m` in `.golangci.yml` — sized to clear the
  worst observed contention with the same headroom `go test -timeout 30m`
  already assumes for Unit Tests in ci.yml — and the hard-coded
  `--timeout=10m` is removed from the root Makefile, along with the
  `--timeout=5m` args that would have kept overriding the config in
  `docker-tests.yml` and `coverage.yml`. Every other invocation site
  (`sdk/go/Makefile`, the ci.yml Lint job via `make lint`) already ran with
  no flag, so the config value is the only bound anywhere; golangci-lint v2
  has no default timeout, and `run.timeout` is a valid key in the schema of
  every pinned version (v2.6.2, v2.7.2, v2.12.2, v2.13.2). The ci.yml Lint
  job gains a `timeout-minutes: 60` backstop so a genuinely hung linter fails
  as a job timeout rather than running to the runner's implicit limit.
  Deliberately not a retry-on-timeout, which would hide a genuine slowdown.
  Verified with `golangci-lint config verify` and a green `make lint` over
  the root, `sdk/go` and `web/desktop` modules.
- **Every `xkey pin` subcommand resolved `~/.xkey` instead of `~/.xkey/data`,
  so it read a phantom empty store and `set-so` could fork the SO PIN
  silently** (#295). `resolvePINDataDir`'s private fallback dropped the
  `data` segment every other subsystem uses, so on a wizard-configured
  device `pin status` reported both PINs unset, `verify` failed against a
  correct PIN, and `set-so` — seeing the phantom store's `soPINSet=false` —
  accepted a new SO PIN without the current one and wrote it beside the
  real record. Worse, `createPINService` ran `MkdirAll` on every path, so a
  read-only `pin status` *created* the empty `~/.xkey/pin/` that made the
  failure invisible.

  The CLI now has ONE data-directory resolution chain,
  `resolveDataDir`/`resolveDataDirExisting`
  (`xkey/cmd/xkey/cmd/datadir.go`): flag > `XKEY_DATA_DIR` > config
  `data_dir` > the xhome data directory — and both the pin and barrier
  groups delegate to it, removing the drifted private copy. Read commands
  (`status`, `verify`, `change-*`, `reset-lockout`) resolve through the new
  non-creating `xhome.ResolveExisting` and open the store with
  `openPINService`, which returns a typed `*PINStoreNotFoundError` instead
  of fabricating a fresh store; only `set-so`/`set-user` may create it.
  `pin status` now renders an absent store as `PIN store: not found`
  (JSON: `store_present: false`) — a fresh install and a misresolved path
  no longer print the same confident "No". Verified by a wizard-layout
  regression test (`TestPINCommands_AddressTheWizardDataDirectory`) proving
  status/verify/set-so all address `~/.xkey/data/pin/`, that a refused
  `set-so` leaves the wizard's SO PIN intact, and that no phantom
  `~/.xkey/pin/` appears; the test fails on the pre-fix resolution.
- **`TestGRPCServer_SocketPermissions` no longer reads the socket mode inside
  the listen→chmod window, where it flaked at 755** (#357). `Start()` creates
  the Unix socket via `net.Listen` and sets the configured mode with a
  separate `os.Chmod`, so the test's poll-for-existence loop could observe the
  socket at the umask default before the chmod ran. The test now polls for the
  condition it asserts — the mode reaching 0640 — and still fails at the
  deadline if the server never sets it (verified by mutation: with the
  `os.Chmod` removed the test goes red at the umask default).
  `pkg/api/unix/grpc_server_test.go`. Verified with 200 consecutive green
  runs. The production-side window (socket briefly world-accessible before
  the chmod) is a separate question recorded in the issue and deliberately
  not changed here.
- **The `test/docker/softhsm` image shipped without the C++ runtime, so
  `libsofthsm2.so` and `softhsm2-util` could not load inside it -- and its
  healthcheck could not detect that** (#227). `test/docker/softhsm/Dockerfile`,
  `docker-compose.yml`, `.devcontainer/docker-compose.yml`.

  SoftHSMv2 is C++, but the runtime stage installed only
  `openssl sqlite-libs p11-kit p11-kit-server` while copying `/usr/local` from
  the builder -- `libstdc++.so.6`/`libgcc_s.so.1` live in the builder's
  `/usr/lib` (pulled by `build-base`) and were never carried across, so every
  load ended in `Error loading shared library libstdc++.so.6` plus ~250
  relocation failures. Latent on every base version (reproduced identically on
  the pre-#177 `alpine:3.22.1`), and invisible because the healthcheck was
  `test -f` on the .so -- a check that cannot fail the way the container was
  broken. The fix adds `libstdc++` and `libgcc` to the runtime `apk add` and
  replaces the healthcheck (Dockerfile and both compose overrides) with
  `softhsm2-util --show-slots`, which links the same runtime and opens the
  token store, so it fails whenever the library would. Verified by building
  the image before and after: `ldd libsofthsm2.so` goes from two
  "Error loading shared library" lines to fully resolved, and
  `softhsm2-util --show-slots` from RC=127 to RC=0 listing slot 0.
  `test/docker/swtpm` was checked for the same gap and does not have it: swtpm
  and libtpms are C, their runtime deps are installed explicitly, and its
  healthcheck (`nc -z` on the command port) exercises the running daemon.
- **`xkmsctl` WebAuthn login and registration could not supply a CTAP2 PIN,
  so neither completed against a PIN-protected authenticator** (#309). The
  identical gap #299 closed for `xkey auth register`/`login`: the fido2 layer
  already carried `WebAuthnRegistrationOptions.PIN` and (since #299)
  `WebAuthnAuthenticationOptions.PIN`, but `xkmsctl user register`,
  `xkmsctl user login` and `xkmsctl admin create` never set either field, and
  offered no way to take a PIN in.

  The three verbs now accept the same three PIN sources, in the same
  precedence order, as the xkey verbs: `--pin-stdin` (preferred — the PIN
  stays out of the process list), the `XKMS_FIDO2_PIN` environment variable,
  then `--pin`. The resolver is re-stated in `cmd/xkmsctl/pin_input.go`
  because `xkmsctl` cannot import the xkey binary's command package; the flag
  names, precedence and empty-PIN semantics mirror xkey's exactly. The PIN is
  resolved before anything reaches the network, an empty `--pin-stdin` is
  rejected as operator input to correct, `CTAP2_ERR_PIN_REQUIRED` with no PIN
  supplied is reported as `ErrWebAuthnPINRequired` naming the sources rather
  than as a device fault, and a wrong PIN keeps its
  `fido2.PINAttemptsError` attempts-remaining annotation so a looming lockout
  is visible. `sdk/go/fido2` additionally re-exports `WebAuthnAssertion` so
  SDK callers can name `AuthenticateWebAuthn`'s result type.

  Files: `cmd/xkmsctl/pin_input.go` (new), `cmd/xkmsctl/user.go`,
  `cmd/xkmsctl/admin.go`, `cmd/xkmsctl/errors.go`, `sdk/go/fido2/fido2.go`.
  Verified by ceremony tests driving the real `pkg/fido2` stack against the
  real virtual authenticator with a PIN installed — registration and login
  complete with the PIN, fail named without it, and report remaining attempts
  on a wrong one — plus resolver-precedence and before-the-network guard
  tests; each fails on the unfixed code.

- **The ACME client's retry-after deadline keeps nanosecond precision, so the
  client can no longer resume before the instant a server named** (#405).
  `RateLimiter` stored the end of a `Retry-After` period through `Time.Unix()`,
  which collapsed every deadline to the next whole-second boundary: a
  one-second back-off held the client anywhere from ~0 ms to 1000 ms depending
  on where in the current second the call landed, and a sub-second `Retry-After`
  was unrepresentable. RFC 8555 §6.6 and RFC 9110 §10.2.3 both expect the value
  to be honoured, so this was the client retrying early against a server that
  had just asked it to back off — the failure a client-side rate limiter exists
  to prevent. It also made `TestRateLimiter_Wait_RetryAfter` fail about one run
  in fifty, which is how it was found, on an unrelated branch's race-detector
  leg.

  `retryUntil` now holds Unix nanoseconds, matching the `lastRefill` field
  beside it, so it stays a lock-free `atomic.Int64` — a change of unit, not of
  representation. Two further ways the limiter could resume early are fixed
  with it: `Wait` slept once and then cleared the deadline unconditionally, so
  a second `429` arriving mid-wait was overwritten and the client resumed on
  the older deadline (it now re-reads after each sleep and clears with a
  compare-and-swap on the value it saw expire, so a later deadline extends the
  wait); and a deadline past 2262 overflowed `Time.UnixNano` to a negative
  value that read back as "not blocked", which `storeRetryDeadline` now clamps.
  `Stats` no longer tears between two reads of the field. `pkg/acme/client` was
  audited for other second-granularity deadlines and has none. Verified by a
  property test asserting `Wait` never returns before the deadline, four killed
  mutants, and 20 consecutive `-race` runs of the package.

## [0.9.4-alpha] - 2026-09-05

### Added

- **Attested-peer verification primitive** — `pkg/attestation/peer`, aliased
  in `sdk/go` as `PeerAttestationVerifier` / `PeerEvidence` / `PeerPolicy` /
  `PeerVerdict` (#273). Answers "is the other end of this connection a
  *currently attested* system?" from a TPM 2.0 quote: attestation-key
  certificate chained to configured anchors and carrying
  `tcg-cap-verifiedTPMRestricted` (TCG DevID v1 r12 §8.2, required by
  default), signature over `TPMS_ATTEST`, nonce echo, TLS channel binding in
  the qualifying data (`QualifyingData` = SHA-256(nonce ‖ exporter) with
  `ChannelBinding` deriving the exporter under `EXPORTER-attested-peer`),
  reported PCR values proven against the signed digest, required registers
  (PCR 10 for measured userspace), baseline comparison, and a maximum
  evidence age judged against the collector's timestamp. The verdict reports
  every check and a typed `FailureClass` separating evidence that was present
  and wrong (`cryptographic`) from a check that could not run (`absence`), so
  a consumer can quarantine on the first and only deny on the second. Fails
  closed throughout; the existing `TPM2.Quote` needed no change because it
  already passes qualifying data through verbatim. Documented in
  `docs/attested-peer/`.

### Security

- **The vulnerability scanner itself floated on `latest`, so what the CI
  and release gates accepted could change between runs with no commit**
  (#325). `.github/workflows/ci.yml`, `.github/workflows/release.yml`,
  `.github/workflows/nightly.yml`.

  Three gate invocations ran `aquasec/trivy:latest` (ci.yml's Docker job,
  release.yml's server and CLI image gates) and three steps used
  `aquasecurity/trivy-action@master`, while nightly.yml already pinned the
  Gitea CLI install to `0.74.0`. A floating scanner moves the gate in both
  directions: a new release can redden a green run mid-release with no code
  change, or -- worse -- reclassify a finding and let a previously-red
  artifact publish. Same doctrine as removing `alpine:latest` (#246).

  All six sites now agree: the image tag is `aquasec/trivy:0.74.0` (the
  version nightly.yml installs, also the current upstream release), the
  action is `aquasecurity/trivy-action@v0.36.0` (repo convention pins
  actions by tag) with an explicit `version: v0.74.0` input, since the
  action's own default is v0.70.0. Scan flags, severities and ignore
  policies are untouched; cross-referencing comments at each site say to
  bump all pins together. Verified by YAML round-trip of all three
  workflows and a grep proving zero `trivy:latest` /
  `trivy-action@master` references remain. Note the vulnerability DB is
  still fetched fresh at run time by design; the pin fixes the scanner's
  classification logic, not DB freshness.
- **A `pinUvAuthToken` survived `setPIN`, and `changePIN` invalidated it only
  incidentally, so a token minted before a PIN change stayed live across the
  user's remediation** (#322). `xkey/pkg/authenticator/cmd_clientpin.go`.

  CTAP 2.1 §6.5.2.1 requires the outstanding `pinUvAuthToken` to be
  invalidated when the PIN is set or changed. `handleSetPIN` never did — and
  the gap is reachable, because `getPinUvAuthTokenUsingUvWithPermissions`
  mints a token against built-in user verification without asking whether a
  PIN exists, so a live token can predate the first `setPIN`. `handleChangePIN`
  dropped the token only as a side effect of `regeneratePINProtocolKeys`
  discarding the whole `pinProtocolState`, which left the token bytes unwiped
  in memory and made the guarantee hostage to any future change that keeps
  the negotiated keys across a PIN change.

  Both handlers now call `stopUsingPinUvAuthTokenLocked` — the same path
  token expiry and `authenticatorReset` use — under the write lock they
  already hold, after the new PIN is accepted and strictly after every
  failure path has returned: a `changePIN` with the wrong current PIN must
  not clear the token, or anyone unable to authenticate could still revoke
  the legitimate session. A replayed old token is refused with
  `CTAP2_ERR_PIN_AUTH_INVALID` and its bytes are zeroed in place.

  Verified by `pin_token_invalidation_test.go`: the old token is refused
  after a successful `setPIN`/`changePIN` while a token minted under the new
  PIN authorizes normally, failed attempts leave the token usable, and
  mutation checks confirm each test goes red when its invalidation call is
  removed (the `setPIN` test also fails on unmodified `main`).

- **`AutoUVBackend` asserted user verification because the barrier was
  unsealed, so an unattended device claimed a human had authenticated**
  (#280). `xkey/pkg/authenticator/keybackend/autouv.go` (deleted),
  `xkey/pkg/gui/app.go`, `xkey/cmd/xkey/cmd/fido2.go`.

  The decorator forced `HandlesUserVerification` true whenever
  `IsAutoUVActive()` reported the barrier open, and in `getAssertion` that is
  the branch immediately after a verified PIN:

  ```go
  case pinAuthValid:                                          // a PIN was verified
      flags |= FlagUV
  case a.keyBackend.Capabilities().HandlesUserVerification:   // barrier unsealed. no human.
      flags |= FlagUV
  ```

  Barrier auto-unseal is by definition the device unlocking its own storage
  with **nobody present**, so the UV flag it produced was false. The comment
  directly above that switch already states the rule it broke: the UV flag
  tells the relying party that a human verified themselves, and downstream
  systems make authorization decisions on it. go-quicbaas gates administrator
  enrollment on that flag, and #215's `credProtect` level-3 enforcement
  requires UV — both were satisfiable with no human at all. In the CLI path it
  was not even tied to barrier state: `staticBarrierProvider{active: true}`
  is a constant.

  Removing it cannot affect unsealing. Every other method of the decorator was
  pure delegation, and the provider only ever *read* barrier state — the
  dependency ran barrier -> decorator, never the reverse. What changes is that
  `getInfo` now reports `uv=false` where a PIN is the verification method, and
  the browser collects that PIN: a real verification instead of a claimed one.
  `HandlesUserVerification` remains for backends that genuinely verify a human
  inside the key operation, which is the phone biometric (`pkg/phone`).

  The `--auto-uv` flag and `fido2.auto_uv` setting are removed with it; their
  only effect was to turn the assertion on.
- **A nil `UserPresenceHandler` installed an auto-approving one, so an
  omitted handler silently granted every ceremony** (#317).
  `xkey/pkg/authenticator/authenticator.go`.

  ```go
  if config.UserPresenceHandler != nil {
      a.upHandler = config.UserPresenceHandler
  } else {
      a.upHandler = NewAutoGrantHandler()   // approves everything
  }
  ```

  The nil case did not skip a check -- it substituted one that always answers
  yes. A caller that simply did not know the field existed got an
  authenticator granting user presence unconditionally, with nothing in its
  construction, its logs or its behaviour saying so. It is the fail-open
  family of #313 in its most dangerous form: the other sites omit a control,
  this one fabricated a passing result for it.

  `NewAuthenticator` now returns `ErrUserPresenceHandlerRequired` when the
  field is nil. There is no safe default to pick: auto-granting fabricates a
  verification, and denying everything silently disables the authenticator,
  so the policy is stated by the caller.

  Each construction site now says what it means. The GUI installs its
  `SocketHandler` at construction instead of relying on
  `AttachPresenceHandler` to replace an auto-grant default afterwards -- and
  because `a.deviceNotifier` is populated in a later startup phase, that
  handler begins with no notifier, which prompts nobody and times out. A
  refusal is the correct direction to fail in that window.
  `virtualdevice` keeps unattended approval, which is right for a
  programmatically driven device with no prompt channel, but now states it at
  the call site rather than inheriting it invisibly.

  Together with #280 this closes both paths that could set UV or UP without a
  human: the key backend asserting verification, and the handler fabricating
  it. Neither fix is sufficient alone.

### Fixed

- **`SignTCGCSRIDevID` stored the IAK and the IDevID certificate under the same
  common name, so the IDevID record overwrote the IAK record** (#371).
  `pkg/ca/tcg.go`, `pkg/ca/interface.go`,
  `pkg/acme/server/handlers/order_finalize.go`, `sdk/go/acme/ca.go`.

  Both certificates were issued from `request.Subject` and persisted through a
  certificate store keyed by `Subject.CommonName`; the IDevID, stored second,
  replaced the IAK. Measured on the platform fleet on 2026-09-05: the CA held
  no IAK certificate for any enrolled device, so nothing server-side could
  list, revoke, or return the IAK it had signed. The ACME finalize handler
  computed an `iak-<model>-<serial>` name for the IAK and never used it.

  The IAK is now issued under `IAKCommonName(model, serial)` =
  `iak-<model>-<serial>` (model and serial from the CSR; the rest of the
  subject is still the request's), which is the one definition of that name:
  the handler's dead copy is gone. The IDevID subject is unchanged, so
  `<model>-<serial>` lookups keep working. `(*CA).IAKCertificate(ctx, model,
  serial)` reads the record back, exposed through a new `IAKCertificateReader`
  interface beside `TCGCA` (not inside it, so existing `TCGCA` implementations
  keep compiling) and re-exported by `sdk/go/acme` as `CAIAKCertificateReader`
  and `CAIAKCommonName`. `TCGData.IAKCertificateDER` still carries the IAK DER
  to the order-finalize hooks unchanged.

  Compatibility: certificate stores written before this release hold no IAK
  record for already-enrolled devices, because it was overwritten at
  enrollment. Re-enrollment, or the consumer's re-issue path, repopulates it;
  no migration fabricates a record the CA never kept.

  Verified by a TCG-CSR-IDEVID assembled in software that passes the CA's
  production verification (`pkg/ca/tcg_iak_certstore_test.go`). Mutation
  record: reverting the IAK subject to `request.Subject` fails five of the
  twenty-one new tests, among them `TestSignTCGCSRIDevID_IAKRecordSurvivesIDevIDIssuance`
  (one record in the store instead of two) and
  `TestIAKCertificate_ReturnsEnrolledIAK` (`ErrCertificateNotFound`).

## [0.9.3-alpha] - 2026-09-05

### Added

- **`tcg-cap-verifiedTPMRestricted` (2.23.133.11.1.3) is now defined, issued
  and re-exported** (#358). The CA stamps it on attestation-key (AK / IAK /
  LAK) certificates only — IDevID keys are Unrestricted by specification and
  never carry it — so a relying party can perform the DevID §8.2 MUST check
  before trusting a quote. `sdk/go` re-exports the TCG DevID OIDs
  (`OIDTCGKpAIKCertificate`, `OIDTCGVerifiedTPM{Residency,Fixed,Restricted}`
  and their `x509.OID` `*Policy` forms) so consumers can verify the policies
  without importing `pkg/ca`.

### Fixed

- **`GetAssertion` aborted on the first allowList entry whose key material the
  key backend no longer held, so one stale credential permanently bricked
  WebAuthn login** (#347). `xkey/pkg/authenticator/cmd_getassertion.go`.

  The server's credential table survives a daemon re-provision, so it keeps
  offering allowList entries whose keys were wiped from the key backend. The
  stored record still loaded from credential storage, so the stale entry was
  selected first and the ceremony died at signing time on
  `keybackend: key not found` — the user's valid credential behind it was
  never tried, and re-registering only appended entries after the poison one.
  Per CTAP 2.1 §6.2 step 1 such an entry is simply not bound to this
  authenticator and is not applicable; `CTAP2_ERR_NO_CREDENTIALS` is correct
  only when the applicable set is empty.

  Selection now probes `keyBackend.LoadKey` for every allowList candidate
  (`filterLoadableCredentials`), branching on the typed
  `keybackend.ErrKeyNotFound` sentinel: not-found entries are skipped at debug
  level and iteration continues in allowList order; any other LoadKey failure
  (backend closed, I/O fault) still aborts the ceremony, so a flaky backend
  cannot silently shrink the applicable set. `numberOfCredentials` and the
  `getNextAssertion` sequence now count only the credentials that can actually
  sign. The discoverable-credential flow (no allowList) and inline-key
  authenticators (no key backend) are unchanged.

  Verified by five regression tests over a real software key-backend adapter,
  including the field case `[stale, stale, valid]` → success with the valid
  credential; the field-case and ordering tests fail against the pre-fix code.
- **An unrecognised elliptic curve on the REST key-generation path told the
  caller they had omitted the curve they supplied** (#153). Two sites discarded
  `types.ParseCurve`'s error with `_`, leaving `ECCAttributes.Curve` nil. The
  nil then reached the backend, whose own guard reported *"curve is required"* —
  so a client sending `curve: "P-999"` was told the field was missing, and the
  offending value was gone from the message. Both sites now propagate the error:
  the handler answers 400 and `buildKeyAttributes`, which already returned an
  error, returns this one. `ErrUnknownCurve` names the value the caller sent.
- **`SetupWizardService.FactoryReset` refuses when no PIN service is wired,
  instead of treating an unrunnable SO PIN check as a passing one**
  (refs #313). `xkey/pkg/gui/services/setup_wizard_service.go`,
  `xkey/pkg/gui/services/errors.go`.

  The SO PIN verification sat inside `if s.pinSvc != nil`, and `pinSvc` is
  supplied by the `SetPINService` **setter**, not the constructor. The shipped
  GUI wires it (`app.go:2047`), so the shipped path was safe — but any
  `SetupWizardService` reaching `FactoryReset` without that setter having been
  called accepted **any non-empty string** as the SO PIN and went on to reset
  the TPM, remove the policy HMAC and reset the GUI config. A destructive
  operation's credential gate must not be conditional on the collaborator that
  enforces it having been wired.

  Now `s.pinSvc == nil` returns the new `ErrSetupPINServiceUnavailable`, which
  is distinct from `ErrSetupSOPINVerifyFailed` so "the check could not run" and
  "the check ran and said no" remain different answers.

  **Seven existing tests were passing because of this defect** — they called
  `FactoryReset` with no PIN service and drove a full wipe on an
  unauthenticated call. Each now wires a PIN service that accepts its PIN, so
  they still cover the post-authorization paths they were written for, and
  assert the SO PIN was actually verified.

- **An unrecognised FIDO2 key backend is refused rather than silently answered
  with software keys** (refs #313). `xkey/cmd/xkey/cmd/fido2.go`.

  `createFIDO2KeyBackend`'s `default:` returned `createFIDO2SoftwareKeyBackend`.
  `FIDO2Config.Validate` accepts exactly `software`, `tpm2` and `phone` and runs
  immediately before the call, so the branch is unreachable today and this
  change is behaviour-preserving — but the two switches are in different
  functions over the same enum, so adding a backend name to `Validate` without
  adding a case here would have downgraded key custody from hardware-backed to
  software without an error. The default now returns `ErrFIDO2InvalidBackend`,
  and a test pins the two switches to the same set.

## [0.9.2-alpha] - 2026-09-04

### Fixed

- **Live-state commands ask the running daemon and label their source** (#271).
  `xkey pin status`, `barrier status` and the `password` status/list verbs
  previously read the on-disk state even while a daemon held the live truth,
  rendering "Sealed from a cold data directory" and "Sealed from a running
  daemon" identically. They now prefer IPC, fall back to disk only when no
  daemon answers, and print `Source:` naming which one did (machine-readable
  `source` fields in JSON). Shipped in this release as `12ecb1fc` without a
  changelog entry; credited retroactively.

- **Two padding tests asserted a probabilistic outcome as if it were
  deterministic, reddening shared CI jobs at random** (#343, #346). Both
  corrupted the LAST ciphertext block and then required a specific unpadding
  failure. In CBC that randomises the whole final plaintext block, so the PKCS#7
  pad byte was uniformly random and happened to be *valid* roughly 1 time in 256
  — at which point unpadding succeeded and the assertion failed against a
  different, equally correct error. Neither defect belonged to any pull request;
  they failed for whichever PR was in the queue.

  Both now flip one bit in the **second-to-last** ciphertext block. In CBC,
  `P_n = D(C_n) XOR C_{n-1}`, so that flips the same bit in the final plaintext
  byte — the pad length — turning `0x10` into `0x90` and `0x0D` into `0x8D`.
  Neither can ever unpad, so the refusal the tests assert is now certain rather
  than likely.

  Measured on the two tests over 1,000 iterations each: both failure modes
  reproduce on unmodified `main` with the exact CI error strings, and neither
  occurs after the change. The assertions are unweakened — with `pkcs7Unpad`
  mutated to accept any input, both tests fail; reverted, both pass.
- **A padding-mismatch test asserted a probabilistic refusal as if it were
  certain** (#345). `TestDecryptAsym_RSA_OAEPMismatch` encrypted with OAEP and
  relied on the PKCS#1 v1.5 unpadding of the resulting block failing. That is
  only *probable*: RSA-decrypting an OAEP ciphertext under v1.5 yields an
  essentially random block, and a random block satisfies v1.5's leading
  `0x00 0x02` roughly 1 time in 65,536 — at which point no error was returned
  and the test failed with *"An error is expected but got nil"*. A fresh key and
  fresh OAEP padding per run made it unreproducible on demand.

  The test now encrypts a chosen block raw (`c = m^e mod n`) whose second byte
  is `0x01`, which RFC 8017 §7.2.2 forbids in an encryption block, so the
  refusal is certain. A counterweight decrypts a correctly v1.5-padded
  ciphertext, so the refusal cannot pass by rejecting everything. Both
  directions are mutation-verified.

### Security

- **Both published container images now patch their base at build time**
  (closes #135). `Dockerfile.cli`, `.github/workflows/release.yml`.

  `apt-get upgrade -y` was present in five of the seven runtime stages in the
  repository. The two that lacked it were exactly the two that **publish**:
  `Dockerfile.cli`, which builds `xkms-cli`, and the `Dockerfile.release`
  generated inside `release.yml`, which builds `xkms-server`. Both now carry
  it, matching `Dockerfile.server` and the three protocol images.

  A pinned base is a reproducible base, not a patched one. `debian:bookworm-slim`
  is rebuilt only periodically, so between rebuilds an image inherits whatever
  its base snapshot carried — which is the same window that shipped a HIGH in
  a sibling repo's published image.

  **Measured, and reported as measured:** on today's base this changes no CVE
  count. Building the CLI runtime stage with and without the upgrade produces
  images that Trivy scores identically — 259 findings each, all of them
  unfixed, so the release gate's `--ignore-unfixed CRITICAL,HIGH` reports 0
  for both. The upgrade is not idle (it moves `libpcre2-8-0`), but no
  outstanding **fixable** CRITICAL/HIGH exists in this base right now. This is
  a preventive control that closes the gap on the day Debian publishes a fix
  ahead of a base rebuild — not a fix for a live vulnerability.

  The first `alpine:latest` half of #135 was already resolved in `a0adcc0a`
  (PR #246); no `alpine:latest` remains anywhere in the repository.
- **A pinUvAuthToken went on authorizing credential operations after the one
  it was used for** (#282, refs #213). `xkey/pkg/authenticator/cmd_clientpin.go`,
  `cmd_makecredential.go`, `cmd_getassertion.go`, `cmd_config.go`,
  `cmd_reset.go`.

  CTAP 2.1 §6.5.5.7: "when a pinUvAuthToken is used with an operation that
  tests user presence, it is updated to remove all permissions except lbw".
  The authenticator never performed that update. `7e567ca2` (#213) bounded how
  *long* a token lives — 30 seconds of disuse, 10 minutes of life — but every
  successful use refreshed the inactivity timer, so inside that window one PIN
  entry authorized an unbounded number of registrations and assertions. #213's
  own acceptance criterion, "a no-permissions token is refused on its second
  use", was not met by the landed fix.

  An operation that sets the `up` bit now clears the token's `userVerified`
  flag and every permission except `lbw` — `clearUserVerifiedFlag()` plus
  `clearPinUvAuthTokenPermissionsExceptLbw()`, per §6.1.2 step 14 and §6.2.2.
  **This is not invalidation and does not make the token single-use.** `lbw`
  deliberately survives, and a getAssertion with `up=false` sets no `up` bit and
  clears nothing, so conditional UI keeps discovering credentials on one token.

  The flag lives on `pinProtocolState`, not in a per-command local, so a second
  command in the same session observes it; and it is read inside the *shared*
  `checkPinUvAuthTokenLocked`, so the non-consuming `CanAuthorizePinUvAuthToken`
  probe reports a cleared token as unauthorized too. Without that, a cleared
  token could still unlock a credProtect-restricted credential or answer an
  excludeList.

  Three smaller defects on the same path:

  - `authenticatorConfig`'s permission check was written `if a.pinState.protocol
    != nil { ... }`, so it was skipped entirely when no token existed rather
    than refusing. It now goes through `tokenHasPermission` and fails closed.
    `7e567ca2` fixed `verifyConfigHMAC` but not this one — unreachable today,
    one edit from an authorization bypass.
  - `getPinToken` accepted the `permissions` (0x09) and `rpId` (0x0A)
    parameters and silently ignored them, letting a platform believe it had
    requested a scope the authenticator did not apply. It now returns
    `CTAP1_ERR_INVALID_PARAMETER`, per §6.5.5.7.1.
  - Stopping a token dropped the reference and left the bytes for the
    collector. They are wiped first, and `authenticatorReset` now routes
    through the same path rather than discarding the protocol state around
    them.

  **Deliberately not implemented.** The user-present time limit and its
  `userPresent` flag: this authenticator never caches presence — every token is
  minted `userIsPresent: false` — and §6.5.2.1 permits a zero user present time
  limit, so the state would be dead. Recorded as a decision in the code and in
  `xkey/docs/fido2/authenticator-security.md`.

  **Adjacent gaps, filed rather than absorbed here:** no permission check
  exists for `bioEnrollment` or `largeBlobWrite` (#318); `setPIN` / `changePIN`
  do not invalidate an outstanding token, so one minted under the old PIN keeps
  working after a change (#322); and authorization and clearing are two
  separate lock acquisitions with the user-presence prompt between them, so two
  concurrent commands can both spend one token (#323, blocked on a design
  ruling).
- **The software backend refuses key attributes that declare more than one
  algorithm family** (#158). `pkg/backend/software/family_gate.go`,
  `pkg/backend/software/software.go`.

  `SoftwareBackend` is the only backend that ROUTES on the algorithm family:
  `DeleteKey`, `RotateKey`, `ImportKey`, `ExportKey` and `ExportKeyMaterial`
  each pick a sub-backend from `attrs.IsSymmetric()`, and its PKCS#8, symmetric
  and quantum sub-backends share one flat `keys/{id}.key` namespace. But
  `IsSymmetric` reads `SymmetricAlgorithm` alone while `KeyAttributes.ID`
  resolves `X25519Attributes` → `QuantumAttributes` → `KeyAlgorithm` →
  `SymmetricAlgorithm`. `Validate` walks ID's precedence and stops at the first
  family, so it raised no objection. **Attributes naming two families were
  processed as one kind of key and addressed as another.**

  Measured, not inferred: attributes carrying `KeyAlgorithm=RSA` with valid
  `RSAAttributes` **and** `SymmetricAlgorithm=aes256-gcm` routed to the
  symmetric backend, which **deleted the RSA private key** at
  `software:tls:<cn>:rsa` and returned `nil` — and through `RotateKey`
  **overwrote it** with AES bytes, after which `GetKey` could no longer parse
  the PKCS#8. Silent and unrecoverable in both cases.

  `RotateKey` is a fifth site not listed on #158; it was found by enumerating
  the dispatch table rather than working from the issue.

  The two export paths did already fail closed, but only by accident downstream
  — the symmetric store rejected the stored DER with `invalid AES key size:
  9736 bits`. That is a size check doing a job nobody assigned it, and it stops
  protecting anything the moment a stored blob is 16, 24 or 32 bytes. All five
  sites now refuse at the boundary with `ErrContradictoryAlgorithmFamilies`,
  which also satisfies `errors.Is` for `backend.ErrInvalidAttributes`.

  **Zero families stays permitted.** The earlier attempt at this check (PR #63,
  closed unmerged in favour of #247) refused zero families as well, which made
  the MCP import tool unsatisfiable by any request shape. A check no legitimate
  producer can satisfy rejects working paths instead of catching wrong ones —
  the same reason `validateKeyType` does not compare the declared curve.
  `TestRequireSingleAlgorithmFamily_ZeroFamiliesIsPermitted` and
  `..._AdmitsEveryListKeysDescriptor` pin both halves of that.

  No interface changed: the gate is a package-private helper in
  `pkg/backend/software`, so no other backend and no SDK type is affected.
- **The release workflow no longer publishes artifacts built with the checksum
  database switched off** (closes #112). `.github/workflows/release.yml`.

  `release.yml` set `GOSUMDB: off` and a pinned `GOPROXY` at workflow scope —
  the two overrides `ci.yml` has prohibited in place since ci-template v1.1.
  They land harder here, because this is the workflow that publishes: a
  release is the one artifact a consumer cannot re-verify after the fact, and
  `GOSUMDB: off` disabled `sum.golang.org` verification for every THIRD-PARTY
  dependency in the build whose output ships.

  The exemption the override was reaching for is far narrower. Only
  `github.com/jeremyhahn/*` cannot be in the public checksum database, and the
  runners already inject `GOPRIVATE=github.com/jeremyhahn/*` alongside the
  `GIT_CONFIG_*` insteadOf rewrite. `GOPRIVATE` derives both `GONOPROXY` and
  `GONOSUMDB` from that one glob, so first-party modules stay exempt while
  `GOSUMDB=sum.golang.org` remains ACTIVE for everything else. That glob
  covers every first-party requirement across all four modules (go-codec,
  go-enclave, go-frost, go-luks2, go-objstore, go-qrdb + its sdk/go,
  go-quicraft, go-truststrap, and this repo's own sdk/go, xkey and
  web/desktop); every other requirement is a public module.

  **This does not change how the shipped artifacts resolve modules.** The
  binaries and images are compiled inside containers that never received
  these two variables: `docker create` in `build-binaries` forwards
  `GOPRIVATE` and `GIT_CONFIG_*` and nothing else, and `docker build` inherits
  no job environment at all (its credentials arrive as the `gomodauth` secret
  mount). Module resolution for the published binaries has therefore always
  run with the checksum database on. The removal makes the job shell agree
  with the containers it drives, and closes the gap for anything that resolves
  modules in the job shell itself.

  The pinned `GOPROXY` is the second half of the same prohibition: it is the
  default value today, so it buys nothing, and a pin breaks the build whenever
  an upstream re-points a tag (go-tpm-tools v0.4.8, 2026-08-14).

  The prohibition and its reasoning are now recorded in place in
  `release.yml`, the way `ci.yml`, `coverage.yml` and `docker-tests.yml`
  already record it.

- **`xkey fido2 status` now names the credential store and says whether
  passkeys are encrypted at rest** (refs #181).
  `xkey/cmd/xkey/cmd/fido2_status.go`, `xkey/pkg/ipc/protocol.go`.

  Under `--storage file` a credential record is plain JSON whose `PrivateKey`
  is a base64 PKCS#8 key, protected only by file permissions. Under
  `--storage barrier` the same record is encrypted. **Nothing on disk
  distinguishes them**: the barrier backend is rooted at the data directory
  with a `fido2/xkey/` key prefix, the file backend at `<dataDir>/fido2` with
  an `xkey/` prefix, and the two prefixes compensate for the differing roots —
  so both layouts compose to the same path, and the file name is identical
  either way.

  The daemon is the only thing that knows which. `status` now reports the store
  type, path, key prefix and — in words — whether records are encrypted. A
  daemon predating the field reports `unknown` rather than defaulting to a
  value that would read as a claim.

  This is reporting only. **No credential data moves**, and the two prefixes are
  deliberately left distinct and are now named constants with a comment saying
  why unifying them would relocate data. The underlying plaintext-at-rest
  exposure and the layout collision it enables remain open on #181.
- **A qrdb transport failure is no longer read as "this credential does not
  exist"** (refs #183). `pkg/webauthn/qrdb_userstore.go`.

  Not-found was decided by substring match — `"not found"`, `"ErrCodeNotFound"`,
  `"no rows"` — against the error text, with a comment calling the check
  "deliberately permissive". Any failure whose message happened to contain one
  of those strings was classified as an absent record, and every caller treats
  absence as benign. In the authentication path that is a fail-open.

  Two of the three key-value sites are worse than an error-classification nit:

  - hydrating a user's credentials, a failed lookup hit `continue`, so a login
    proceeded against **silently fewer credentials than the user has** and could
    judge a valid passkey unknown;
  - reading the credential index, a failed lookup read as **"this user has no
    credentials at all"**.

  The KV classifier is now typed and fails closed: it matches
  `*transport.KeyNotFoundError` with `errors.As` — the contract the qrdb SDK
  itself uses in its kvstore adapter, coordination and guarded-swap paths — and
  anything it does not positively recognise is returned as an error.

  **The user-record path is deliberately unchanged** and still matches on text.
  `UserClient.GetUser` and `GetUserByEmail` document no not-found error, their
  implementations live outside this repository, and this package's tests use
  hand-written fakes, so what a real missing user produces cannot be observed
  here. Inverting that default without the answer would turn every genuine
  not-found into an error and break registration. Asked upstream as
  `go-qrdb#286`; the comment at `isUserNotFound` names it. Noted there too:
  `qrdbsdk.ErrNotFound` is an `ErrorCode` constant rather than a sentinel
  error, so `errors.Is` cannot match it and `IsDAONotFound` is the only typed
  probe the SDK offers.
- **The GUI trust store now sees certificates added or removed by another
  process** (#182). `xkey/pkg/truststore/`, `xkey/pkg/gui/services/trust_service.go`.

  `BackendStore` and `FileStore` populate their in-memory caches once, at
  construction, and the `TrustStore` interface offered no way to refresh them.
  A certificate imported by the CLI while the GUI was running stayed invisible
  until the application restarted — and with TLS anchors now scoped by purpose
  (#250), a freshly imported CA is exactly what a user adds and then expects to
  work.

  `TrustStore` gains `Reload()`, implemented by both stores. The cache is
  **replaced, not merged**: a certificate another process removed must stop
  being trusted, not merely stop being listed. The cached `x509.CertPool` is
  invalidated with it, so the listing and the trust decision cannot disagree.
  A failed reload restores the previous view rather than leaving the store
  empty.

  The GUI reloads before listing and counting, and returns a reload failure
  rather than serving the cache — an answer that may no longer be true looks
  exactly like one that is.

  Only two types implement `TrustStore`, so widening it was cheaper than a
  narrower seam; compile-time assertions now pin that, because the interface is
  small enough for an implementer to drift out of it silently.

  fsnotify-driven invalidation is not included: reload-on-view addresses the
  reported symptom, and a watcher is a separate change with its own failure
  modes.

- **The keys that unwrap the authenticator's key hierarchy now live in
  protected memory** (#285). `xkey/pkg/authenticator/key_manager.go`.

  `KeyManager.adminKey`, `.cmk`, `.smk` and `.umk` were plaintext `[]byte` on
  the ordinary Go heap for the whole time the manager was unlocked — swappable
  to disk, dumpable, and wiped only by convention on `Lock()`. These are the
  keys that unwrap everything below them, including the attestation key that
  #218/#223 moved into a `secure.Buffer`: an attacker reading the heap did not
  need the protected key, only the one that unwraps it.

  All four are now memguard-backed `*secure.Buffer` — mlocked so they cannot
  reach the swap file, canary-guarded, and destroyed deterministically. Every
  consumer borrows through `WithBytes` rather than `Bytes`, because only
  `WithBytes` holds the borrow across the read; a memguard failure anywhere in
  the process unmaps every live enclave, and an accessor that has already
  returned cannot protect the caller reading the slice.

  Scope was measured rather than assumed: **four fields, and all 33 references
  in one file.** The issue described two fields; `smk` and `umk` have the same
  shape.

  **What this does not close.** `KeyWrapper.Unwrap` returns plaintext on the
  ordinary heap, so every unwrap still transits ordinary memory before the copy
  into protected memory — brief, because `secure.NewBufferFromBytes` wipes its
  source, but present. This change closes the **long-lived** exposure, material
  held for an entire unlocked session; it does not close the transit. Filed as
  #291, which is gated on a design question rather than on size: `GetCMK`
  returns a heap copy *because callers mutate it*, so the fix has to decide how
  a caller mutates key material that lives in protected memory. `GetCMK` is
  commented as the shape #291 removes rather than as something it protects.
- **The GUI never runs on the auto-grant presence handler** (#214 follow-up).
  #214 stopped `FIDO2DeviceService.Stop` from inventing an `AutoGrantHandler`
  and had it restore the handler `Start` displaced — but `pkg/gui/app.go`
  configures no `UserPresenceHandler` at all, so the handler being restored
  *was* the library's auto-grant default. Toggling the FIDO2 device off in the
  UI therefore still left the browser-extension and autofill paths approving
  user presence with no user involved, and the same hole was open before the
  device ever started, when it was disabled in settings, and when `/dev/uhid`
  was unavailable.

  The GUI touch prompt is now installed at authenticator initialization and
  held for the session (`FIDO2DeviceService.AttachPresenceHandler`); `Start`
  captures that same handler and `Stop` puts it back, so the restore is a
  no-op and there is no window in which presence auto-approves. The prompt does
  not need the UHID bridge — it notifies the frontend and waits for approve,
  deny or timeout — so stopping the device narrows nothing but USB.
  `socketHandler` becomes an `atomic.Pointer`: it is created on the startup
  goroutine, replaced by `Start` on a Wails-dispatched goroutine, and read by
  `HandleTouch` and `GetStatus` on others.
- **An authenticator's Security Officer PIN can now be established, and
  "no SO PIN set" no longer reads as "no SO required"** (#233).

  `InitializeSOPIN` and `VendorCmdSetSOPIN` had no reachable caller, so no
  device could be given an SO PIN and every SO-gated capability was
  unreachable. Building a path to them without also closing the
  trust-on-first-use window would have shipped the window, so both land here.

  **The model.** xKey's SO/User split is PKCS#11's, not FIDO2's — CTAP 2.1 has
  no Security Officer — so two specifications govern two halves. PKCS#11 v3.0
  §5.6 (`C_InitToken`) governs the lifecycle: a token is *uninitialized* until
  it is given an SO PIN, refuses SO-gated operations before that, and
  afterwards the SO PIN changes only by authenticating as SO.
  `Authenticator.InitializeToken` / `ChangeSOPIN` / `UnlockSO` are that
  lifecycle; `authenticatorReset` is the only way back.

  **The window.** The first SO PIN cannot be authenticated against anything, so
  CTAP 2.1 §6.9's own two bounds on `authenticatorReset` are applied to it:
  accepted only within `Config.TokenInitWindow` (default 10s) of power-up, and
  requires user presence. No bespoke enrolment token was invented alongside
  them. A successful reset re-arms the window, since the caller has just proven
  both. **For a software authenticator a power cycle is a process restart** —
  the security doc states this rather than implying a hardware guarantee.

  **The lockout was ornamental and is now enforced.** `SOPINManager.Verify`
  called `ResetRetries()` on *every* call, before the caller had validated
  anything, so the subsequent failure decrement netted out and the counter
  never reached zero: 20 consecutive wrong SO PINs left 7 of 8 retries. It is
  replaced by an explicit three-call contract —
  `BeginVerify` / `ConfirmVerified` / `RecordFailure` — that spends the retry
  **before** the answer is known, so a caller that crashes or never reports
  back gets no free attempt. CTAP 2.1 §6.5.5.7's power-cycle threshold (3
  consecutive failures → `ErrSOPINAuthBlocked`) is added, and the token layer
  persists every spend, on failure as well as success, so a restart cannot
  refund one.

  **Three further fail-opens found while wiring this, each with a test that
  fails without the fix:**

  - `SOPINManager.Change` rotated the Argon2id salt and reset the retry counter
    **before** the caller validated the current SMK. A single wrong-PIN change
    attempt therefore made the real SO PIN underivable — a bricked token — and,
    because the counter was reset on each attempt, made the change path an
    unbounded online brute force. `KeyManager.ChangeSOPIN` now unwraps the Admin
    Key first and only then calls the renamed `Rekey`, which mutates nothing it
    has not been told is authorised.
  - `UnlockWithSOPIN` succeeded when `WrappedAK` was empty. With nothing to
    authenticate the derived SMK against, *any* PIN unlocked the SO role. It now
    returns `ErrKeyManagerNoAK`.
  - `MemoryStorage.copyState` silently dropped `SOPINManager` and every wrapped
    key, so SO state did not survive a save/load cycle at all.

  `SerializableState.SOPINRetries` also lost its `omitempty`. That one was
  *not* live — a dropped zero decodes back to zero and the restore is
  unconditional — but a tag that omits a lockout is a landmine under the next
  person who makes the restore conditional, so it is written unconditionally
  and the reason is in the field comment.

  **Reporting.** SO-gated operations on an uninitialized token returned
  `ErrKeyManagerLocked`, indistinguishable from "the SO has not authenticated".
  They now return `ErrTokenUninitialized`, and `Authenticator.TokenFlags()`
  surfaces the PKCS#11 `CK_TOKEN_INFO` flags (`CKF_TOKEN_INITIALIZED`,
  `CKF_SO_PIN_COUNT_LOW`, `CKF_SO_PIN_FINAL_TRY`, `CKF_SO_PIN_LOCKED`), which
  render an uninitialized token as `uninitialized` rather than as an empty flag
  set. The `GetSOPINRetries` vendor subcommand becomes `GetTokenInfo` (same
  wire ID `0x06`) and no longer *fails* on an uninitialized token — an error
  reading "SO PIN not set" is precisely what gets mistaken for "no SO PIN
  needed". Every SO error now maps to a real CTAP status code instead of
  collapsing to `CTAP2_ERR_OTHER` (0x7F).

  `authenticatorGetInfo` now advertises `vendorPrototypeConfigCommands` (0x15),
  which CTAP 2.1 §6.4 requires whenever the `vendorPrototype` subcommand is
  supported; its absence left the whole vendor surface undiscoverable.

  **Not fixed here, and recorded rather than implied:** there is still no CLI
  verb reaching these commands — `authenticatorConfig` `0x0D` is the only
  transport — and `xkey pin set-so` drives an unrelated subject (the qrdb PIN
  service), which `docs/fido2/daemon-configuration.md` previously stated the
  opposite of. CTAP 2.1 §6.9's power-up bound on `authenticatorReset` itself is
  also still not enforced.

- **The unscoped common-name key lookup is fixed on gRPC and REST** (#221).
  #166 fixed it for MCP; the same first-match-on-CN scan existed on the other
  two transports and was not covered. A key ID on these transports is a common
  name, which is unique only **within** a tenant, so a scan over an unscoped
  backend matches whichever tenant's key is listed first.

  Both transports now resolve through a `lookupTenantBackend(ctx, name)` helper
  that supplies `callerTenantID(ctx)` to `XKMSService.LookupTenantBackend` —
  the same shared helper MCP uses, so all three agree on what a tenant is.

  **The two were not equally exposed**, and the difference was measured rather
  than assumed:

  - **gRPC acted on the unscoped result.** `DeleteKey`, `RotateKey`,
    `ExportKey`, `CopyKey`, `EncryptAsym` and `GetTLSCertificate` resolved the
    CN unscoped and then operated on what came back. Reproduced end to end
    through the real RPC: a caller belonging to a tenant that held **no key of
    that name at all** deleted another tenant's key, and a tenant deleting
    "its own" key destroyed a different tenant's instead. This is a
    cross-tenant **write**, not only the read the issue describes.
  - **REST only pre-checked with it.** `DecryptHandler` and
    `EncryptAsymHandler` used the resolved attributes for this transport's 404
    and for the symmetric branch, then delegated the operation to the service
    layer with `TenantID` set, and the service re-resolves scoped. The exposure
    was therefore an existence oracle plus a possible wrong branch, not
    cross-tenant key use. Scoping the pre-check closes the oracle and removes
    the reliance on a second layer catching it.

  The system tenant is deliberately still unscoped — `tenantScopes`' rule, not
  a special case added here — and a test pins it so a later tightening cannot
  silently break system-level administration.

  Not fixed here: the FROST paths (`pkg/api/grpc/service_frost.go`, build tag
  `frost`) carry the same inline scan but cannot use this helper, because
  `getFrostBackend()` resolves to the concrete key provider and unwraps any
  scoping — the same structural problem as #163, and reported rather than
  guessed at.
- **credProtect is now enforced, and an SO attestation override can no longer
  fall open to `none`** (#215, #216). All paths `xkey/pkg/authenticator/`.

  **credProtect enforcement (#215).** `getInfo` advertised `credProtect`,
  `makeCredential` validated the level, echoed it to the relying party in the
  authenticator-data extension map and persisted it — and nothing ever applied
  it. `checkAssertionCredentialProtection` was a `return nil` stub, and the
  stored `StoredCredential.CredProtect` had **no** enforcement reader on the
  assertion path at all. A level-3 (`userVerificationRequired`) credential
  produced an assertion with the UV bit clear and no PIN demanded, and a level-2
  credential was disclosed — credential ID, user id, name and display name — by
  an empty-allowList enumeration without user verification. The RP was told a
  protection level was in force and made decisions on that echo.

  The CTAP 2.1 §12.1 rules now decide which credentials a request may see, in
  one predicate (`credentialProtectionSatisfied`) applied by the credential
  filter: level 3 requires user verification however the credential was named,
  level 2 requires either an allowList naming it or user verification, level 1
  and unset are unrestricted. A credential that fails is treated as **absent**
  — the request ends in `CTAP2_ERR_NO_CREDENTIALS`, indistinguishable from the
  authenticator not holding it, so the protection level does not itself become
  an oracle.

  This required knowing whether the request is user-verified *before* selecting
  credentials, which is also CTAP 2.1 §6.2.2's order. The pinUvAuthToken checks
  are now shared by two entry points: the existing, committing
  `AuthorizePinUvAuthToken`, and a new read-only `CanAuthorizePinUvAuthToken`
  that binds no permissions RP ID, refreshes no timer and discards no expired
  token — asking the question must not spend the use the authoritative call
  later commits.

  The transport's no-credentials deferral heuristic keeps its existing
  behaviour through a separate unfiltered `lookupCredentialsForAssertion`: it
  asks only whether the authenticator holds anything for the RP, and the
  `CredentialIndexer` fast path answers from an in-memory index that cannot
  filter without loading credentials. A heuristic that changed answer with the
  storage backend would be worse than one that consistently ignores protection
  levels, and getAssertion enforces §12.1 regardless.

  **Attestation override (#216 D).** `RPPolicy.AttestationOverride` holds a
  WebAuthn attestation *conveyance preference* (`none` / `indirect` / `direct` /
  `enterprise`); `buildMakeCredentialAttestation` wrote it straight into the
  attestation *statement format* slot, where `direct`, `indirect` and
  `enterprise` matched no case and returned `none`. An SO who mandated
  attestation got a credential telling the RP none was available, with no error
  — the only value that "worked" was `none`, i.e. the existing behaviour.

  The two vocabularies are now separate. `resolveAttestationOverride` maps a
  conveyance preference onto a statement format and returns
  `ErrAttestationOverrideUnsupported` (`CTAP2_ERR_UNSUPPORTED_OPTION`) when the
  preference cannot be honoured; a backend that cannot produce the mandated
  statement yields `ErrAttestationUnavailable` rather than a silent downgrade.
  There were three fall-open paths to `none`, not the one reported.

  **Data race, found while fixing the above and not previously filed.**
  `buildMakeCredentialAttestation` set `a.config.AttestationFormat`, called the
  builder and restored it — mutating shared authenticator state with no lock, on
  both the enterprise and SO-override branches. Two concurrent registrations
  under different RP policies could observe each other's format and attest under
  it. The format is now a parameter and no shared state is written;
  `TestBuildMakeCredentialAttestationIsRaceFree` reproduces the race under
  `-race` against the old code.

  **SO policy on the Go API path (#216, unfiled).** `MakeCredential`'s Go API
  never consulted `rpPolicyStore` at all, so an SO's RP block and attestation
  override did not fire for in-process callers even though the CBOR path
  honoured both — `GetAssertion`'s Go API already applied policy, so the two
  diverged. Both controls now apply on that path. `UVOverride` deliberately does
  not: this path's PIN precondition differs, so what "required" means for an
  in-process caller is a question rather than a transcription, and it is tracked
  separately.

  **Policy HMAC coverage (#216 E2).** `PolicyFields` omitted
  `RequireUserPresence`, `EnableUserIntentCheck`, `AttestationFormat`,
  `EnablePIN`, `EnableResidentKey`, `EnableHMACSecret`, `SupportedAlgorithms`
  and `AAGUID`, so an attacker with exactly the filesystem write access the HMAC
  exists to detect could flip `RequireUserPresence` to false and still verify.
  All eight are now covered and named individually in the mismatch report.

  **The canonical form now carries a schema version** (`"v"`), and a policy
  signed under a different field set reports the new `ErrPolicySchemaChanged` —
  never `ErrPolicyTampered`. The two demand opposite responses from an operator:
  one means "re-sign your policy", the other means "someone modified your
  device". Without that distinction this very change would have reported
  tampering on every signed device at once, because `Canonical()` is a
  `json.Marshal` of the struct and seven of the eight added fields serialize
  unconditionally.

  A schema change does not raise `TamperDetected` and does not prevent startup;
  it logs that integrity is unverified until the SO re-signs. Field diagnostics
  are suppressed for it, because a snapshot from another field set deserializes
  with zero values for fields it never carried and would name settings nobody
  touched.

  No migration path is implemented, because there is nothing to migrate:
  `Config.PolicyIntegrityProvider` is constructed nowhere outside tests, so
  `PolicyManager` is nil in every shipped configuration and no device holds a
  `PolicyHMACTag`. The version is added while that is still true.
  `PolicyFieldsSchemaVersion` is bumped whenever the field set changes shape —
  #216's E3 and F will both change it.
- **`enroll-01` no longer panics when the activation POST fails** (#243).
  `Verify` reused one `resp` variable for both HTTP requests. The GET registered
  `defer func() { _ = resp.Body.Close() }()`, which closes over the **variable**;
  a failed `client.Post` then assigned `nil` to that same variable and returned,
  so the deferred close dereferenced the nil POST result instead of the GET's.
  Every transport failure on the activation request crashed the goroutine rather
  than returning the error four lines above it.

  `Verify` connects to a host named by the challenge, so the peer chooses when
  to drop the connection. The activation response now has its own variable.

  It was found by making `TestVerify_PostError` deterministic: the test raced a
  50ms sleeper against `Verify`'s two requests, so it usually failed the GET and
  returned early, never reaching the line that panics. The flaky test was hiding
  the defect it was named for.
- **Security**: bumped `google.golang.org/grpc` to v1.83.1 across all four
  modules, closing CVE-2026-84304 (HIGH). Trivy flagged it in the published
  `xkms-cli` image, failing the Docker gate on `main`. (#258)

- **Key import no longer silently destroys an existing key** (#165).
  `SoftwareBackend.importAsymmetricKey` and `importSymmetricKey` wrote key
  material with `storage.SaveKey`, a plain Put, so importing under the
  attributes of a key that already existed replaced it and reported success.
  Generation had always refused the same collision. For an asymmetric key the
  loss was unrecoverable: every certificate issued against the old public key
  is orphaned and anything the key protected becomes undecryptable.

  Both import paths now refuse the collision with `backend.ErrKeyAlreadyExists`,
  matching what the symmetric key provider's own `ImportKey` already did.
  Replacing a key is an explicit delete followed by an import.

  **Operational impact.** An import that previously overwrote now fails. Any
  workflow that relied on import-as-replace must delete the key first.

  The presence check reads the key rather than calling `storage.KeyExists` or
  `storage.SaveKeyIfAbsent`, because neither is usable across the storage
  engines this backend runs on: `Exists` returns true for a key that was never
  written on the file, pebble and qrdb engines, and `PutIfAbsent` fails on
  those same engines with `embedded: TransactionServicer must not be nil`.
  Both are pre-existing storage-layer defects, filed separately; `Get` is the
  one primitive that separates present from absent on every engine.

- **CTAP2 request authorization: pinUvAuthToken permissions and lifetime are
  enforced, the UP and UV flags no longer assert interactions that did not
  happen, and the excludeList no longer answers before the user presence gate**
  (#213, #214, #217). All paths `xkey/pkg/authenticator/` unless noted.

  **pinUvAuthToken permissions (#213 A).** `handleGetPinUvAuthTokenUsingPinWithPermissions`
  and its UV variant recorded `tokenPermissions` and `tokenRPID`, and nothing on
  the makeCredential or getAssertion path ever read them — `tokenRPID` had no
  non-test reader anywhere in the repository. Both commands verified the HMAC
  alone, so a token minted with `permissions = ga` and `permissionsRPID =
  "benign.example"` authorized registration and assertions at **any** RP after a
  single PIN entry. Both now call the new
  `Authenticator.AuthorizePinUvAuthToken`, which checks the required permission
  bit (`mc` / `ga`) and the permissions RP ID and answers every failure with
  `CTAP2_ERR_PIN_AUTH_INVALID`. A token minted without a permissions RP ID is
  bound to the RP ID of its first use, per CTAP 2.1 §6.1.2 and §6.2.2. The
  superseded `getPinToken` subcommand now explicitly grants `mc` and `ga` with
  no RP binding (§6.5.5.7.1) instead of leaving the previous token's permissions
  and RP binding in place.

  **pinUvAuthToken lifetime (#213 B).** The token had no timers and was cleared
  only by `authenticatorReset` or by being overwritten, so one PIN entry
  authorized unlimited commands for the life of the process. It now carries the
  CTAP 2.1 §6.5.2.1 usage timers — 30 seconds of inactivity and a 10-minute cap
  from issuance — and is discarded once either elapses. A token installed
  without going through the minting path is treated as expired rather than as
  valid forever. The timers apply to every command a token authorizes, so
  credential management (`cmd_credmgmt.go`) and authenticator config
  (`cmd_config.go`) refuse an expired token too.

  **Fabricated UV (#214 H).** The `InternalPINHash` path compared the stored PIN
  hash against a value its only caller had read back out of the same
  authenticator (`xkey/pkg/gui/services/autofill_service.go`), so the
  constant-time comparison was `x == x`. It always succeeded and set the **UV
  flag**, telling the relying party a human had verified themselves when no one
  had. `InternalPINHash` is now what it always was — an in-process trust marker
  that gets a caller past the "a PIN is set, so present a `pinUvAuthParam`"
  precondition. It never sets UV and never satisfies the user presence gate,
  which now runs for these callers as it does for any other.

  **Go-API user presence (#214 G).** The Go API `MakeCredential` gated presence
  on `!pinAuthValid` while the CBOR path gated on `(!pinAuthValid ||
  RequireUserPresence)`, so with valid PIN auth the Go API skipped the gesture
  even when `RequireUserPresence: true` — and then set `FlagUP` unconditionally.
  Both paths now use the same condition, and `FlagUP` is set only when a
  presence test actually ran, the key backend collected presence itself, or the
  platform completed a PIN entry.

  **Shared user presence handler (#214 J).** `FIDO2DeviceService.Stop` installed
  an `AutoGrantHandler` on the **shared** authenticator, so toggling the virtual
  FIDO2 device off in the UI left the browser-extension credential path
  auto-approving every presence request for the rest of the session. `Start` now
  records the handler it replaced and `Stop` restores it.
  `Authenticator.SetUserPresenceHandler` takes the authenticator lock and
  returns the previous handler, and `requestUserPresence` reads the handler
  through it — the UI goroutine could previously mutate the interface value
  while the transport goroutine was reading it.

  **excludeList credential oracle (#217).** `checkExcludeList` ran before any
  presence or PIN gating and returned `CTAP2_ERR_CREDENTIAL_EXCLUDED`
  immediately, so any process that could reach the CTAP interface could test
  `(credentialID, rpId)` pairs at machine speed, with no prompt and no log
  entry, and enumerate which sites the user had registered with. The answer is
  now withheld until after the user presence gate and returned regardless of
  whether the user approved, per CTAP 2.1 §6.1.2, so a match costs the same
  gesture and takes the same observable path as an ordinary registration. The
  check also honours `credProtect`: a level-3 credential stays invisible without
  user verification in the same transaction.

  **Operational impact.** A platform that mints a scoped pinUvAuthToken and then
  uses it for a command it did not request permission for, or at a different RP,
  now gets `CTAP2_ERR_PIN_AUTH_INVALID` and must run the clientPIN ceremony
  again; a token idle for more than 30 seconds is refused the same way. Browser
  extension autofill assertions now report UV as absent, because that path
  collects a user presence gesture and never user verification — there is no
  in-process path that collects a real PIN entry, so a UV-carrying autofill
  assertion would have to be fabricated to exist.

  `pkg/autofill`'s `AssertionVerifier` therefore gains
  `NewAssertionVerifierWithOptions` and `VerifierOptions{AllowMissingUV: true}`,
  which xKey's in-process autofill service uses. **`NewAssertionVerifier` is
  unchanged and still requires both UP and UV**, as does the zero
  `VerifierOptions`: the type is re-exported through `sdk/go` and downstream
  consumers verify assertions from real authenticators, where UV is a genuine
  claim that a human verified themselves. Every field on `VerifierOptions` names
  the check it relaxes, so a caller who does not think about the struct gets the
  strict posture.

- **TPM and JWK ECDSA public keys are now validated as points on the curve**
  (#226). `pkg/tpm2` reconstructed `ecdsa.PublicKey` values from TPM ECC public
  areas by assigning the raw `X` and `Y` coordinates straight into the struct,
  across 11 sites in 8 production files; `pkg/encoding/jwk` did the same for
  the `x`, `y` and `d` members of an EC JWK. Assigning raw coordinates performs
  **no validation at all**: a point that is not on the curve, or the point at
  infinity, was accepted silently and then used as an EK, SRK, IDevID, IAK or
  attested-key identity. A broken, emulated or hostile TPM could therefore have
  an off-curve point accepted as an attestation identity.

  All of them now route through the new `pkg/crypto/ecpoint` helper, which
  assembles the SEC 1 uncompressed encoding and parses it with
  `ecdsa.ParseUncompressedPublicKey` / `ecdsa.ParseRawPrivateKey`. Those
  parsers reject an off-curve point and the point at infinity. Failures surface
  as `tpm2.ErrECCPublicArea` (wrapped as `ErrCertifyMalformed` on the certify
  path) and as `ecpoint.ErrInvalidPoint` / `ErrInvalidScalar` / `ErrCoordinateTooLong`,
  which remain reachable through `errors.Is` at every caller.

  **Operational impact.** This is a behaviour change on a security-critical
  path: a reconstruction that previously "worked" can now return an error.
  Anything that reports an invalid point was already producing a key that could
  not verify a signature, so an operator who sees `tpm2: ECC public area does
  not yield a valid public key` is looking at a device or emulator fault, not a
  new restriction — the EK / SRK read, IDevID and IAK issuance, TCG-CSR
  verification, `TPM2_Certify` verification and the attestation profile now fail
  loudly at the point of reconstruction instead of downstream at signature
  verification, or not at all.

  `pkg/crypto/ecpoint` **left-pads each coordinate to the curve's field size**
  before parsing. `TPM2B_ECC_PARAMETER` buffers and JWK members are not
  required to carry leading zero bytes, so a coordinate whose high byte is zero
  arrives short — roughly one in 256. Assembling `0x04 || X || Y` from those
  buffers without padding rejects perfectly valid keys, intermittently; this is
  the same failure mode fixed for the PKCS#11 EC point in #191. P-256, P-384
  and P-521 each have an explicit short-buffer regression test built from a
  deterministic fixture rather than a random key, because a round-trip test
  using only random keys passes ~99.2% of the time and hides it.

  One further hardening on the JWK path: `ToPrivateKey` now derives the public
  key from the `d` member and refuses a JWK whose `x`/`y` describe a different
  point, instead of returning an `ecdsa.PrivateKey` whose `PublicKey` field
  contradicts its own scalar.


- **`golang.org/x/crypto` v0.55.0 -> v0.56.0 across all four modules** (#201).
  Clears GO-2026-6355 and GO-2026-6354, both reachable from this repository —
  govulncheck names the trace as `pkg/ssh/session/dial.go:217:50`,
  `session.DialClient` calling `ssh.NewClientConn`. The failure was
  deterministic, so it turned Security Scan red on `main` and on every open PR
  simultaneously.

### Fixed

- **Two pre-existing test defects that reddened the `Race Detector` job at
  random** (#339, #340). `pkg/server/unified_api_e2e_test.go`,
  `pkg/acme/client/preauth_test.go`.

  Both are test-only, and neither belonged to the PR each was blocking. #311
  was investigated as a suspected race in its own reload path before the job
  log showed zero `DATA RACE` reports and a port-bind failure in a package
  that PR does not touch — `git diff origin/main <branch> -- pkg/server/`
  is empty.

  **#339 — the port helper reserved nothing.** `freeLoopbackPort` bound an
  ephemeral port, read the number and closed the listener before returning,
  under a comment calling the result "the small reuse race is acceptable
  in-process". Measured, it is not: 24 concurrent allocators with a 2 ms gap
  between allocation and bind produced 12 collisions in 4800 attempts on an
  idle host, each the `bind: address already in use` that failed CI — and on
  a loaded runner the gap is the whole of TLS material generation and qrdb
  node composition, not 2 ms. The helper is replaced by a reservation that
  holds all four listeners until the statement before `New` composes the
  server. The same measurement against the replacement is 0/4800.

  Handing the server a `net.Listener` would close the window rather than
  shrink it, and is the better fix where it exists. It does not exist here:
  only the legacy REST path has that seam, while the gRPC, QUIC and MCP ports
  reach the embedded qrdb node as port numbers in its configuration — and MCP
  is the port that actually collided. A retry loop around the bind was
  rejected as hiding the window rather than shrinking it.

  **#340 — a genuine data race in an ACME test.** `PreAuthorizeMany` processes
  identifiers concurrently, one goroutine each, so the mock server's handler
  runs on several `httptest.Server` connection goroutines at once. The test
  wrapped that handler in a closure incrementing a plain `int` and writing
  four `authzFail*` fields, while `handleNewAuthz` read them — unsynchronised
  on both sides. The counter becomes an `atomic.Int64`; the four fields move
  behind a mutex and are read as one snapshot, so a caller cannot pair a new
  status with a stale detail. **The concurrency itself is untouched** — it is
  what the test exercises.

  **What this does not establish.** The #340 race did not reproduce on the
  development host in 420 runs under `-race`, including 400 at `-cpu=16`. The
  evidence that it is real is CI's own race report, naming both goroutine
  stacks inside the wrapper handler, plus the source: concurrent writers and
  an unsynchronised reader. The repeated green runs after the fix therefore
  confirm nothing was broken; they are not the proof that the race is gone.

- **`xkms.Initialize` validates the backend names it is configured with**
  (#174). `Initialize` assigned `config.Backends` and `config.KeyProviders`
  verbatim and never checked their keys, while `RegisterServiceBackend`
  validated every name it was handed and `LookupBackend` validates on every
  lookup. So the single-registration path was guarded and the bulk entry point
  — exported to embedders as `ServiceInitialize` — was the one way to install a
  name no other path would have admitted.

  Both maps are now validated against `validation.ValidateBackendName` before
  anything is registered, with a typed `ErrInvalidBackendName`. A key provider
  is addressed by name exactly as a backend is, so validating only the one map
  would have left the gap half open.

  Because the canonical charset is lowercase, this makes the fold-collision
  #174 is named for **unconstructible** rather than merely unlikely: two names
  differing only by case cannot both be valid. Downstream code that compares
  backend names case-insensitively — `pkg/api/mcp`'s import guard does — can no
  longer be pointed at the wrong backend by registering `hsm-a` and `HSM-A`
  together.

  **This is a behaviour change on SDK surface.** `sdk/go/embedded.go` passes a
  caller's `BackendName` straight into `Initialize`, so an embedder using an
  uppercase, underscored or whitespace-padded name now receives a typed error
  where it previously succeeded. That is the gap this fix closes, and the name
  it refuses is one every other entry point already refused, but it will be
  visible to a consumer that had been relying on the unguarded path.

  A backend name is a **registry key, not a store-type keyword**: `token-a` and
  `hsm-a` are legal names that `types.ParseStoreType` maps to `StoreUnknown`,
  and a test pins that they stay registrable and resolvable. Conflating the two
  is a separate defect, filed as #297.

- **`pkg/server`'s backend factory resolves its default deterministically**
  (#174, #173). `backend_factory.Initialize` computed the default by ranging
  the backend map and taking the first entry, which reads Go's randomized
  iteration order. It also computed a **non-empty** default before calling
  `xkms.Initialize`, so the deterministic rule added there never ran for this
  caller, and it silently substituted a backend when the configured default was
  absent — pre-empting `ErrDefaultBackendNotFound` and turning a configuration
  typo into a randomly chosen store rather than a startup error.

  It now calls `xkms.ResolveDefaultBackend`, matching `server.go`'s own service
  construction: the requested name when loaded, then software, then the first
  name in sorted order.

  **`server.Initialize` has no in-repo caller** — every reference outside its
  own definition is a `_test.go` file, which is what #173 reports and proposes
  deleting the function over. So this repairs a path the daemon does not take:
  the live construction is `server.go`, which already resolved deterministically.
  It is fixed rather than left because the function is **exported**, so an
  external importer can reach it — the same reasoning #174 itself makes, that
  "no in-repo caller" answers whether the daemon does it and never whether a
  consumer can. Whether to delete it instead is #173's call, not this change's.
- **The KDF hash sets now report what the process can actually compute** (#292).
  `kdfAlgorithmBridge.hash` admitted a hash on `crypto.Hash.Available()`, which
  reports **linkage**. Under `GODEBUG=fips140=only` Go keeps a refused digest
  linked and lets `New()` succeed, then **panics on the first Write** — so
  deriving with X9.63/SHA-1 killed the process instead of returning an error.

  Lookups now go through the new `types.HashUsable`, and a hash the runtime
  will not compute is refused with the existing `ErrUnsupportedKDFHash`.

  **Neither `Available()` nor a FIPS predicate is correct here**, which is why
  this probes instead. Measured on go1.26.7:

  | mode | `fips140.Enabled()` | `SHA1.Available()` | SHA-1 Write+Sum |
  |---|---|---|---|
  | (none) | false | true | ok |
  | `fips140=on` | **true** | true | **ok** |
  | `fips140=only` | true | true | **panic** |

  `Available()` is true in every mode, so it cannot see the refusal.
  `fips140.Enabled()` is true under **both** `on` and `only`, but SHA-1 works
  under `on` — gating on it would withdraw a digest the process can compute.
  There is no exported predicate for `fips140=only`, so `HashUsable` hashes one
  byte behind a `recover`, once per digest, and caches it. The probe is the same
  operation the caller is about to perform, so it cannot disagree with it, and
  it keeps working if the standard library later refuses a different digest.

  This narrowing is deliberately **mode-dependent**, which is the opposite of
  the JWK thumbprint decision in the same issue — and the difference is what
  each one is. A thumbprint becomes a stored artifact, so a mode-dependent
  answer would let one process mint what another cannot recompute; a hash set
  is a *capability report*, and capabilities genuinely do differ by mode. Nothing
  is lost by narrowing it: under `fips140=only` a SHA-1 derivation could never
  have succeeded, so this converts a process-killing panic into a typed refusal
  rather than removing a working option. Nothing in this repository persists a
  KDF hash choice — the persisted key metadata records no hash at all — so there
  is no stored record to invalidate.

  **The `kdf.go` doc claim is corrected** in the same change. It asserted
  "SHA-1 is an approved KDF hash per SP 800-56A Rev.3 and SP 800-131A Rev.2",
  which is true of the **standards** and false of what the **runtime** permits.
  Both statements now appear, distinguished.

  Two tests that encoded the old contract are updated:
  `TestKDFBridges_EveryAdvertisedHashDerives` now means "every hash the bridge
  *reports*", and `TestKDFHashSets_AreIndependentOfWeakHashPolicy` asserts the
  property it is named for — the same answer for both policy values — rather
  than "SHA-1 always derives", which was only ever true of a non-FIPS process.

  **`pkg/types` still fails under `GODEBUG=fips140=only`, for reasons that are
  not this defect**, and that is worth stating so a red package is not read as
  unfinished: four weak-hash and legacy-key-wrap policy tests fail, each of them
  independently confirmed to fail the same way on unmodified code. Panics are
  down from one to **zero** — which is why one of the four is newly *visible*:
  the panic used to abort the binary before it ran.
- **`pkg/api/rest`'s WebAuthn session tests no longer assert on wall-clock
  timing** (#287). `TestWebAuthnStores_StartCleanupRoutine` slept 150ms and
  required that a goroutine on a 60ms tick had fired *and* that a 50ms TTL had
  elapsed. Go promises neither. It failed `CI / Unit Tests` on PR #267, whose
  diff touches no file in `pkg/api/rest` — the fourth unrelated PR felled by
  this class.

  Its own comment stated the assumption it could not establish: *"We can't
  directly check the count, but the cleanup ran"*. It now waits on the **event**
  — `MemorySessionStore.Count()` reaching zero, through a `waitFor` helper with
  a generous 30s deadline — so it asserts the cleanup having run rather than a
  duration during which it probably ran.

  **The cleanup test deliberately keeps real time.** The routine ticks on a real
  `time.Ticker`, so a fake clock would stop the session ever expiring by the
  routine's reckoning and the test would wait for an event that cannot happen.
  What was wrong there was the synchronisation, not the clock.

  Two neighbours did need the clock, and one of them was **unsafe in the
  direction a wider bound cannot fix**: `TestWebAuthnStores_SessionStore` saved
  a session with a 100ms TTL and required a `Get` two statements later to
  succeed. That fails whenever the machine stalls between them, and widening the
  TTL only pushes out the sleep the same test needs for its expiry half. Both it
  and `TestWebAuthnStores_CleanupSessions` now advance an injected clock.

  The package's fourth sleep, in `auth_tls_test.go`, was audited and left alone:
  it is inside a poll-with-deadline helper, which is already the correct shape.

  Each fix was checked for discrimination rather than assumed: stubbing the
  cleanup routine to do nothing makes the routine test fail (after its deadline,
  with the reason named), and disabling expiry makes the other two fail. Verified
  under `-race` with `-count=5` and `-shuffle` across four seeds on a machine
  with all 24 cores saturated. The three tests drop from ~400ms of sleeping to
  0.05s.
- **A key ID may no longer contain the identifier separator, and there is one
  validator for what a key ID is** (#168, #169). `KeyAttributes.ID()` joins its
  fields with `':'` and the storage parser disambiguates purely by segment
  count, so a colon inside a key ID shifted every field after it: `"a:b"` was
  written as `software:tls:a:b:rsa` and read back with `CN == "b"`. The key was
  stored, listed under a name the caller never asked for, and unreachable by
  `get_key` or `sign` — the operation reported success and wrote something
  nothing could find.

  Three exported `ValidateKeyID` functions disagreed about what a key ID is.
  `pkg/validation` and `pkg/api/rest` carried byte-identical patterns
  maintained separately — agreeing by coincidence rather than construction, and
  the REST copy's doc comment had already drifted, describing "alphanumeric,
  dash, underscore, dot" while its pattern also permitted the colon. REST now
  delegates to `pkg/validation`, which is the single definition; its doc
  comment is corrected.

  **The extended format is unaffected, because it was never a key ID.**
  `backend:type:algo:keyname` is a key REFERENCE, and
  `validation.ValidateKeyReference` splits on colons *before* delegating to
  `ValidateKeyID` — so the extended form never reached the simple validator
  with a separator still attached. Excluding the colon costs the feature
  nothing and additionally refuses a separator buried inside a reference's
  keyname component, which would shift the identifier the same way.

  **The refusal is at the service layer, not only the transports.** Tightening
  the transport validators fixes REST, which calls them. It does not fix MCP:
  `handleGenerateKey` checks only that `key_id` is non-empty, and
  `XKMSService.GenerateKey` does the same before handing the value to
  `buildKeyAttributes`, which assigned `CN` verbatim — neither `pkg/api/mcp`
  nor `pkg/xkms` called a key-ID validator at all. So the path #169 measured,
  and the one callers use most, crossed no validator. The guard now sits where
  the CN first becomes an identifier segment, which every method crosses,
  rather than in each handler that would otherwise have to remember. It applies
  to the import builder too. Failures are `ErrKeyIDValidation`, unwrapping to
  both `ErrInvalidKeyID` and the validator's own constraint.

  **Compatibility.** A key ID containing `':'` produced a key that was stored,
  listed under the wrong name and unreachable, so no caller can have depended
  on the behaviour — it did not work. Nothing in the tree creates a key under
  such a name, and the full `pkg/xkms`, `pkg/api/rest`, `pkg/api/mcp` and
  `pkg/validation` suites pass unchanged. One existing REST test asserted the
  colon was accepted; it encoded the defect and now asserts the refusal.

- **The `pkg/acme/client` DNS tests no longer query the public internet**
  (#243). Ten call sites across four files resolved real domains — `google.com`,
  `example.com` — or queried `8.8.8.8` through the global resolver, inside the
  `Unit Tests` gate. That made a gate depend on DNS reachability from the
  runner: it fails on any hiccup, on an air-gapped runner, and on any host with
  egress filtering, and it always looks like a defect in whatever PR happens to
  be running.

  Every assertion is preserved — an unmatched value is still
  `ErrDNSRecordNotPresent`, a failed nameserver lookup is still wrapped with
  "failed to get authoritative nameservers" — but the dependency and the
  multi-second network timeouts are gone. The four tests that asserted
  "`google.com` has nameservers" now assert what the code actually does with a
  supplied resolver, which is strictly more coverage than measuring a third
  party's DNS.

  Verified by building the test binary and running it inside a network
  namespace with only loopback (`unshare -rn`): every converted test passes
  with no network at all.

  **Two classes are NOT fixed here**, both recorded on #243 with the same
  measurement:

  - **`route53` zone discovery** (six tests) is not reachable from this seam.
    It goes through `providers.FindZoneByFQDN`, a different package with its
    own query path and a package-global zone cache; closing it needs a seam in
    `providers` affecting every DNS provider.
  - **Six tests in `cross_sign_test.go` call Let's Encrypt production.** Each
    builds an `httptest` server and passes its URL, so the intent is local, but
    the `acme.Client` carries no `DirectoryURL` and `golang.org/x/crypto/acme`
    then defaults to `acme-v02.api.letsencrypt.org`. That is an outbound HTTPS
    call to a third party's production service from the unit gate. It needs no
    API change to fix and is the cheapest of the three.
- **The DNS-01 provider zone-discovery tests no longer query the public
  internet** (#243). Eleven tests — six in `route53`, five in `clouddns` —
  climbed the real DNS tree for a SOA record on `google.com`, inside the
  `Unit Tests` gate.

  Unlike the other classes on this issue, this one was **deliberate**: the tests
  say so, "using real DNS lookups for well-known domains". So this is a design
  change, not a repair of an oversight, and the seam above is the design.

  The fixtures are unchanged — the mocks still describe `google.com` zones and
  the assertions still expect them — so each test proves exactly what it proved
  before. Only the resolution step is local.

  `azure` calls `FindZoneByFQDN` too but its tests never reach that path, so it
  needed no change; the seam is available if that changes.

  Verified with `unshare -rn`: `route53`, `clouddns`, `azure` and `providers`
  all pass with no network. Ordering was verified rather than assumed, since the
  package-global zone cache made it a live variable: each affected test passes
  alone, under `-test.shuffle` across five seeds, and under `-count=5`. As the
  decisive check, they also pass with **every `ClearZoneCache()` call removed**,
  which is what proves the cache bypass is structural rather than a convention
  the next test author has to remember.
- **The timing-sensitive `pkg/acme` tests are deterministic** (#243). They
  asserted on wall-clock behaviour the runtime does not guarantee — `time.Sleep`
  promises a minimum and never a maximum — so under `-race` on a shared runner
  they measured the machine. They reddened three PRs that do not touch
  `pkg/acme`, which trains people to re-run red until it goes green.

  - **`NonceStore` and `PersistentNonceStore` take a clock** (`WithClock`, and a
    `now` field respectively; both default to `time.Now`, so production is
    unchanged and a bare struct literal still works). Eight expiry tests now
    advance a fake clock instead of sleeping. `TestNonceStore_ExpirationPrecision`
    is the clearest case: it slept 80ms and asserted a 100ms TTL had not
    elapsed, which is an assertion that the machine stayed idle.
  - **`TestVerify_PostError`** serves the GET and then hijacks and closes the
    POST's connection, so the transport error it is about happens on the request
    it is about, every time — instead of racing a sleeping goroutine.
  - **`waitFor` / `waitForListener`** replace "sleep and hope the server came up"
    in `pkg/acme/client`. The deadline is deliberately generous (30s), which
    makes it a hang detector rather than a second coin flip.

  `pkg/acme/common` drops from 6.9s to 1.6s, because five seconds of it were
  literal sleeping. Verified by running the affected tests 30x (nonce) and 15x
  (enroll-01, client) under `-race` with all 24 cores saturated.

  Not addressed here, and a different defect: several tests resolve **real
  public domains** through the global resolver — `TestCheckDNSFromAuthoritative_Success`
  and its two neighbours in `pkg/acme/client`, plus the `route53` zone-discovery
  tests. That makes a gate depend on the public internet. Fixing it needs a
  resolver seam through `getAuthoritativeNameservers`, `CheckDNSFromAuthoritative`,
  `CheckDNSFromPublic` and `providers.CheckDNSPropagation` — a cross-package
  change to exported API, so it is reported rather than guessed at.
- **The ACME cross-sign tests no longer call Let's Encrypt production** (#243).
  Seven tests in `pkg/acme/client/cross_sign_test.go` made an outbound HTTPS
  request to `acme-v02.api.letsencrypt.org` on every unit run, from every
  branch.

  Nobody chose this. Each test already builds an `httptest` server and passes
  its URL, so the intent was plainly local — but the `acme.Client` was
  constructed with only a `Key`, and `golang.org/x/crypto/acme` falls back to
  Let's Encrypt when `DirectoryURL` is empty. It was a missing field, not a
  design, and the correct pattern already existed four times in the same file.

  Each test's handler now serves `/directory` and `/new-nonce`, and its client
  sets `DirectoryURL`. No production code changed and no API changed.

  **`TestProcessAuthorization_GetAuthorizationError` was passing for the wrong
  reason**, which is why it did not show up as a failure: it asserts an error,
  and the error it received was the DNS lookup for Let's Encrypt failing, not
  the rejected authorization it is named for. Its handler 404'd every path
  including the directory; it now answers the directory and nonce normally and
  404s only the authorization, so it fails for the reason it claims.

  This mattered in three directions: it could fail for reasons unrelated to
  this repository, with a remote party controlling the outcome; it put
  unsolicited CI load on a third party's production API, which is how an
  organisation's egress address gets blocked and real issuance breaks; and
  `CLAUDE.md` requires third-party API calls to be mocked.

  Verified by building the test binary and running it inside a network
  namespace with only loopback (`unshare -rn`): all seven pass with no network.
  That check is the only one that answers the question — reading the code does
  not, since the dependency is a library default rather than anything visible
  at the call site.

- **MCP key import now receives the key material** (#159).
  `pkg/api/transport/mcp.Transport.ImportKey` marshalled a
  `transport.ImportKeyRequest` straight onto the wire, but the handler decodes
  `pkg/api/mcp.ImportKeyParams`, and the two disagreed on the field carrying
  the key: `wrapped_key_material` against `wrapped_key`. `WrappedKey` was
  therefore `nil` on every import over that transport, which has never
  functioned. `aes_key_size`, `hash` and `partition` were dropped with it, so a
  symmetric import failed on a zero key size and any requested digest or
  partition was discarded.

  The transport now builds `ImportKeyParams` field by field, which links the
  two structs at compile time, and the params struct gained the three missing
  fields. The wire name stays `wrapped_key`, the vocabulary every other params
  struct on this transport uses. A contract test asserts the two structs still
  describe the same field names, with `tenant_id` recorded as the one
  deliberate exception -- this transport's handlers take the tenant from the
  authenticated caller rather than from the wire.

  An audit of the sibling methods, which #159 asked for, found the same class
  of mismatch in `WrapKey` (`wrapping_public_key` against
  `wrapping_public_key_pem`, plus `backend` and `key_spec` dropped) and
  `UnwrapKey` (`wrapped_key_material` against `wrapped_key`, plus `backend` and
  `key_spec`). Both are filed separately rather than fixed here.
- **xkey CLI: `auth` now reads the xKey trust store, and gained `--tls-ca`**
  (#250). `xkey trust add` populated a store the `auth` HTTP client never
  opened: `defaultAuthClientFactory` built its TLS configuration from the SPKI
  pin alone, so an operator whose CA was sitting in `xkey trust list` — with an
  independently valid chain — still could not connect, and the error named
  certificate trust rather than the fact that the store was never consulted.
  `--spki-pin` was the only route to such a server, which is pinning, not CA
  trust.

  `auth register` and `auth login` now build the client's `*tls.Config` from
  the system roots, the xKey trust store, and a new `--tls-ca` PEM bundle.
  A bare `--spki-pin` is unchanged and still trust-on-first-use: with no
  `--tls-ca` on the same command line the pin remains the sole trust anchor and
  no chain is built, so an unrelated certificate in the store cannot break a
  working pinned invocation. Named together with `--tls-ca` the pin is additive
  on top of chain validation — via the new `xkms.VerifySPKIPinnedConnection`
  SDK re-export — rather than silently discarded, which is what passing a
  caller-built `*tls.Config` to the REST transport would otherwise do.

  The session login plane had the same gap and is fixed with it:
  `auth login --piv`, `auth refresh` and `auth logout` built their
  `xkms.LoginClient` with the recorded pin and a nil `RootCAs`, so an unpinned
  server fell back to the system store alone. They now supply the same pool
  when the registry entry carries no pin; a pinned entry is unchanged, since
  `LoginClientConfig` ignores `RootCAs` whenever `SPKIPin` is set.

- **xkey CLI: `unlock` no longer reports success while the daemon is still
  locked** (#250). Two fail-opens stacked. The IPC dispatcher stamped
  `StatusOK` on every unlock whose handler returned a nil Go error, but the GUI
  and headless handlers report a refusal *in band* as
  `UnlockResult{Success: false}` with a nil error — so a refused unlock reached
  the client indistinguishable from a granted one. `runUnlock` then read only
  the transport status, never `UnlockResult.Success`, and printed `Unlocked`.

  The dispatcher now maps the result onto the status (`ErrUnlockRefused`,
  `ErrUnlockNoResult`), and `unlock` takes success from the result rather than
  the transport, then **confirms it**: it queries the daemon's status and exits
  non-zero with `ErrUnlockStillLocked` when the daemon reports itself locked
  after granting the unlock. A daemon that owns no app lock confirms nothing,
  and the command says so instead of implying it checked. `headlessHandler`
  and `guiIPCHandler` now report the real lock state as the new
  `ipc.ActionLocked` / `ipc.ActionUnlocked` actions, so `xkey unlock` and
  `xkey fido2 status` agree.

  This mattered well beyond the wrong exit code: an automated ceremony built on
  the false success failed much later with the authenticator's
  `MakeCredential: operation denied`, which reads as a user declining a touch.
  The real cause was a lock the whole time.

- **xkey CLI: `trust add` reports skipped certificates** (#250). `trust add
  --help` promised that already-present certificates are "silently skipped and
  reported separately"; nothing was reported, so `Certificates added: 0` was
  indistinguishable from a parse failure, an empty file, or a permissions
  problem. `addPEMWithOptions` now returns an added and a skipped count and the
  command prints both, and a file that yields no certificate at all is
  `ErrTrustNoCertificates` rather than a silent zero.

- **xkey CLI: `auth register` reuses the SPKI pin it recorded** (#250,
  measured after the issue was filed). `auth login` reused the pin on the
  server entry; `auth register` did not, because it built its client before it
  ever opened the registry. A second registration against a server whose CA is
  outside the system trust store therefore failed the handshake with the same
  `x509: certificate signed by unknown authority` unless `--spki-pin` was
  passed again — while `auth status` displayed the fingerprint on the entry.
  Register now looks the entry up first and falls back to its recorded pin. An
  explicit `--spki-pin` still overrides it, and a stale recorded pin still
  refuses the connection rather than accepting whatever the server presents.

- **xkey CLI: only TLS-eligible trust-store purposes anchor a TLS chain**
  (#250). The auth path trusted every certificate in the xKey trust store.
  The store also holds TPM manufacturer roots, Android hardware attestation
  roots and IDevID issuers, which anchor DEVICE ATTESTATION chains; a TLS
  session to a server is not one, and trusting them here let a TPM vendor root
  authenticate an xkms server — a wider grant than the operator made when they
  imported it for attestation. The pool is now built from the new
  `truststore.TLSRoots`, which selects `user-ca`, `bootstrap-ca` and `general`.

- **xkey CLI: `unlock` names the subsystems it released** (#250). The daemon's
  status action reports the app lock and nothing else, so it cannot express a
  PIN that releases the app lock without unsealing the barrier: status answers
  `unlocked` and the post-unlock confirmation passes. That is the state the
  reported ceremony ran in. `AppLockService.UnlockVerified` now observes every
  subsystem the lock governs before and after the attempt and reports the
  transition, so `ipc.UnlockResult` carries `unlocked` and `still_locked`.
  `unlock` prints `Unlocked: app lock, barrier` and fails with
  `ErrUnlockIncomplete` when a subsystem stayed locked, naming both halves. A
  daemon that does not report subsystems still gets the bare success line, so
  the richer report is additive. Both IPC bridges answer through the one
  service method and cannot drift.

- **xkey: one PEM import implementation** (#250). `addPEMWithOptions` was a
  CLI-local copy of the store's own import loop, which is how the two came to
  disagree about skip counting in the first place. `FileStore` and
  `BackendStore` now share `truststore.ImportPEM`; the copy is deleted, and
  `trust bootstrap` reports skips the way `trust add` does — re-running a
  bootstrap against an already-trusted CA is the common case, and
  `imported: 0` on its own reads as a failure.

- **MCP `wrap_key` and `unwrap_key` now reach the handler with the key they
  were given** (#255). `pkg/api/transport/mcp` marshalled a
  `transport.WrapKeyRequest` / `UnwrapKeyRequest` straight onto the wire, but
  the handlers decode `pkg/api/mcp.WrapKeyParams` / `UnwrapKeyParams`, and the
  structs disagreed:

  - **UnwrapKey** named the material `wrapped_key_material` on the request and
    `wrapped_key` in the params, so `WrappedKey` was `nil` on every call and the
    handler refused with `wrapped_key is required`. This is the #159 defect
    repeated character for character on the unwrap path.
  - **WrapKey** named the wrapping key `wrapping_public_key` (DER `[]byte`) on
    the request and `wrapping_public_key_pem` (PEM `string`) in the params, so
    the field was always empty and the handler refused with `invalid wrapping
    public key PEM`. This is not a rename: the two ends use different
    **encodings**, and assigning the DER across yields base64, which is
    non-empty and still fails `pem.Decode`. The transport now PEM-encodes.
  - Both dropped `backend` and `key_spec`. `key_spec` is load-bearing for
    key-spec aware backends such as AWS KMS.

  These were reachable from shipping code: `xkmsctl key wrap` / `unwrap`, and
  any SDK consumer selecting `ProtocolMCP`.

  All five import/export ops (`ImportKey`, `ExportKey`, `WrapKey`, `UnwrapKey`,
  `CopyKey`) now build the handler's params struct **by name** rather than
  marshalling the request, so a rename on either side is a compile error rather
  than a silent runtime drop. `ExportKey` already agreed and is converted for
  the same protection rather than to fix anything.

  **`backend` is now honoured, not merely carried.** Both handlers previously
  ran against the process-default keystore whatever the caller named. They now
  resolve a named backend through the tenant-scoped lookup, falling back to the
  configured keystore when none is named. A params field that arrives and is
  then ignored is the failure mode #160 warns about, so the tests assert on the
  wrap and unwrap **results**, which differ per backend, rather than on the
  field being set.

  `tenant_id` is deliberately still absent from these params: `tenantForRequest`
  returns `ErrTenantIDNotAccepted` for any supplied tenant, because the tenant
  comes from the authenticated identity.

  Not fixed here: `CopyKeyParams` carries `hash` and `aes_key_size` that
  `transport.CopyKeyRequest` cannot express, so no caller of this transport can
  populate them. That is #155 and needs a decision about whether the request
  struct gains them on every transport.
- **The absent-key storage contract is now executable, and the note describing
  it is no longer wrong** (#252). `storage.Backend` documents `Get` and
  `Delete` as returning `ErrNotFound` for a key that does not exist, and
  `Exists` as reporting whether a key exists. Four implementations disagreed,
  and nothing pinned the disagreement.

  `pkg/storage/storagetest` gains `RunAbsentKeyContract`, covering `Exists`,
  `Get`, `Delete` and `PutIfAbsent` on a never-written key, wired to
  `NewMemory`, `NewPrefixBackend`, `NewFile`, `NewPebble`, and the `file`,
  `luks`, `sealed` and `mocks` backends.

  It is a **characterization** suite, not a conformance snapshot. Pinning
  today's behaviour would have encoded the defect as the contract — "`Exists`
  returns true for a key that was never written" would become the blessed
  answer and fixing the engines would read as a regression. So the assertions
  state the correct semantics, and a backend that does not satisfy them yet
  declares it with `Config.AbsentKeyDivergence` (#252) or
  `Config.PutIfAbsentUnavailable` (#61). Those branches assert the wrong answer
  deliberately **and fail the moment it becomes right**, telling the reader to
  delete the flag — the same self-destructing design as
  `pkg/storage/qrdb/factory_cas_characterization_test.go`.

  **The `mocks.MockCertStorage` divergence the suite found on its first run is
  fixed here**, because it is this repository's own code and needs no upstream
  ruling: `Get` and `Delete` returned a bare `key not found: <key>` message
  rather than wrapping `storage.ErrNotFound`, so `errors.Is(err,
  storage.ErrNotFound)` was false against the mock. Any test that swapped a
  real backend for it took the wrong branch.

  **The note on `pkg/storage/constructors.go` was wrong about the blast
  radius** and is corrected. It said the transaction-service gap hit
  "uniformly, for memory, file and pebble alike". It does not: `NewMemory` —
  this package's `engineBackend` — conforms on all four verbs. The divergence
  travels with the **embedded QRDB client, not with the storage medium**, so
  `qrdb.NewMemory` diverges exactly like the two on disk while `NewMemory` does
  not. The comment now carries the measured table and both divergences, since
  it is the note a caller reads before choosing an engine.

  Not decided here, deliberately: which answer is correct is already settled by
  the interface documentation, but whether to fix the engines upstream or adapt
  in `engineBackend` is a go-qrdb call and stays open on #252.
- **Software backend: `validateKeyType` no longer blesses ECDSA/Ed25519
  mismatches** (#53). The validator checked RSA only; ECDSA and Ed25519 fell
  through a `default:` arm commented *"basic validation is sufficient"* — the
  fail-open comment pattern — so an **Ed25519 private key declared as
  ECDSA-P256 imported successfully**, exactly as a consumer measured. Those two
  are the algorithms the signing policy uses (ed25519 by default, ECDSA-P256
  under FIPS), so the unvalidated pair was the pair that mattered: everything
  downstream reasons from the declaration rather than from the key — the
  storage identifier, the reported key spec, the algorithm a later operation
  selects — and a key stored under a false description poisons all of them.

  Every supported key type now has an arm (RSA, ECDSA, Ed25519, X25519), public
  keys of every algorithm are refused rather than only RSA ones, and a key type
  no arm recognises is refused instead of admitted. The declared EC curve is
  deliberately **not** compared against the key's own: `PKCS8Backend.ListKeys`
  reconstructs attributes from an identifier that carries no curve and reports
  P-256 for every ECDSA key, so copy, migrate and `C_UnwrapKey` all reach the
  validator through attributes built that way and a curve comparison would
  refuse working paths rather than catch wrong ones (#156 carries the caveat
  and the `ListKeys` fix it needs).

  Surveyed the other backends that import asymmetric material: `azurekv` is
  already fail-closed by type assertion, `awskms` restricts asymmetric import to
  RSA, and `tpm2`/`pkcs11`/`gcpkms`/`phone` do not parse caller-supplied PKCS#8
  on this path. `software` was the outlier.

- **MCP `xkms.importKey` can name the algorithm of the key it imports** (#53).
  `ImportKeyParams` had no key-algorithm field — its `Algorithm` is the
  *wrapping* algorithm — so the handler built attributes from the key ID alone
  and imported through the process default backend. The key was stored under an
  identifier ending in `unknown` that nothing else constructs, and the backend's
  check of material against its declared type had nothing to check against. The
  tool now takes `key_type` (required), `key_size` and `curve`, the same fields
  and vocabulary the REST and gRPC imports already use, and routes through
  `XKMSService.ImportKey` so all three transports build key attributes in one
  place and the request's backend is the backend written to.

- **PKCS#11 `C_UnwrapKey` carries the curve the template names** (#53). The
  unwrap request never set `TargetCurve`, and the service substitutes P-256 for
  an empty curve, so every EC key unwrapped through the module reached the
  backend described as P-256 — stored under attributes that misstate the key
  and reported as `ECC_NIST_P256` by `determineKeySpec`. `CKA_EC_PARAMS` is now
  resolved through the same `extractCurveFromParams` that `C_GenerateKeyPair`
  uses, and a value the module does not recognise is answered with
  `CKR_CURVE_NOT_SUPPORTED` rather than silently defaulted. An absent
  `CKA_EC_PARAMS` stays legal — v3.2 Table 13 footnote 6 says an EC private
  key's must not be specified on unwrap — and leaves the previous behaviour
  unchanged.

- **`web/desktop` module pins are no longer stale** (#205). The release path
  enumerated three modules and this repository has four, so `web/desktop` was
  left on the pre-release tags by both v0.9.0-alpha and v0.9.1-alpha and `make
  vet` failed, taking `main` red on Lint. The durable fix for the release path
  itself is tracked separately.

- **PKCS#11: exporting an ECDSA public key no longer fails for 1 key in 256**
  (#191). `exportECDSAPublicKey` decided whether `CKA_EC_POINT` held a bare
  X9.62 uncompressed point or a DER OCTET STRING wrapping one by testing
  `ecPoint[0] == 0x04 && ecPoint[1] == len(ecPoint)-2`. `0x04` is both the
  OCTET STRING tag and the uncompressed-point marker, so the first half of that
  test is true of every bare point and the whole thing reduced to "does the
  first byte of X happen to equal len-2?" — 0x3f on P-256, 0x5f on P-384, which
  is 1 key in 256 on each. When it hit, two bytes of X were discarded as a
  phantom DER header and the export failed with `invalid EC point encoding`;
  which keys were affected depended only on the key, so the failure looked
  intermittent. (P-521 was never affected: its len-2 is 0x83 and the first byte
  of a 66-byte P-521 X never exceeds 0x01.)

  The encoding is now decided by length, which is exact rather than
  probabilistic: a bare point on a curve over a `byteLen`-byte field is always
  `1 + 2*byteLen` bytes, and any DER wrapper is strictly longer, so no content
  byte of a point can move it from one case to the other. The curve is already
  known from `CKA_EC_PARAMS`. An attribute value that is neither form now
  returns a typed `ErrInvalidKeyAttributes` naming what it found instead of
  falling through to a best guess.

  Affects any PKCS#11 module that stores `CKA_EC_POINT` unwrapped. No
  configuration change; the wrapped encoding is decoded exactly as before.

- **`cert_der` PIV factor metadata is decoded as base64** (#199 follow-up).
  `pkg/auth_factors.decodeCertificate` named its variable `derB64` but passed
  the value straight to `x509.ParseCertificate` with no decode. Because
  `AuthFactor.Metadata` is a `map[string]string` that round-trips through
  JSON, and raw DER is not valid UTF-8, `cert_der` was a form that could
  either be stored faithfully or parsed — never both — while
  `MissingChallengeFieldError{Field: "cert_pem|cert_der"}` advertised it as an
  equal alternative to `cert_pem`. A caller who followed that message got a
  PIV factor that resolved normally and failed verification at login. The
  value is now standard base64 of the DER, and the doc comment says so.

  Raw DER in `cert_der` is now **rejected** rather than accepted, deliberately:
  accepting both forms would restore the ambiguity the defect is about, and a
  raw-DER value that has crossed any encoded transport is already corrupted.
  Nothing in the stack emits `cert_der` — go-xkms's own PIV factor records the
  certificate as PEM in `Enrollment.PublicKey`, and go-quicbaas requires
  `cert_pem` — so the accepted form is now unambiguous and that downstream
  narrowing can be lifted.

- **`TestWithTimer_MeasuresDuration` no longer asserts a maximum on
  `time.Sleep`** (#243). The test required its measured elapsed time to land
  within 20ms on **both** sides of a 100ms sleep. `time.Sleep` guarantees a
  minimum and never a maximum, so the upper bound asserted a property Go does
  not provide: on a shared CI runner under `-race` it failed at 120.167ms,
  missing by 0.167ms, with nothing wrong in the code under test.

  It now asserts a lower bound only, which is the whole property `WithTimer`
  can guarantee — it brackets `fn()` with `time.Now()` / `time.Since`, so the
  recorded duration cannot be shorter than the work. A 30s ceiling remains
  purely as a runaway/hang detector, three orders of magnitude above the work
  so scheduling noise can never reach it.

  The test also now installs a recording adapter and asserts on the duration
  `WithTimer` actually **recorded**, with its name and tags. Previously it
  passed a bare context with no adapter, so nothing was recorded and a test
  named "MeasuresDuration" was really asserting that `time.Sleep` sleeps. A
  companion case covers the error path, where a failed operation's latency is
  exactly the latency an operator needs.

  #243 tracks this pattern in several packages; `pkg/acme` still owes the same
  treatment, so the issue stays open.


### Added

- **PIV slot-attestation verifier: `xkms.VerifyPIVAttestation` /
  `ParsePIVAttestation`** (#206). xkms produced attestation material that
  nothing in the stack could decode — `AttestPIVSlot` emitted the slot and `f9`
  certificates, and the only consumer-side check possible was that a chain
  anchored. Yubico's `1.3.6.1.4.1.41482.3` arc was not known to the repository
  at all.

  `pkg/pivcert` now parses the vendor extensions and returns their **values**:
  firmware version (`.3`), serial number (`.7`), PIN and touch policy (`.8`),
  and form factor (`.9`, high bit marking FIPS). A deployment can enforce
  *"touch must be required"*, *"this serial is on the allowlist"* or *"firmware
  at or above X"* — policies presence alone cannot express. Re-exported through
  `sdk/go` with a `PIV` prefix, alongside a builder so a consumer can construct
  synthetic attestation certificates for its own tests without reaching past
  the SDK.

  **Absent, unparseable and unrecognised are three distinct answers.** An
  extension that is not present leaves a nil field; one that is present and
  does not decode leaves a nil field *and* an entry in `Unparseable`; a value
  that decodes but is unknown to this build is returned with `Known()` false.
  Collapsing the first two would let "this device does not report touch policy"
  and "this device reports something I cannot read" reach the same verdict,
  when they warrant opposite responses.

  **Trust anchors are the caller's.** `AttestationVerifyOptions.TrustedRoots`
  is supplied by the caller and **no vendor root ships** — which root a
  deployment trusts is its decision, mirroring `pkg/attestation/android` where
  the embedded Google root is an opt-in offered separately rather than baked
  into verification. A nil or empty pool is an error, not a pass. Parsing
  performs no trust evaluation at all, so a deployment with no vendor root
  configured keeps its existing presence check rather than choosing between a
  full verdict and none.

  **Scope of validation, stated because a green test suite here does not
  establish it.** The layout is Yubico's documented one and has **not** been
  validated against a physical device; every fixture is built by this package's
  own encoder, which proves the parser and builder agree and nothing about real
  hardware. Decoding is therefore strict — exact lengths, exact ASN.1 types —
  and a mismatch is reported as unparseable rather than coerced, so a device
  that disagrees surfaces as "I could not read this" instead of a confidently
  wrong touch policy. A test builds the most likely alternative framing (each
  value inside an inner `OCTET STRING` rather than raw in `extnValue`) and
  asserts it yields unparseable rather than a plausible value; that test is what
  makes the limitation safe rather than merely disclosed. The limitation is
  recorded in `docs/piv-smartcard/engineering.md`, not only here.

  A nil error from the verifier means the **chain** verified, not that a policy
  is satisfied: a trusted chain may carry no readable claim, as a
  software-backed slot's self-signed certificate does. Callers must read the
  decoded field.
- **`webauthn.WithClock`** (#287) — an optional time source for
  `MemorySessionStore`, supplied to `NewMemorySessionStore` /
  `NewMemorySessionStoreWithTTL`. Variadic, defaulting to `time.Now`, with a
  usable zero value, so production behaviour and every existing call site are
  unchanged. `rest.WebAuthnStoresConfig` carries it through as `Clock`.
- **The FIPS-approved bootstrap suite is reachable through go-xkms** (#269).
  Noise_NK mandates X25519, which SP 800-56A Rev. 3 does not approve, so
  go-truststrap compiles its Noise DH out under the `fips` build tag and every
  entry point returns `ErrFIPSUnsupported`. A FIPS build had **no working
  bootstrap handshake at all**, and because consumers reach go-truststrap only
  through this repository, no released go-quicbaas could reach the approved one.

  `pkg/trust/bootstrap` and `sdk/go/bootstrap` gain a P-256 set mirroring the
  Noise set name for name — `P256StaticKey`, `GenerateP256StaticKey`,
  `NewP256StaticKey`, `Encode`/`DecodeP256StaticKey`, `P256HexKeySize`,
  `P256PublicKeySize` — plus the wire suite identifiers `SuiteNoiseNK` and
  `SuiteP256AESGCM`. The set is re-exported **complete** on purpose: the Noise
  set records what a partial one costs, having once exposed a generator and a
  config without the adapter joining them, so both halves compiled and could
  not be used together.

- **`EnsureSuiteAvailable`** (#269), with the `ErrSuiteUnavailable` sentinel —
  resolves a suite while a listener is being **configured**, so a build with no
  usable suite says so once and actionably at startup instead of binding a
  listener and refusing every handshake. That is go-trusted-platform#209's
  acceptance criterion.

  **It asks the library; it does not consult a FIPS predicate.** The obvious
  `if fips.Compiled()` is wrong for the reason recorded on the certstore
  thumbprint (#212/#219): `GODEBUG=fips140=off` turns that predicate false on a
  GOFIPS140-built binary, so such a guard fails **open** for exactly the
  artifacts the policy most cares about. Availability is instead derived from
  go-truststrap, whose Noise DH is selected by build tag — a compile-time
  property of the binary, read by attempting the operation and classifying the
  result, cached once per process. If upstream later supports Noise under some
  FIPS configuration, this answer changes with it, where a restated predicate
  would go stale.

  Pinned by a paired build-tagged test: `suite_nofips_test.go` asserts the Noise
  suite is available, `suite_fips_test.go` asserts it is refused with a typed
  error naming the approved alternative. The two assert opposite things, which
  is what proves the answer is derived from the build rather than guessed.

  **Not included: the suite selection mechanism.** Whether a consumer picks a
  suite by explicit configuration or by negotiation with a default is a protocol
  decision with an interop consequence, and is still open on #269. Everything
  here is correct either way.

- **PIV private-key import: `xkms.ImportPIVKey`** (#207). A PIV slot could be
  generated into or given a certificate, but an externally held private key
  could not be loaded into one. The SDK's only PIV write paths were
  `GeneratePIVKey` (key never leaves) and `StorePIVCertificate` (certificate
  only), so a consumer with an existing key had nowhere to put it — and the
  motivating downstream had been passing a **private key into the field named
  `Certificate`**.

  `ImportPIVKey` accepts PEM or DER in PKCS#8, SEC 1 or PKCS#1 encoding,
  detecting the encoding rather than requiring the caller to re-encode a key it
  already holds, and returns only the public half so the caller can confirm what
  the slot holds. A declared `Algorithm` is checked against the supplied key
  (`ErrPIVAlgorithmMismatch`) rather than trusted over it. A public key supplied
  where a private one belongs is refused (`ErrPIVKeyMaterialInvalid`) rather
  than stored into a slot that could never sign.

  Key material is **not handed to a backend in the clear**. xkms has exactly one
  import path — `GetImportParameters` / `WrapKey` / `ImportKey` — and the PIV
  verb reuses it rather than adding a second, plaintext one: the key is wrapped
  to a backend-issued wrapping key under a single-use import token and unwrapped
  inside the backend. The PKCS#8 encoding is wiped on every exit path. Import is
  reached through the same `KeyProvider().(backend.ImportExportBackend)`
  assertion that `xkms.ImportKey` already makes, so PIV import and generic key
  import reach a backend the one way rather than two.

  Capability is expressed by a new optional `PIVKeyImporter` interface,
  implemented completely by **both** production generators (software and
  backend-backed) in this change. It is deliberately *not* a method on
  `PIVKeyGenerator`: a real PIV applet may refuse import for particular slots or
  algorithms, and a generator that cannot honour it yields
  `ErrPIVImportNotSupported` so the refusal is reportable rather than mistaken
  for success.

  **Import establishes a different trust class from generation, and callers must
  account for it.** A slot-generated key cannot have existed anywhere before it
  existed in the slot; an imported one can, and no property of the slot
  afterwards distinguishes a key that was only ever there from a copy retained
  elsewhere. **An attestation over an imported key therefore asserts residency
  but not exclusivity**, and `VerifyChain` does not recover the difference — it
  anchors the attestation to a manufacturer, which establishes that the card is
  genuine, not that the key was born on it. Nothing in a PIV attestation carries
  the distinction today, so a relying party cannot ask for it: a deployment that
  needs exclusivity must generate in-slot rather than infer it from a verified
  chain. This is documented where a caller actually decides what to trust —
  `docs/piv-smartcard/{architecture,engineering,api,cli,user}.md` and
  `docs/ca/configuration.md`'s attestation-gate semantics.

  The verb is SDK-only and is on no network transport, because its input is
  private key material.

- **PIV key provenance, and an imported key is not attestable** (#207).
  `types.KeyOrigin` (`generated` / `imported`) records how a key arrived where
  it lives, and **`AttestPIV` now refuses a slot whose key was imported**
  (`ErrPIVKeyImportedNotAttestable`), returning no material.

  The refusal matches the hardware: YubiKey PIV attestation is already
  available only for slot-generated keys. Without it an xkms PIV attestation
  would assert something weaker than a YubiKey one **while looking identical to
  a verifier** — an invisible difference at the moment it matters. It is
  derived from provenance rather than a configuration switch deliberately: a
  switch is mutable state that can be flipped after the key lands, and creates
  an ordering hazard where configuring for attestation and then importing
  forces one of the two to lose. "This key was imported" is decided once and
  can never become false.

  **Provenance is recorded by the system and never accepted from a caller**,
  the same rule PKCS#11 applies to `CKA_LOCAL`: the generate and import paths
  stamp it from the code path that ran, and `stampKeyOrigin` strips and
  recomputes whatever a caller supplied. A provenance field a caller can set is
  worse than no field, because a verifier reads it as authoritative when it is
  merely asserted.

  `KeyOrigin` is a **sibling axis** to where a key lives, not the same one — a
  hardware-resident key may still have been imported, and that combination is
  the dangerous one. It is named to sit beside a future attestation level
  (#220) rather than collide with it.

  Making the fact durable exposed a pre-existing gap worth naming on its own:
  **the software backend's import path wrote no metadata record at all**, so
  the tenant, the exportability and now the origin of every imported key were
  lost — `ListKeys` reads that record for exactly the attributes the key
  identifier cannot express, and a tenant-scoped view filters on the tenant it
  could not see. Import now writes the record generation always wrote, via a
  new `pkcs8.WriteKeyMetadata`, and rolls the key back if it cannot. The record
  gains schema version 2 for the origin, overlaid the way the tenant and
  partition already are.

  **Attestation fails closed on the origin**: anything that is not `generated`
  is refused, not merely `imported`. A check that refuses only the known-bad
  values would start attesting silently the day a write path forgot to record
  an origin, with nothing failing and nothing warning.

  Keys written before the field existed still attest, but that reasoning is
  applied **once, where the record is read** rather than as a permanent
  exception inside the security check. `pkcs8.resolveKeyOrigin` resolves a
  record with no origin — schema below 2, or no record at all — to `generated`,
  because such a key predates every PIV import path and cannot have been
  imported. A **schema-2 record carrying no origin is a defect rather than a
  legacy key**: it was written by a build that had the field and did not set
  it, so it stays unknown and is refused. That distinction is the reason the
  inference sits at the boundary.

  A slot whose key this process does not hold at all — it lives in another
  backend, or an in-memory generator was restarted — is a separate case with no
  provenance to judge, and attestation of the stored certificate proceeds as
  before.

  **The guarantee is closed at import rather than at attestation.**
  `ImportPIVKey` reads the origin back after writing it and rolls the import
  back with `ErrPIVImportProvenanceNotRecorded` if the backend did not record
  it. A backend with no provenance plumbing therefore cannot hold an imported
  key at all, which is what makes it safe for an unrecorded origin to attest.
  Refusing on an unrecorded origin instead would have made **every
  hardware-backed PIV slot unattestable** — only the pkcs8 provider persists an
  origin today, so PKCS#11, TPM2 and the cloud KMSes report none for every key
  they hold, generated ones included. That is the case PIV attestation exists
  for. A non-empty origin this build does not recognise is still refused.

- **`importAsymmetricKey` writes the key metadata record it always owed**
  (#162). Its symmetric sibling and every generation path wrote one; asymmetric
  import wrote the PKCS#8 bytes and nothing else, bypassing the component that
  owns the record. `ListKeys` treats that record as authoritative, so an
  imported key came back describing a different key than the one imported: the
  tenant was lost, and `parseStorageKeyID` then reinterpreted a five-segment
  identifier's leading tenant as a **partition**. `TenantScopedBackend.ListKeys`
  filters on the tenant, so neither of two keys imported by different tenants
  was visible to the tenant that imported it — import reported success and
  signing reported key-not-found.

  The record is now written on the import path through a new
  `pkcs8.WriteKeyMetadata`, the explicit metadata-write seam of the two options
  #162 set out, and the key blob is rolled back if the record cannot be
  written. Schema version 2 additionally carries the **digest**, which
  `keyMetadata` had no field for at all — so a hash set on import was inert
  rather than merely unpersisted, exactly as #162 describes.

  **Only the software backend's asymmetric import is fixed.** The other
  backends implementing `ImportExportBackend` — PKCS#11, TPM2, AWS KMS, GCP
  KMS, Azure Key Vault — each own their persistence and are unaudited for the
  same shape. That is now fail-closed rather than silent: `ImportPIVKey` reads
  the origin back and refuses the import if a backend did not record it, so PIV
  key import works where provenance persists and is refused, visibly, where it
  does not.

  Recording the provenance on the enrollment record or in an attestation
  extension remains deliberately **out of scope**: the enrollment record is
  qrdb's model and raises the cross-repo vocabulary question still blocking
  #220, and for real hardware xkms cannot stamp the card-minted `f9`
  certificate at all. #206 owns the verifier that would consume either.


### Changed

- **The Lint gate reports every finding instead of the first few** (#225).
  `.golangci.yml` set none of golangci-lint's three output filters, so the
  defaults applied and the gate reported a **floor rather than a count**:

  | filter | default | effect |
  |---|---|---|
  | `max-same-issues` | 3 | per identical message text |
  | `max-issues-per-linter` | 50 | |
  | `uniq-by-line` | true | only the first finding on a given line |

  All three are now set explicitly to report everything, with the rationale in
  the file so the next reader does not need to know golangci-lint's defaults to
  know what the gate measures.

  **This never produced a false green** — `exit-code` is 1 while any issue
  survives filtering, and a filter can only reduce a printed count, never take
  one from ≥1 to 0. What it distorted is the reported *extent*, which cost time
  twice: a family sharing one message printed three at a time, so fixing what
  was printed and pushing yielded three more — indistinguishable from a
  regression — at a full CI cycle per round on the runner that has been the
  binding constraint. And work was sized against the printed number: the
  v2.12.2 → v2.13.2 bump (#189) was scoped against 14 SA1019 findings that were
  themselves capped.

  Unlimited rather than a larger bound, because any bound reintroduces that
  failure the moment a family exceeds it, and a number that is sometimes a
  count and sometimes a floor cannot be reasoned about.

  **Measured before changing anything**, with the runner's v2.13.2: uncapping
  reveals **no hidden findings**. Root, `sdk/go` and `web/desktop` each report
  `0 issues.` capped and uncapped, and `xkey`'s non-usb subtrees likewise, so
  this cannot turn the gate red. The change was then shown to do what it claims
  by injecting a six-instance finding family: **3 printed under the old cap,
  all 6 under the new configuration**.
- **`go-truststrap` v0.2.0-alpha → v0.4.0-alpha across all three modules**
  (#269) — root, `xkey` and `sdk/go` together, for the reason #208 took
  x/crypto and #259 took grpc across all four: a module left behind
  reintroduces the gap in the next artifact built from it.

  **This is a breaking bootstrap wire change, and both ends must upgrade
  together.** From v0.4.0-alpha the bootstrap handshake's first frame carries a
  two-byte `version || suite` header; v0.2.0-alpha sent a bare Noise message 1
  with no header and no prologue. Upstream lists "strip the header and speak the
  old wire" among the attacks it deliberately defends against, so there is **no
  silent fallback** — an un-upgraded peer is refused, by design.

  Upstream justifies the break on the grounds that "the downstream consumers are
  blocked today", which is true of FIPS consumers and **not** of a non-FIPS
  Noise bootstrap, which works today. Any deployed client/server pair therefore
  has to move in lockstep.

- **`make release-alpha` cuts a correct release, and takes the version as an
  argument** (#58). The old seven-line recipe had four defects, every one of
  them measured while releasing v0.7.8-alpha and v0.8.0-alpha by hand: it could
  only ever bump PATCH, so a breaking pre-1.0 release was not expressible; it
  wrote `VERSION` and nothing else, leaving all nine reciprocal `go.mod` pins
  at the previous version, which no in-repo build can notice because they all
  resolve through local `replace` directives; a bare `git tag` aborted under
  the `tag.gpgsign=true` that `agent-git.sh` sets, so the target was unusable
  by the only thing that releases these repos; and `git push --tags` published
  every local tag rather than the three it created.

  The target is now `scripts/release-alpha.sh`, and the version is **stated**:
  `make release-alpha VERSION=0.9.2-alpha [BUMP=minor]`. Deriving it asks an
  open question — what is the greatest version anywhere? — whose answer depends
  on local tags, remote tags, reachability, malformed tags and three lockstep
  namespaces. Validating a stated one asks a closed question against a fixed
  checklist. `BUMP` is a declared intent, refused unless it agrees with
  `VERSION`, and it is what makes a breaking release expressible.

  The nine pin edges are **declared**, not counted. Comparing a count of pins
  found at the current version with a count at the next fails open twice over:
  a stale edge is in neither total and a deleted one is absent from both, so
  the totals match and the release ships a module that no longer pins its
  sibling. Each edge is checked by name at the current version before anything
  is written and at the new version after. Tags are annotated, explicitly
  signed with the signature confirmed on the object before any push, and
  published with `--atomic` so a lockstep release cannot half-publish immutable
  module tags.

  Two bounds rather than guards: the script refuses to start on a dirty tree,
  which deletes the "unrelated edits swept into the release commit" class
  outright, and its CHANGELOG preflight is anchored to the line start exactly
  as `release.yml` requires, so a heading the workflow would reject is caught
  before the tags become permanent. Hardening the remaining seams between the
  first read and the final push is #211, which needs an owner ruling.

- **BREAKING: `webauthn.allow_public_registration` now defaults to disabled**
  (#184, owner ruling 2026-09-01). An unset flag used to mean open self-service
  sign-up; it now means invite-only, aligning go-xkms with the stack-wide
  registration model (canonical flag `iam.self_service_registration.enabled`,
  default off) and the company secure-by-default convention: a setting that can
  silently produce an open surface is a defect.

  **Operator impact.** A deployment that relied on omitting the key now refuses
  WebAuthn registration for unknown emails; add
  `allow_public_registration: true` to restore open sign-up. Accounts
  provisioned through the authorized user-creation path still enrol their first
  passkey through the same endpoint — only implicit account creation is
  withheld, and the refusal now carries its documented wire contract
  (REST `403 registration_disabled`, gRPC/Unix `PermissionDenied`) instead of
  falling through to a 500/`Internal`.

  When xkms runs as a ServiceModule under go-quicbaas, the host-projected
  registration decision passes through verbatim and is authoritative; the
  secure default applies only when the host never decided.

- **FLAG DAY: device attestation is now challenge-response (protocol version 2)**
  (#129, #93, owner ruling 2026-08-24). Supersedes the embedded-challenge
  freshness model.

  A phone now holds ONE persistent hardware-attested key. Its
  SubjectPublicKeyInfo hashes to the stable `DeviceFingerprint`, and freshness
  is proved by a LIVE signature over the verifier's nonce rather than by a
  nonce baked into the attestation certificate.

  The old model could not work on Android and this is not a preference:
  Keystore fixes the attestation challenge at key GENERATION and offers no
  re-attest-existing-key API, so a per-pairing challenge forces a per-pairing
  key. A stable device identity and embedded-challenge freshness are mutually
  exclusive there, which made the per-device binding #93 required
  unimplementable as specified. Version 2 separates the two properties the old
  one conflated, and works unchanged on TPM devices, removing the asymmetry.

  **Operator impact.** After upgrading, a *new* pairing requires an xkey-android
  build that speaks version 2; an older app is refused rather than accommodated,
  because a peer that could decline the check by claiming an older version would
  choose its own security level. **Existing pairings keep working** under their
  recorded binding until re-paired, and are not reported as though they had the
  stronger one. `xkey device attest-device` upgrades a record in place.

  Wire contract, including byte-exact interop vectors:
  `xkey/docs/device/pairing.md` and go-xkms#129. A change to any published
  vector is a wire break, not an edit.

- **Device attestation is verified in one place** and consumed by every
  surface — pairing, reconnect, `device attest-device`, the FIDO2 and
  backend-based CLI commands, and the desktop GUI (#130 (a)).

  It previously lived in `cmd/xkey/cmd`, which the GUI cannot import, so the
  two surfaces established device trust by different rules. That is not a
  hypothetical cost: pairing verified chains `attest-device` did not (#95), the
  two derived the device identity differently (#93), the GUI performed no
  pairing attestation at all, and the GUI's record mirror silently dropped the
  attestation protocol version so a CLI-paired device read as unbound. The
  decision now lives in `xkey/pkg/attestation`.

  The GUI proves liveness **before** publishing a connection, and refuses a
  version 2 record when no trust store is configured.

### Fixed

- **BREAKING (display): `certstore.ToString` no longer prints a SHA-1
  fingerprint** (#197). It prints a SHA-256 fingerprint instead.

  `crypto/sha1.Sum` panics rather than erroring in FIPS 140-only mode, so every
  FIPS-activated process that formatted a certificate for display through
  `ToString` — exported by the SDK as `CertToString` — died on a human-readable
  thumbprint.

  The line is **removed, not conditioned on a FIPS check**. No predicate
  available can answer "is this a FIPS artifact": `GODEBUG=fips140=off` turns
  `fips.Compiled()` false even on a `GOFIPS140`-built binary (#219), so a guard
  would fail open for exactly the artifacts the policy cares about. Deleting the
  line leaves no predicate to get wrong, and `crypto/sha1` is no longer imported
  by the package at all.

  **Operator impact:** anything comparing this block against
  `openssl x509 -fingerprint` must switch to `openssl x509 -fingerprint -sha256`.
  Anything indexing the block by line offset must be updated. Nothing in this
  repository parses the value — `SHA-1 Fingerprint` occurred exactly once, at the
  print site — and both callers only print the result.


### Added

- **The ACME DNS pre-checks take an injectable resolver** (#243).
  `CheckDNSFromAuthoritative`, `CheckDNSFromPublic` and
  `CheckDNSFromNameservers` gain variadic `DNSCheckOption`s —
  `WithNameserverLookup` (a `NameserverLookup`) and `WithPropagationQuery` (a
  `PropagationQuery`).

  **Production behaviour is unchanged**: with no options the defaults are
  `getAuthoritativeNameservers` (the system resolver) and
  `providers.CheckDNSPropagation` (a real query), exactly as before. The
  options are variadic, so every existing call site still compiles, and a nil
  option is ignored rather than installing a nil dependency.

  `getAuthoritativeNameservers` also gained an internal seam:
  `authoritativeNameservers(fqdn, nsLookup)` carries the logic — stripping the
  `_acme-challenge` label and trailing dot, appending `:53`, refusing an empty
  answer — so that logic is testable without asking the internet.
- **`providers.ZoneFinder`** (#243) — the seam a DNS-01 provider uses to resolve
  a zone apex. It has `FindZoneByFQDN`'s exact signature, and that function is
  the default wherever a provider takes one, so supplying nothing changes
  nothing and no existing signature moved.

  `route53.Config` and `clouddns.Config` gain an optional `ZoneFinder` field.
  A `Provider` built without one — including by a bare struct literal or by
  `NewWithClient` — falls back to `providers.FindZoneByFQDN`.

  **Supplying one bypasses the zone cache, deliberately.** The cache is an
  optimisation over *real DNS*; a caller supplying its own resolution is making
  no round trips, so it has either no need of a cache or a cache of its own, and
  should not share a process-global map with production lookups. A seam that
  injected only the DNS *query* while leaving the cache in place would write
  fabricated SOA answers into the real map, where the next lookup of the same
  FQDN would inherit another caller's fiction. Replacing the whole cached lookup
  removes that structurally rather than requiring every caller to remember
  `ClearZoneCache`, which remains for the default, cached path.

- **`fido2-attestation` certificate profile** (#232). The CA can now issue a
  FIDO2 authenticator attestation certificate that satisfies WebAuthn Level 2
  §8.2.1: Subject-C and Subject-O stamped from the issuing CA's own subject (the
  device cannot credibly assert its vendor's country or legal name), the literal
  Subject-OU `Authenticator Attestation`, Basic Constraints CA:false, and the
  `id-fido-gen-ce-aaguid` extension copied from the request. Select it with
  `SignOptions.Profile` / `SignCSRRequest.Profile` = `fido2-attestation`, which
  is what `xkey fido2 provision-attestation --profile` names.

  Before this, `SignCSR` dropped every CSR extension and asserted only the
  subject the CSR carried, so an attestation certificate had no Subject-C, no
  Subject-O and no AAGUID extension — a relying party rejects that, and the
  xkey provisioning command refuses it at install.

  The profile **refuses** rather than issuing something short: a request with no
  AAGUID, a malformed AAGUID, no common name, or an issuing CA whose subject
  lacks a country or organisation is rejected.

  **Trust assumption.** The AAGUID is copied verbatim; the CA does not check it
  against a registry of operator-vouched authenticator models, because none
  exists. The binding rests on the provisioning ceremony (device possession plus
  the Security Officer PIN) and on the CA being the operator's own.

- **`CertificateRequest.CSRExtensions`** carries the extensions a certificate
  signing request asked for through to `Profile.Apply`. The CA still copies no
  CSR extension by itself — a requester that could name its own basic
  constraints or key usage would be issuing to itself — so a profile opts into
  the specific extensions it understands. `fido2-attestation` is the only
  profile that does.

- **The version 2 `local.attestDevice` request carries no channel binding.**
  Each side derives it from its own Noise session; the transcript still commits
  to it. Sending it would make a prover that signs the supplied value
  indistinguishable from one that derived its own until the exact relay attack
  the binding prevents.

- **Pairing protocol error code `-32037`
  (`ErrorCodeAttestProtocolDowngrade`)**, reserved for a prover refusing a
  device-attestation request that does not ask under protocol version 2. It is
  the prover's half of the downgrade refusal: the verifier refuses a version 1
  answer, so the prover refuses a version 1 request. go-xkms never sends it —
  this repository is the verifier — but the number is reserved so a future
  method family cannot claim it.

- **`sdk/go`: `AndroidKeyAttestationOID` and `BuildAndroidAttestationExtension`.**

  Consumers verify Android key attestation through `sdk/go`, but could not
  BUILD an attestation extension through it — so a consumer testing its own
  verifier had to reach past the SDK into `pkg/attestation/android`, which the
  architecture boundary forbids and CI enforces. `BuildAndroidAttestationExtension`
  is deliberately a test-support API on the SDK surface: `pkg/attestation/android`
  already exported it for exactly that purpose, and it simply was not reachable
  through the boundary. A nil `RootOfTrust` builds a chain that verifies while
  claiming nothing about boot state — a case that exists to be REFUSED, so it
  has to be constructible on purpose.

### Security

- **MCP resolves a key by common name within the caller's tenant** (#166).
  `export_key` performed no tenant check: it resolved the key through an
  unscoped backend and took the first common-name match. A common name is
  unique only within a tenant, so one tenant could export another tenant's
  wrapped key material by naming its key ID — a read of key material across the
  tenant boundary.

  Both shared lookups (`findKeyInBackend`, `findKeyByCN`) now resolve through a
  backend scoped to the authenticated caller's tenant, which fixes every caller
  of them — export, delete, decrypt, encrypt, sign, verify, and the asymmetric
  and TLS-certificate paths — not just the export handler. `listKeys` is scoped
  by the same view, so a listing can no longer show a key the lookup then
  reports as missing, and `seal` / `unseal`, which each carried their own inline
  copy of the same first-match-on-CN scan, now resolve through the one shared
  lookup.

  The system tenant remains unscoped and still sees every key, matching the
  service layer's existing `resolveTenantBackend` predicate. A caller with no
  identity is unaffected.

  New on the service layer: `XKMSService.LookupTenantBackend` and
  `xkms.ScopeBackendToTenant`, so a transport that holds a backend name (or a
  backend) and a tenant gets the same scoped view the service's own request
  paths use, rather than reimplementing the predicate.


## [0.9.1-alpha] - 2026-09-02

### Fixed

- **The default backend was chosen by Go's randomized map iteration** (#171).
  Both `xkms.Initialize` — exported to embedders as
  `xkmssdk.ServiceInitialize` — and the daemon's `initializeKeyStore` took
  "the first" entry of the backend map when they had no usable configured
  default. Go randomizes that order by design, so the same binary on the same
  configuration resolved a different default on each start: 500 constructions
  over four backends selected all four (318/63/62/57).

  The default is not cosmetic. It decides where keys generated or imported
  without an explicit backend are stored, and therefore their `StoreType`
  segment in `KeyAttributes.ID()`, so a key written before a restart could be
  looked for in a different store after one, with nothing logged to explain it.

  Resolution is now one rule, `xkms.ResolveDefaultBackend`, already applied on
  the auto-configuration path and now shared by all three: the requested
  backend when it is loaded, then the software backend, then the alphabetically
  first name — every step a function of the backend names alone.

  Reached differently by each caller, deliberately. `xkms.Initialize` still
  fails closed on a default that was configured but not loaded
  (`ErrDefaultBackendNotFound`) and consults the rule only when none was
  configured. The daemon keeps starting in that case — a `default_backend`
  naming a backend absent from the build is not fatal — but now logs a warning
  naming the configured and resolved backends instead of substituting one
  silently. Embedders who relied on an arbitrary default with several backends
  loaded and none named will see a stable choice, which may differ from the one
  a given run happened to make.

- **Release `v0.8.0-alpha` did not contain the fix it was cut for** (#195).
  The tag pointed at `3b227eee`, which predates `efdf8d76` (#190,
  "resolve logins by the canonical email key"), so every consumer
  resolving a tag still got the broken email resolution. Nothing in the
  repo could see this: the fix was on `main`, the tag looked current, and
  only `git merge-base --is-ancestor <fix> <tag>` distinguishes them.
  Downstream, go-quicbaas#359 stalled against it.

  `v0.9.0-alpha` carried the fix but was rejected by `Release / Validate
  tag` for having no CHANGELOG section; this release supersedes it. The
  two are identical in code — the published `v0.9.0-alpha` module is
  usable, it simply has no release pipeline behind it.

### Changed

- go-qrdb pinned to `v0.16.0-alpha` (from `v0.15.0-alpha`), which brings
  go-quicraft `v0.9.0-alpha`. A zero-source-change bump here: all three
  modules build and `pkg/auth`, `pkg/apimodule`, `pkg/storage`, `pkg/api`
  and `pkg/webauthn` pass under the full tag set.

  Pinned deliberately rather than left to drift. go-quicbaas requires
  go-qrdb `v0.16.0-alpha`, so MVS hands it to go-xkms regardless of what
  this module declares — better that the pin is tested here than
  discovered at a consumer's integration. It also resolves the
  `seal.StorageBackend` / `CompareAndDelete` break that `v0.8.0-alpha`
  presented to consumers on qrdb v0.15.

- Cross-module requires bumped to `v0.9.1-alpha` in all three `go.mod`
  files. `make release-alpha` does **not** do this (Makefile:4342 tags the
  submodules but never rewrites the requires), and the local `replace`
  directives hide the omission because a `replace` inside a dependency
  module is ignored by consumers. Releases are cut by hand until PR #73
  lands.

## [0.8.0-alpha] - 2026-08-20

**MINOR, not PATCH**: this carries a breaking API change, and pre-1.0 that is
what MINOR means ([release-versioning.md](https://198.51.100.91:3001) §1).
`make release-alpha` only increments PATCH, so this was tagged by hand.

**`agent.Session.Stop` now takes a context and returns a `ShutdownReport`.**
v0.7.8-alpha bounded shutdown with a fixed internal constant and returned
nothing — the silent bounded stop: it re-introduced, as an *undocumented*
surprise, the thing the connection drain was built to prevent, with the bound
chosen by the library rather than by whoever is shutting down.

Upgrading from v0.7.8-alpha: `defer sess.Stop()` becomes
`defer sess.Stop(context.Background())`, or pass a deadline and read the
report. `connect.Session`'s `Stop`, `Sync` and `SyncAndStop` take one too.

The hardening below is mostly in code v0.7.8-alpha did not change. What
changed is that its errors and bounds became *meaningful*: making an error
real is a change to every caller that ignores it, and bounding a call is not
free, because every fail-open beneath it turns a timeout into a silent
success.

### Changed

- **BREAKING: `agent.Session.Stop` takes a context and returns a
  `ShutdownReport`** (#55, owner ruling on #52). v0.7.8-alpha bounded shutdown
  with a fixed internal constant and returned nothing, which is the silent
  bounded stop: it re-introduced, as an *undocumented* surprise, the very thing
  the connection drain was built to prevent, with the bound chosen by the
  library rather than the caller.

  Neither pure horn is acceptable — an unbounded `Stop` hands control of a
  worker's lifetime to a wedged TPM, and a silent bounded one hides a real
  residual. So `Stop(ctx) ShutdownReport`: the listener closes and every
  attached client is disconnected **unconditionally**, before any waiting, so
  no new client can attach and no new signing operation can start; the
  connection handlers are then joined within `ctx`, and the report names how
  many were abandoned. Never a bare nil.

  The residual, documented rather than discovered: an abandoned handler may
  still deliver a signature to a client that attached *before* `Stop` began. No
  new authorization occurs — that client was already served by an authorized
  session. Re-exported as `AgentShutdownReport`.

  Callers upgrading from v0.7.8-alpha change `defer sess.Stop()` to
  `defer sess.Stop(context.Background())`, or pass a deadline and act on the
  report. `connect.Session.Stop` takes a context and returns the same report
  for the same reason — a layer that picks the bound on a caller's behalf is
  choosing when to give up on their behalf too.

## [0.7.8-alpha] - 2026-08-20

**Agent-only SSH sessions**: an xkms-held key served over an ephemeral
in-process SSH agent socket with no connection target, for tools that speak
the ssh-agent protocol without dialing a host. The motivating consumer is git
commit signing under `gpg.format=ssh`; `ssh-keygen -Y sign` and `age` use the
same socket.

This also hardens `pkg/ssh/agent` considerably, and most of that hardening is
in code this release did not otherwise change. Nothing about that code moved —
what moved is its exposure: it stopped being an internal detail of one call
path and became a primitive any consumer can point at any key, which raises
the security bar it has to meet. The Security section below is the cost of
that promotion, paid here rather than inherited.

Two behaviour changes worth reading before upgrading: an RSA key served over
an agent socket **no longer signs with SHA-1**, so a server accepting only
legacy `ssh-rsa` will not authenticate with one; and `agent.Listen` no longer
clears a stale socket, so a leftover from a crashed run is the directory
owner's to remove.

### Added

- **SSH SDK: agent-only sessions (`xkmsssh.StartAgent`)** (#52). Serves
  xkms-held keys over an ephemeral in-process SSH agent socket with **no
  connection target**, for tools that speak the ssh-agent protocol without
  dialing a host — `git commit -S` under `gpg.format=ssh`, `ssh-keygen -Y
  sign`, `age`. `Keys().Signer` returns an in-process `ssh.Signer`; those
  tools need a socket. `StartConnect` had the agent machinery but demanded a
  Host/Port/User and known_hosts seeding that a signature has no use for.
  The socket is bound synchronously (connectable when `StartAgent` returns,
  bind failures typed as `*AgentListenError`) and dies at the first of
  `Stop()` or context cancellation, taking an owned work directory with it.
  No host-key semantics are implied: `StartAgent` neither seeds nor consults
  `known_hosts`. Only the public half ever reaches disk. Documented in the
  new [`docs/ssh-agent-sessions/`](docs/ssh-agent-sessions/) feature folder,
  which is normative for this capability; the rest of `docs/ssh/` remains
  unconverted legacy.

### Changed

- `pkg/ssh/agent` gained an internal listen/serve split (`Serve` is unchanged
  and now composes them) so the socket can be bound before serving begins. The
  raw binder stays unexported: `net.Listen` binds before the mode is applied,
  so for an arbitrary path there is a window in which the socket carries
  whatever the umask left it, and only a 0700 containing directory closes it —
  which `StartSession` can promise and a raw path cannot.
  Shutdown closes every attached client and joins its handler, and unlinks the
  socket exactly once — by closing the listener — so a successor session on the
  same `WorkDir` cannot have its live socket deleted by a predecessor's late
  cleanup. **`Listen` no longer clears a stale socket** — an
  occupied path is refused with `ErrSocketInUse` (an agent answers there) or
  `ErrPathOccupied` (anything else), re-exported by the SDK as
  `ErrAgentSocketInUse` and `ErrAgentPathOccupied`. Clearing one needs
  inspect-unlink-bind, and between those steps another process can bind its
  own live agent at that path, which the unlink then destroys. A leftover from
  a crashed run is now the directory owner's to remove. This is a behaviour
  change to the pre-existing `Listen` / `Serve` path, which had no in-repo
  callers.
- `pkg/ssh/connect.Start` drives the new `agent.StartSession` instead of
  carrying its own copy of the agent plumbing; its 3-second socket poll (and
  the `time.Sleep` in it) and the `LaunchError{Op: "agent socket"}` it could
  return are gone, because the bind is now synchronous. Its error contract is
  unchanged: agent setup failures are still `*connect.LaunchError`
  (`Op: "agent session"`), with the cause reachable through `Unwrap`. `WorkDir`
  still means "create the scratch area here", so `connect` creates it — the
  agent deliberately will not conjure a directory it would not own — and every
  path derived from it is absolutised, because the socket and the seeded
  `known_hosts` both leave this process for a child with its own working
  directory.

### Security

- **RSA keys served over an agent socket never sign with SHA-1.** An unflagged
  `SIGN_REQUEST` is an ssh-agent client's default rather than a deliberate
  choice, and x/crypto's default for an RSA signer is the legacy `ssh-rsa`.
  With `StartAgent` making the agent reachable by any ssh-agent client, that
  would hand out a non-approved primitive on request under the project's FIPS
  140-3 requirement. RSA requests now get `rsa-sha2-256` (or `-512` when
  flagged), and an RSA signer that cannot select an algorithm is refused with
  `*UnsupportedAlgorithmError`. **Behaviour change**: a server that accepts
  only legacy `ssh-rsa` will no longer authenticate with an RSA key served
  this way.
- **`StartAgent` has no `WorkDir` option**; the session always creates its own
  private directory. A socket's 0600 mode does not protect its *pathname* — the
  containing directory governs who may replace it — and validating a
  caller-supplied directory is inherently check-then-use, because an attacker
  controlling any ancestor redirects the path between the check and the bind.
  Closing that needs an anchored no-follow bind, which
  `net.Listen("unix", path)` cannot express. The option is absent rather than
  guarded by a check that looks like a guarantee and is not. `pkg/ssh/agent`
  still accepts a directory for `pkg/ssh/connect`, which supplies one it
  created itself, and validates it (`*InsecureWorkDirError`: symlink, foreign
  owner, group/world-writable).
- **Shutdown terminates even when a signer does not.** Closing the listener and
  disconnecting every attached client are unconditional; joining the connection
  handlers afterwards is bounded. A handler stuck inside an uninterruptible
  `Signer.Sign` (a TPM awaiting touch, a stalled KMS) cannot be woken by
  closing its connection — but it also cannot answer anyone, because that
  connection is already closed. Waiting forever would hang `Stop()` and leave
  the work directory unreaped to guard against an oracle with nobody to talk
  to.
- **Typed-nil signers are rejected.** A nil pointer boxed in an `ssh.Signer`
  passes an interface nil check, and the first `PublicKey` call would panic in
  the serving goroutine, taking the process down.
- **`agent.Serve` validates the socket's parent directory** on the same terms
  `StartSession` applies. It takes an arbitrary path, so without that a caller
  could bind a signing socket in a shared directory — where the bind-to-chmod
  window is reachable and the pathname can be replaced outright.
- **Off Unix, a caller-supplied work directory is refused.** The isolation this
  package relies on is expressed in Unix mode bits; Windows ACLs are inherited
  rather than implied by a `Mkdir` mode, invisible to `fs.FileInfo`, and not
  comparable against a uid. A check that cannot see the permissions it is
  checking must not return "safe". Sessions that create their own directory are
  unaffected — `os.MkdirTemp` lands under the platform's per-user temp
  location, which is the OS's isolation rather than a claim made here.
- **`connect.Session` teardown is synchronised, and cannot be held hostage.**
  `Sync` and `Stop` touched `knownHostsFile` and the agent handle unguarded
  while `Sync`'s own doc says the GUI polls it on a live session — a data race,
  and one that could delete the known_hosts out from under a running import,
  losing exactly the first-contact pins `Sync` exists to capture. `Stop` now
  stops the agent first and independently: the import runs against a
  caller-supplied store over a context this session does not control, so
  holding a lock across it would let a stalled backend keep a signing agent
  alive. Removing the work directory waits for an in-flight `Sync`, but only
  briefly.

## [0.7.7-alpha] - 2026-08-20

A dependency release: **go-qrdb v0.6.0-alpha → v0.9.0-alpha**, with
go-quicraft v0.6.2-alpha → v0.8.0-alpha and go-objstore v0.2.2-alpha →
v0.3.0-alpha arriving through minimal version selection. Root, `sdk/go` and
`xkey` all move together.

### What this release does and does not change

**No behaviour of go-xkms itself changes** except where the adopted version
required it, described below. No API is added, removed or migrated, and no
custody path is altered.

**The exception is an adaptation you should understand, because it looks
like a one-line error change and is actually a protocol fix.** Since go-qrdb
v0.8.0-alpha, `pkg/dao` *negotiates* index capability: it calls
`RegisterEntityIndexes` when a DAO is constructed and reads the reply. An
error matching go-qrdb's `ErrKVIndexUnsupported` means "this store has no
index subsystem, plan full scans"; **any other error means construction
failed**. Previously the refusal was ignored.

`pkg/storage/kvadapter` cannot maintain secondary indexes — it bridges an
opaque byte-oriented `storage.Backend` and never decodes entity payloads —
and it refuses index operations for that reason. But it reported only its
own sentinel, which go-qrdb does not recognise, so a *capability signal* was
read as a *hard failure* and every DAO built over the adapter refused to
construct. `IndexingNotSupportedError` now matches both sentinels: the local
one, so existing callers keep working, and go-qrdb's, so the DAO plans scans.
The same value is re-exported as `xkms.ErrIndexingNotSupported`, and
consumers may test for either.

### Known gaps, stated plainly

**The deprecated Shamir share API is suppressed, not migrated.** quicraft
v0.8.0-alpha deprecates `Split` and `Share.Value` in favour of
`SplitProtected`/`ProtectedShare`, because a Go string cannot be wiped and a
ceremony holding all N shares is the widest exposure in the scheme. Eight
call sites — all in test helpers, no production path — carry per-line
`//nolint:staticcheck` directives rather than being migrated, because
changing key custody inside a dependency bump would be the wrong place to do
it. Tracked separately; closing that work means deleting every directive.

### Fixed

- `kvadapter.IndexingNotSupportedError` now satisfies `errors.Is` against
  go-qrdb's index-capability sentinel as well as its own, restoring DAO
  construction over `KVStoreAdapter` under go-qrdb ≥ v0.8.0-alpha.
- The ACME remote-transport adapter (`pkg/acme/qrdb`) had the same defect on
  all five of its index methods, and it was **not** latent: `NewProvider(svc,
  nil)` — the documented default — installs that adapter, so the default
  remote ACME path could not construct a DAO at all under v0.9.0-alpha. All
  five now refuse with an error the go-qrdb DAO recognises, and a regression
  test asserts this **through `NewProvider(svc, nil)`** rather than only
  through a hand-built adapter.
- `release.yml` installs Go in its `Validate tag` job. Without it the job
  died at `go: command not found` and **no release after v0.7.4-alpha
  produced a release object, binaries or checksums**.
- `release.yml` gained a `workflow_dispatch` tag input so an already-published
  tag can be rebuilt without moving it, and now stamps binaries with the
  released commit rather than the branch HEAD a dispatch ran from.

### Changed

- go-qrdb v0.6.0-alpha → v0.9.0-alpha (root, `sdk/go`, `xkey`)
- go-qrdb/sdk/go v0.6.0-alpha → v0.9.0-alpha
- go-quicraft v0.6.2-alpha → v0.8.0-alpha (via MVS)
- go-objstore v0.2.2-alpha → v0.3.0-alpha (via MVS)

## [0.7.6-alpha] - 2026-08-19

### What this release does and does not guarantee

Read this before the entries below, because the headline is easy to
over-read.

**Closed: the lifetime axis.** A Noise static key held in protected memory is
now owned by exactly one component, and nothing reads it while it is being
destroyed. Every reader synchronises against the destroyer; every generated
key has an owner that frees it; no path frees a key another goroutine is
still decrypting through. That is what the ~35 fixes in this release are.

**NOT closed: the escape axis.** The phone-pairing Noise private key is still
persisted as a base64 string in YAML, and `LocalNoisePrivateKey string` is
still an ordinary Go string for the whole life of a loaded config. Go strings
are immutable, so that copy cannot be wiped, and the file is plaintext at
mode 0600 — protected by filesystem permissions only, not by protected
memory and not sealed at rest. This is pre-existing and unchanged by this
release; it is not a regression, and it is not fixed either.

So: **"Noise keys are held in protected memory" is true of their lifetime in
process and false of their persisted form.** Closing the second half needs a
config-format migration and a decision about whether that key should be
sealed rather than plaintext-0600. That is an open owner decision, tracked
separately. Anyone relying on this release for at-rest protection of the
phone-pairing key does not have it.

**Third thing, on the shutdown paths.** When a shutdown cannot confirm that
every reader has stopped, it keeps the protected key rather than freeing it,
and reports `ErrShutdownIncomplete`. **That retention is permanent for the
life of the process, not deferred.** Nothing reclaims the key afterwards:
the component is closed, its references are cleared, and there is no retry.
memguard's only reclamation is `secure.Purge`, which destroys every locked
buffer in the process at once — a shutdown operation, not a way to recover
one leaked key while the program runs. `xkmsd` arms it; the `xkey` binaries
do not arm it at all. So repeated shutdown timeouts accumulate locked pages
against the process memlock limit for as long as the process lives. It is
still the right trade against freeing pages a live goroutine is decrypting
through, but it is a real cost and it is stated here rather than implied
away.

### Changed

- **BREAKING — `go-truststrap` protected-memory Noise API adopted**
  (`v0.1.3-alpha` -> `v0.2.0-alpha`). Static Noise keys are now
  `*noise.StaticKey` values living in guard-paged, swap-locked memory rather
  than `[]byte` and `string`. The wrapper layer in `xkey/pkg/pairing` follows
  the same shape, so the encode direction writes into a caller-supplied
  buffer instead of returning a string that can never be wiped:

  ```go
  // before
  func EncodeStaticKey(key *DHKey) string
  // after
  func EncodeStaticKey(dst []byte, key *StaticKey) error
  ```

  `GenerateStaticKey`, `LoadStaticKey` and `DecodeStaticKey` now return
  `*StaticKey`, and `NoiseSessionConfig.LocalStaticKey` is a `*StaticKey`.
  Callers own what they generate and must `Destroy()` it.
- **`go-qrdb` `v0.5.9-alpha` -> `v0.6.0-alpha`** across all three published
  modules, in lockstep.
- **`xkmsctl bootstrap noise-key` writes to a file and no longer prints the
  private key to stdout.** `--output` is now required. The file is created
  `O_EXCL` at mode 0600, a short write is treated as an error, and a partial
  file is removed rather than left behind. The encoded key is staged in a
  protected buffer that is destroyed on return. (Owner ruling: writing the
  key to a file is acceptable; printing it to a terminal, scrollback and
  shell history is not.)

- **BREAKING — shutdown can now report that it did not finish cleanly.**
  `(*phone.PhoneKeyBackend).Close` and `(*phone.BLEPeripheral).Stop` return
  `phone.ErrShutdownIncomplete` when a reader could not be confirmed stopped
  within the shutdown window. Both were previously `nil`-always on that path.
  The component IS shut down either way and needs no second call. The error
  says the component could not prove it finished — for `Close`, and for
  `Stop` when a connection did not drain, that means the protected key was
  retained; `Stop` also returns it when an advertisement could not be taken
  down, which does not retain the key because nothing reachable through an
  advertisement reads it. **A caller that supplied the key and kept ownership
  must not destroy it after seeing this** — that is exactly the
  use-after-free the retention avoids.

### Added

- **`sdk/go/transport/usb` re-exports `ErrDirtyState`**, the sentinel
  `Connect` now returns when the transport still holds state from a previous
  connection. It was added to the implementation in this release and left out
  of the SDK, so an SDK consumer could see the refusal and not identify it.
  A test pins every sentinel in that package as the same value the transport
  returns, since a re-export that drifted into a separate `errors.New` would
  compile and pass every in-repo test.
- **`sdk/go/bootstrap` re-exports the whole Noise key surface**, not most of
  it: `NoiseHexKeySize`, `NoiseServerStaticKey` and `WipeNoiseBytes` join the
  generate/encode/decode helpers that were already there. Consumers are
  required to use the SDK boundary rather than `pkg/trust/bootstrap`, and
  without these three an SDK-only caller could generate a protected key,
  could not size a buffer to encode it, could not hand it to
  `NoiseServerConfig`, and could not wipe the buffer afterwards. The same
  composition gap appeared one layer down earlier in this release; each half
  compiled on its own, and nothing exercised the combination. There is now a
  test that walks generate → adapt → encode → decode → wipe using only what
  this package exports.

### Removed

- **SHA-1 is no longer an option for a JWK thumbprint** (#292).
  `jwk.Thumbprint` offered `crypto.SHA1` and `ThumbprintSHA1` wrapped it.
  `crypto/sha1` **panics** rather than erroring under `GODEBUG=fips140=only`,
  so any FIPS-activated process reaching that path died — the same defect
  class as the certstore thumbprint (#197/#212), in a package that audit
  never reached.

  **Removed rather than conditioned on a FIPS predicate**, following #212. A
  guard would have to ask "is this artifact FIPS-constrained", and
  `crypto/fips140.Enabled()` cannot answer it: `GODEBUG=fips140=off` turns it
  false on a `GOFIPS140`-built binary (#219), so the guard fails **open** for
  exactly the artifacts the policy most cares about. Removing the option leaves
  no predicate to get wrong, and — more importantly — no mode-dependent output:
  a non-FIPS process can no longer mint a thumbprint a FIPS process cannot
  recompute.

  `Thumbprint` now accepts SHA-256, SHA-384 and SHA-512, and refuses anything
  else through the typed error it already had. RFC 7638 §3.4 defines the
  thumbprint over SHA-256, so nothing approved is lost.

  **Nothing to migrate — audited rather than assumed.** No persisted index,
  cache key, comparison or wire field carried the SHA-1 form. `ThumbprintSHA1`
  was already marked deprecated and "must NOT be called from new code"; it had
  no caller anywhere outside this package's own tests, no SDK re-export, and
  the only two non-test importers of `pkg/encoding/jwk` never compute a
  thumbprint at all.

  **API break:** `ThumbprintSHA1` is deleted, and `Thumbprint(key,
  crypto.SHA1)` now returns an error instead of a digest.

  Verified under the activating environment rather than by reading:
  `GODEBUG=fips140=only go test ./pkg/encoding/jwk/` panicked before and now
  reports **zero panics of any kind**. Its three remaining failures are
  `TestX25519*`, which fail on a clean *error* — `crypto/ecdh: use of X25519 is
  not allowed` — because X25519 is genuinely unapproved. That is the policy
  working as intended, not the defect class this fixes.

- **BREAKING — `(*pairing.NoiseSession).LocalStaticPrivateKey()` is gone**,
  and with it the same method on the `phone.NoiseSession` alias. It handed
  the protected static scalar back to any caller as an ordinary `[]byte`,
  which is precisely the guarantee the rest of this release implements —
  a public accessor that copies protected material out of protection
  contradicts holding it in protection at all. It had no non-test caller in
  the tree. Removed under the pre-1.0 MINOR breakage allowance
  (`release-versioning.md` §1) because leaving it costs more than removing
  it. `LocalStaticPublicKey()` is unaffected: the public half is what callers
  legitimately need, and it identifies the scalar in use without exposing it.

### Security

- **The Noise bootstrap server's static key is no longer freed while the
  server is running.** `startNoiseBootstrap` destroyed it on the way out, on
  the stated premise that `Start` blocks until shutdown. It does not:
  `noiseboot.Server.Start` binds the listener, launches its accept loop in a
  goroutine, and returns. The protected pages were therefore freed while the
  published server and every subsequent handshake still aliased them, so any
  client connecting afterwards read freed memory. The key now belongs to the
  `Server` and is destroyed in `Shutdown`, and only when `Stop` both returns
  nil AND its deadline has not expired. Neither alone is proof: upstream
  `Stop` returns nil whether it drained or timed out, and it also returns
  immediately without waiting for anything when it does not consider itself
  started, which leaves the deadline unexpired. Without both the key is
  retained.
- **Shutdown results are propagated, not logged and dropped.** The components
  learned to report an incomplete drain earlier in this release, and every
  layer above them discarded it: `PhoneService.Disconnect` returned nil over a
  timed-out teardown, `Server.Shutdown` swallowed both the Noise drain timeout
  and its own global deadline, and `xkey device listen` exited 0 after a
  handler-drain timeout. A contract that is correct and unread is the same
  fail-open one layer up. `Server.Shutdown` and the CLI now return the
  incomplete result; `PhoneService.closeActiveConnectionLocked` returns an
  error its three callers act on.
- **`Server.Shutdown` is latched.** Concurrent callers raced into
  `close(s.shutdownCh)` and panicked on close-of-closed, and each independently
  stopped the bootstrap server and could destroy the same protected key twice.
- **The bootstrap server is published only after it starts.** Publishing
  first left a window where `Shutdown` could snapshot a server that had not
  started, call `Stop` on it — which returns immediately without waiting for
  anything — read that as a clean drain, and destroy the key before the
  accept loop ever ran. Publication and the shutdown check now happen under
  one lock, so either `Shutdown` sees a started server or the startup path
  sees the cancelled context and stops the server itself.
- **`TCPPairingServer.Stop` bounds its wait and no longer holds the lifecycle
  lock across it.** Connection workers call a caller-supplied handler
  synchronously, so closing the socket does not interrupt one that ignores
  cancellation — the wait could never return. Holding the lock across it also
  deadlocked any handler that called `LocalStaticPublicKey`. `Stop` now
  returns `ErrShutdownIncomplete` and retains the key when the join times out.
- **Every retention path keeps the key reachable rather than clearing the
  field.** The pages survive either way — memguard pins every live buffer in
  a package-level list, and has no finalizer — but "we are retaining this"
  and "we dropped the only pointer to it" should not look identical in the
  source, and holding the owner is what a future reclamation path would need.
  A test pins the upstream assumption so a change to it fails there rather
  than in a shutdown path nobody runs.
- **A supplied key whose ownership transfers is consumed from the config.**
  `OwnsStaticKey` recorded the backend as owner but left the pointer in the
  caller's config, so a second construction from the same config produced two
  owners of the same protected pages and whichever closed first freed pages
  the other's session was reading. This is the mirror of the write-back
  hazard fixed earlier in this release: that one added a key the caller never
  supplied, this one failed to remove one the caller gave away.
- **Connection teardown detaches its generation before draining.** The
  bounded drain releases the connection mutex — that is what lets in-flight
  operations finish — and a concurrent `Connect` could publish a new
  transport, session and key in that window. Teardown then cleared the new
  session and destroyed the new key. It now snapshots what it is tearing down
  before the wait and destroys only that.
- **`MessageRouter.Start` registers under the router mutex, and `Join`
  refuses to report a drain before `Stop`.** The single-waiter join latches
  whatever it first observes, so a `Join` running before `Start` could latch
  "drained" on an empty wait group and keep reporting success while the
  receive loop was alive — telling the owner it was safe to destroy a key
  being actively read. `Start` is now a no-op on a stopped or already-started
  router, which is also what a `WaitGroup` requires: an `Add` from zero must
  happen before any `Wait`.
- **Every Noise static key now has exactly one owner.** Previously a
  generated key could be destroyed by a component that had merely borrowed
  it, or leaked because no component considered itself responsible. Ownership
  is decided once, at construction: a backend destroys the key it generated,
  or the one a caller explicitly transferred to it, and never one it
  borrowed.
- **The constructor no longer writes a generated key back into the caller's
  config.** A reused config would otherwise hand the next backend a key the
  first one owns and destroys, leaving the second reading freed protected
  pages. Ownership is now tracked in an unexported field the caller cannot
  observe or reuse.
- **Readers are synchronised against destruction, everywhere.** The USB
  transport serialises its whole `Connect`/`Close` lifecycle under one lock
  rather than checking a flag and acting on it later; `Connect` re-checks the
  closed state in-lock; the TCP pairing server and the BLE peripheral join
  their connection goroutines before releasing key material; the phone
  backend drains outstanding session leases before destroying anything.
- **`Close` retains an owned key rather than freeing it under an unjoined
  reader.** If the message-router join cannot be confirmed within its
  timeout, the key is deliberately NOT destroyed. Leaking protected pages is
  the safe failure mode; freeing pages a live goroutine is decrypting through
  is not.
- **`bootstrap.NoiseServerStaticKey` replaces an alias that no longer
  composed.** `NoiseStaticKey` became a protected `StaticKey` while
  `NoiseServerConfig.StaticKey` still took a `*noise.DHKey`, so the two
  re-exports could not be used together by an outside caller even though
  both compiled in isolation. The adapter returns a pair that aliases the
  protected pages rather than copying them.
- **Decoded key buffers are wiped on every path**, including the failure
  paths that previously returned early with the buffer live.

### Fixed

- **Every shutdown drain is bounded, not just the router join.** Three waits
  added by this release waited without a bound on work the package does not
  control, so each was a shutdown that could hang forever:
  `PhoneKeyBackend.Close` (waiting for session leases, while holding the
  mutex every other method needs), `BLEPeripheral.Stop` (waiting on a
  caller-supplied `RequestHandler` with a context it neither owns nor
  cancels), and the GUI phone service's teardown (waiting on a BLE round trip
  with a handset that may never answer).

  The bounded-join lesson had been applied at exactly one site and not
  carried to the shape. All four now go through one primitive, and all four
  take the same branch on timeout: retain the protected key, report it, do
  not free pages a reader may still be using.
- **The USB transport drops its bus handle when it closes it.** `Close` shut
  the underlying transport down but left it installed, and `Connect` only
  builds a new one when the field is nil. The production USB transport treats
  `Close` as terminal, so `ErrDirtyState`'s own advice — close, then
  reconnect — could not be followed: the dirty check passed and every
  reconnect handshaked over a dead bus. `Connect`'s own failure paths drop it
  too. The lifecycle tests missed this because their fake is reusable; there
  is now one whose `Close` is terminal.
- **A failed bridge setup no longer leaks the xkmsd client and TPM
  enroller.** `EnableBidirectional` gained an error return in this release,
  which gave `newPhoneBackendWithBridge` a failure path it never had, and
  the resources acquired above it have no other owner until the wrapper is
  built. It now mirrors the cleanup the adjacent `NewBridge` failure already
  did.
- **`xkmsctl bootstrap noise-key` no longer deletes a file it did not
  create.** The failure cleanup called `os.Remove(path)`, which unlinks
  whatever holds the name at that moment rather than the file the failure
  produced. Anything with write access to the parent directory could rename
  the partial key away and drop an unrelated file at the same path in
  between, and the cleanup would delete that instead. The removal is now
  gated on `os.SameFile` against a stat taken while the descriptor is still
  open; when identity cannot be established the file is left alone, because
  a stranded partial key is reported and refused by the next run's `O_EXCL`
  while a wrong unlink is silent and irreversible.
- **`MessageRouter` shutdown is split into `Stop()` and `Join(timeout)`.**
  `SendRequest` now registers on the wait group with a check-and-`Add` under
  the router mutex, so a request in flight cannot race a shutdown that has
  already observed an empty group. The previous unconditional wait could hang
  indefinitely, because `receiveLoop` blocks in an uncancellable
  `Transport.Receive` and only observes shutdown between messages. Making
  `Receive` cancellable is tracked as go-xkms#30 and is NOT required for
  memory safety — see the retention behaviour above.
- **`EnableBidirectional` returns an error, requires a connected backend, and
  is idempotent** instead of silently starting a second router.
- **`e2eprobe` tears down in order** — signal, unblock, join, then release —
  rather than relying on three LIFO defers whose order was wrong.
- Corrected a comment in `message_loop.go` that claimed `receiveLoop` manages
  its own lifecycle via the done channel. It does not; that claim is what
  made the original unconditional join look safe.

### Known limitations

- The phone-pairing Noise private key is persisted as base64 in YAML and held
  in an unwipeable Go string while loaded. See the guarantee note at the top
  of this release.
- `usb.NoiseConfig.LocalStaticPrivateKey` remains a public `[]byte`. It is
  caller-supplied rather than produced by this package, so it is part of the
  same storage-format question rather than a separable fix.
- **Which parts of this release are backed by execution, and which are not.**
  Worth knowing, because it is not uniform:
  - `xkey/pkg/phone`, `xkey/pkg/pairing`, `xkey/internal/lifecycle` and
    `pkg/trust/bootstrap` pass under `-race`, under the default tags and
    under `-tags ble`, and every behavioural fix in them has a test that
    fails against its own regression.
  - `xkey/cmd/xkey/cmd` **cannot compile its test binary under `-tags ble`**
    (go-xkms#31) — pre-existing on the v0.7.5-alpha tag, but it means that
    package's ble-tagged tests have never run.
  - `-tags usb` cannot be vetted or tested without libusb-1.0 headers, which
    CI does not install. That surface is verified by build and review only.
  - Ten packages in the `xkey` module and eight in the root module fail their
    tests, identically on v0.7.5-alpha and on this release. Three of the root
    ones need `-tags codec_json` and are red without it. The `xkey` module is
    not wired into CI at all, which is why nobody noticed. Nothing here
    regressed them and nothing here fixed them.

## [0.7.5-alpha] - 2026-08-19

### Security

- **Post-quantum seeds are wiped on every return, not only the happy path.**
  `generateMLDSAKey` and `generateMLKEMKey` wiped their source seed only after
  `sealSeed` succeeded, so a protected-memory or `mlock` failure returned with
  32/64 bytes of live seed still on the stack or heap — precisely the path
  where fail-closed cleanup matters. Both now `defer secure.Wipe(...)` as soon
  as the seed exists. (Codex review of PR #16, blocking finding 1.)
- **The FIPS allowlist now names its validated boundary exactly.** The comment
  claimed only ML-DSA and Ed448 come from CIRCL; ML-KEM-512 does too, because
  `crypto/mlkem` ships only 768 and 1024 and `pkg/quantum/mlkem512` wraps CIRCL
  for the 512 parameter set. The permitted set is unchanged — whether FIPS mode
  should reject CIRCL-backed algorithms outright is an owner ruling (#21).
  (Codex review of PR #16, blocking finding 2: valid, escalated not silently
  resolved.)
- **PIN lockout could stop counting under contention, and an attacker
  controlled the contention.** This is a security fix, not a test fix.

  The PKCS#11 failed-attempt counter is server-authoritative precisely so that
  several remote-mode clients sharing one token count their failures against
  one durable budget. `IncrementFailedAttempt`'s compare-and-swap loop gave up
  after 16 lost races and returned an error; the caller
  (`SetAttemptPersistence` in `module.go`) reports `persisted=false` on error,
  so **that failed PIN attempt never advanced the durable budget** and fell
  back to a per-process in-memory counter. Concurrent PIN attempts from several
  clients are exactly what produces the contention, so the condition that
  disables the lockout is the condition an online guessing attack creates.
  A caller that keeps losing can therefore keep guessing.

  Two defects made the loop lose races it should have won. It discarded the
  current value that a failed `CompareAndSwap` returns — the
  `CompareAndSwapper` contract supplies it so a caller can recompute and retry —
  and re-read through a separate, unsynchronized `Get`, reopening the window
  between observing the counter and swapping it. And the 16-attempt budget was
  mismeasured: a losing writer's retry count is not a function of how many
  clients contend, because the loser is descheduled while the winner keeps
  incrementing, so one competitor can beat it an unbounded number of times in a
  row. Reproduced with only TWO writers under `-race` at `GOMAXPROCS=2`.

  Retries now recompute against the value the failed swap itself observed, the
  budget is 1024 with a yield on each loss, and a single `opContext` deadline
  bounds the whole loop instead of a fresh 10s timeout per attempt. Verified at
  5000 iterations with zero failures where 3000 iterations previously failed
  repeatedly.

### Fixed

- **`gofmt` compliance in `xkey/cmd/xkey/cmd/trust_fetch_test.go`.** `gofmt`
  does not respect module boundaries, so the root Lint job format-checks
  `xkey/` even though every other job treats it as the separate module it is.
  One unformatted file there failed CI's Lint job at its first step while
  passing every root-module-only local check.
- **Reciprocal cross-module pins refreshed to the released version.** `xkey`
  and `sdk/go` recorded `go-xkms` and each other at `v0.7.1-alpha` while the
  repo had released `v0.7.4-alpha`. The local-path `replace` directives resolve
  every in-repo build — and CI's own builds — through the working tree, so the
  stale requirement was invisible to `go list`, to zip inspection and to every
  local check, while a consumer resolving `sdk/go` or `xkey` at the new tag
  would have been handed `go-xkms v0.7.1-alpha`. This is the defect
  go-qrdb `v0.2.0-alpha` shipped; release-versioning.md §2 names go-xkms as
  carrying the same exposure.
- **Race Detector no longer dies on a busy runner**: the job passes
  `-timeout 30m` instead of relying on `go test`'s 10-minute per-package
  default. `pkg/pkcs11/module` is the only package the `pkcs11` build tag
  exercises, and its ~1400 tests each pay a production-cost Argon2id PIN
  derivation, so under contention the package alone exceeds ten minutes.
  The same commit passed on a quiet runner and failed on a loaded one,
  alternating across consecutive runs — starvation, not a hang.
- **Docker Build & Scan no longer fails on the BuildKit cache**: `type=gha`
  is now requested only on github.com. On Gitea the Actions cache server is
  advertised on an address buildx cannot route to (buildkit runs in its own
  container on the default bridge), and the build died on
  `connect: connection refused` before any layer was built.

### Changed

- **`GOPROXY` / `GOSUMDB` removed from the CI environment** (ci-template v1.1
  prohibition). The runners inject `GOPRIVATE`, which already exempts
  first-party modules from the proxy and the checksum database; the blanket
  `GOSUMDB: off` had disabled checksum verification for every third-party
  dependency as well.
- **`make trivy-image` matches the CI image gate** by passing
  `--ignore-unfixed` (devops.md §8), so the local target reproduces the gate
  it claims to mirror instead of failing on unfixable base-image advisories.
- **Integration Tests is advisory, not required** (ruled 2026-08-18, the same
  demotion go-quicbaas already carries). The job still runs on every commit and
  its result is still printed by the CI Gate; it simply no longer blocks. It has
  passed once in 40 executions and never on `main`, because `run_with_server`
  uses `[ -f /.dockerenv ]` to mean "am I the devcontainer" and that is true
  inside the Actions job container (#19). A required check that has never passed
  detects no regression and blocks every merge. It returns to required when
  #19's harness rebuild lands.
- **`go-luks2` bumped to v0.1.7-alpha.** `go-truststrap` is deliberately HELD at
  v0.1.3-alpha: v0.1.4-alpha reshapes `pkg/noiseproto` (`StaticKey` replaces
  `*noise.DHKey`, `EncodeStaticKey` takes a destination buffer), and
  `go-qrdb v0.5.9-alpha` consumes that package and has not caught up, so the
  bump breaks the build in a dependency this repo does not own.
- **A zero-byte `pkg/server/audit-events.ndjson` is no longer tracked.** It is a
  runtime artifact — `pkg/server/server.go` writes the audit sink to a relative
  path when no storage path is configured — and `.gitignore` already listed it.
- **CI no longer runs every commit twice**: `.github/workflows/ci.yml` scopes
  its `push` and `pull_request` triggers to `main` (ci-template v1.5), the sole
  trunk since `develop` was folded into it. A branch that was both
  push-triggered and a PR head produced two full runs of the same commit — one
  `push`, one `pull_request` — and this Gitea has no working supersession, so
  the duplicate ran to completion. `master` and `develop` no longer exist as
  branches, so nothing loses coverage. A `concurrency:` block is deliberately
  **not** used: on Gitea 1.27.1 a job carrying a concurrency group is cancelled
  even when the group is unoccupied.
- **Cross-repo dependencies bumped to their latest tags** (root, `sdk/go`,
  `xkey`): go-frost v0.1.7→v0.1.8-alpha, go-objstore v0.2.1→v0.2.2-alpha,
  go-qrdb v0.5.7→v0.5.9-alpha (and `go-qrdb/sdk/go` v0.5.7→v0.5.9-alpha),
  go-quicraft v0.4.2→v0.6.2-alpha, go-truststrap v0.1.2→v0.1.3-alpha.
  go-codec (v1.4.0) and go-luks2 (v0.1.6-alpha) were already current.
- **go-truststrap typed errors renamed at the source**: `ErrPinNotFound` →
  `PinNotFoundError` and `ErrNilPin` → `NilPinError`. Call sites in
  `pkg/trust/bootstrap` follow; the field shapes are unchanged. This repo's
  own `resolver.ErrPinNotFound` is a different type and keeps its name.
- **SPKI pin bootstrap verifies through `VerifyConnection`**, not
  `VerifyPeerCertificate`. go-truststrap made the switch because
  `VerifyPeerCertificate` is skipped on a resumed session, which would let a
  resumed connection bypass the pin; it also disables session tickets.
  `NewSPKIPinTLSConfig` is a passthrough, so this repo inherits the fix.

### Removed — BREAKING (Go SDK)

- **`sdk.QRDBCachedDiskBackend` and `sdk.QRDBNewCachedDiskBackend`** are gone.
  They were pass-through aliases for `qrdb.CachedDiskBackend` /
  `qrdb.NewCachedDiskBackend`, which go-qrdb removed in v0.5.9-alpha with no
  replacement. Nothing in this repo consumed either alias. Callers needing a
  read-through cache in front of a disk backend must supply their own.

## [0.6.0-alpha] - 2026-08-17

### Changed — BREAKING: login plane unified (mTLS + FIDO2 + PIV)

- **`auth.type: "adaptive"` is removed** and fails startup with a typed
  error naming the replacement. First boot provisions the administrator
  and their mTLS credential at startup, so there is no pre-credential
  window to bridge. All shipped configs use `type: "composite"`.
- **Composite derives the session-vehicle chain** when no methods are
  configured: jwt (the pairs the FIDO2/PIV login ceremonies mint; present
  when a verification key or the built-in issuer exists) + mtls (when TLS
  is enabled). Single-vehicle chains keep the concrete authenticator.
- **Authentication on the unified server is qrdb's, single-pass**: the
  module implements `qrdbsdk.ModuleAuthFallback` — qrdb's mTLS chain runs
  first, xkms's session-vehicle chain second, and qrdb's ONE authorizer
  (store-resolved roles) decides. `BindRoute` no longer applies inline
  authentication, ending the double-auth pass.
- **Embedded node auth is explicit**: `buildXKMSQRDBConfig` mirrors
  xkmsd's `auth.enabled` onto the node (qrdb ≥0.5.2 is fail-safe anyway),
  with SPIFFE pinning when configured. Requires go-qrdb v0.5.5-alpha.

### Added

- **SDK login plane** (`sdk/go/login.go`): `NewLoginClient` with
  `PIVLogin` (PIV slot certificate as the TLS client credential),
  `Refresh`, `Logout`, `Validate`. The WebAuthn (FIDO2) ceremony remains
  the six-transport Servicer surface; `WithXKMSFactorVerifiers` remains
  the canonical verifier export for embedders.
- **Chained-file audit fallback** (`pkg/audit.ChainedFileLogger`):
  deployments without a qrdb client audit to a local tamper-evident
  chained file with the identical record shape — never a silent NoOp.

## [0.5.0-alpha] - 2026-08-16

### Changed
- **Re-pinned go-qrdb to v0.5.1-alpha.** The embedded node now enforces
  authentication and authorization on every unified-server route (qrdb
  `pkg/auth/wiring`), and carries the sealed-store crash-durability fix
  (a killed node previously lost its root key and orphaned all encrypted
  data). Do not use qrdb v0.5.0-alpha (truncated SDK error surface).
- **Adaptive authentication now composes JWT and mTLS.** A JWT-only chain
  locked out the first-boot administrator the moment their own creation
  flipped adaptive mode to enforced: cert-based enrollment is the
  bootstrap plane, so the SPKI-bound admin certificate must authenticate.
- **The system tenant is no longer a storage scope.** The tenant-scoped
  backend resolvers treat the system tenant like the platform scope via
  qrdb's canonical `IsSystemTenant` predicate; previously a system-scoped
  caller's sign/encrypt could not see keys the unscoped create had stored.
- **Local IPC stays plaintext and xkmsd-owned.** The Unix socket is no
  longer mapped onto the embedded node (qrdb transports are TLS-only, and
  the local plaintext clients — the PKCS#11 module, the CLI, the SDK unix
  transport — depend on the filesystem-permission trust model). xkmsd
  serves its own socket in every storage mode.
- **Unified server TLS honors `tls.client_auth`** with a rotating
  client-CA pool: operator files seed it and the embedded CA's bundle
  replaces it after composition, so admin-mTLS clients verify without
  operator-managed files.
- **Server certificates cover the deployment's names.** Locally issued
  serving certificates (bootstrap and CA-issued) now carry the machine
  hostname, the configured listen host, and — because the CA-issued
  certificate replicates cluster-wide keyed by CN — every cluster peer's
  hostname.

### Added
- **Module role grants** (`pkg/apimodule/module_grants.go`): at module
  construction xkms derives its full permission set (REST route table ∪
  MCP method specs ∪ gRPC proto options), registers it into qrdb's global
  permission registry, and grants it to the Admin and Owner built-in
  roles. Without this every xkms operation would be denied on the
  authenticated unified server, including to the first-boot admin.
- **Boot-time leader retry** (`pkg/server/leader_retry.go`): first boot,
  TLS certificate issuance, and JWT signing-key provisioning retry
  not-leader failures while a cluster's initial election settles.

### Fixed
- **First-boot Path A now delivers the admin key.** `GenerateAdminCert`
  generates the administrator's key pair locally and has the CA sign a
  CSR — the credential never enters platform key custody, and the
  generate-and-distribute pair is actually distributable (previously the
  CA path never returned a private key and the credential was silently
  dropped).
- **Trust bootstrap defaults to the public first-contact route**
  (`/v1/ca/bootstrap`); the authenticated `/api/v1/ca/bundle` default
  only ever worked through the adaptive-auth anonymity window that
  mandatory first boot now closes.
- **CA root and CSR key generation tolerate lost creation races** in a
  cluster: on `ErrKeyAlreadyExists` the winner's key is fetched instead
  of failing boot.
- The 3-node cluster integration harness authenticates as the first-boot
  administrator over mTLS, probes the qrdb admin plane (`/peers`) for
  leadership, and passes 17/17 including leader failover and killed-node
  rejoin.

## [0.4.0-alpha] - 2026-08-14

### Changed — BREAKING: network serving is the unified API server; legacy transport stacks removed (Phase 4 complete)
- **The legacy "MCP" line-framed JSON-RPC-over-TCP plane is replaced by the real Model Context Protocol.** The server side is qrdb's Streamable HTTP MCP endpoint (`https://host:mcp_port/mcp`); every xkms JSON-RPC method is an MCP tool (`xkms_<method>` with dots as underscores, one optional `params_json` string argument carrying the params object verbatim). `pkg/api/mcp` retains only the dispatch core (`NewServer` + `InvokeMethod` + the tenant/authorization gates) backing the module's tools; the TCP/UDS listener, wire framing, and the `xkms.subscribe` notification plane are deleted. The MCP client transport (`pkg/api/transport/mcp`) now speaks real MCP (mcp-go Streamable HTTP with mTLS) — its ~120 typed methods and their payloads are unchanged.
- **Enabling any network protocol (`rest`, `grpc`, `quic`, `mcp`) now requires `storage.backend: qrdb` and `tls.enabled: true`** (enforced by config validation): the embedded qrdb node's multi-protocol server takes xkmsd's ports and serves the capability plane through the registered `ServiceModule`. The legacy per-transport network listeners are deleted (`pkg/api/quic` removed wholesale; the in-process gRPC/MCP/REST network listeners in `pkg/server` removed). Local IPC is exempt: the Unix socket still serves in-process for non-qrdb storage, and the desktop loopback engine still serves its injected listener. **QUIC is now HTTP/3 on the REST port** (advertised via `Alt-Svc`); the QUIC client transport dials the REST port. TLS material is operator `cert_file`/`key_file` when configured, otherwise a persisted node-local bootstrap certificate serves from first boot and is replaced in-place by the CA-issued certificate once the CA composes. The embedded web UI registers on the unified server (public prefix routes, lazy SPA binding). The QUIC client's stale legacy dialect was migrated to the shared `/api/v1` forms — including 12 previously broken routes (8 PIV paths missing the `/api` prefix, 4 TCG-CA paths on a removed route family).

### Added
- **Unified API server — full module surface (Phase 3 waves 2+3) + cutover switch (Phase 4)**: The xkms `ServiceModule` now carries all three unified-server surfaces. *HTTP*: the REST surface is table-driven — new `pkg/api/rest/routes.go` (`RouteSpec`/`Routes()`) is the single source for both the legacy chi router and `Module.RegisterHTTP`, which registers every route through qrdb's permission-recording registrar (public → `HandlePublic`, authenticated-session → `identity:gated`, permission routes → `resource:action`), late-binding handlers via `pkg/server.ModuleRESTServer()` (503 while composing, 501 for absent subsystems) with legacy group middleware reapplied per route (`rest.BindRoute`). *MCP*: every xkms JSON-RPC method (including the frost namespace) registers as a real mcp-go tool (`xkms_*`, `params_json` parity argument) dispatched through the new connectionless `mcp.Server.InvokeMethod`, which runs the same tenant + authorization gates as the wire path. *Cutover*: new `server.unified_api` config hands the embedded qrdb node's server xkmsd's REST/gRPC/Unix/MCP ports and stands the corresponding legacy listeners down (QUIC/Noise stay legacy pending a qrdb `RegisterQUIC` hook); the composition-time `XKMSService` publish is now mutex-synchronized. At go-qrdb `v0.3.0-alpha`, module MCP tools remain fail-closed under qrdb auth middleware until qrdb exports a module tool-permission registry hook.

### Changed — BREAKING: cluster/auth-factor proxy planes replaced by the qrdb SDK (unified API server Phase 2)
- **xkmsd no longer ships its own cluster/rebalance proxy surface.** The hand-authored cluster plane (`pkg/xkms/servicer_cluster.go` mutation surface, `pkg/api/rest/handlers_cluster.go`, `pkg/api/grpc/service_cluster.go`, the `Cluster*` proto RPCs, `pkg/auth/permissions_cluster.go`, and the per-transport cluster handler/tests) is deleted; xkmsd hosts go-qrdb's own control plane on the embedded node (`pkg/server/qrdb_control_plane.go`) and `xkmsctl cluster|rebalance|factors` drive the `qrdbsdk.Client` directly. The internal `ClusterLeaderEndpoint` + NotLeader redirect behavior is retained. Wire consumers of the removed `Cluster*` KeystoreService RPCs must move to the qrdb control-plane surface.

### Added
- **Unified API server seam — go-xkms as a qrdb `ServiceModule` (Phase 3 wave 1)**: New `pkg/apimodule.Module` registers the wholesale `KeystoreService` gRPC surface (lazy service binding; `Unavailable` until composition completes) into the embedded qrdb node's multi-protocol server under the module name `xkms`, wired via `qrdbsdk.WithModule` in `pkg/server/qrdb_node.go`. Per-RPC authorization rides `option (qrdb.v1.permission)` annotations on all 143 RPCs (locked by `authz_proto_option_test.go`; unannotated ⇒ default-deny). The stack convention is one module per provider project, named after the project; the module is re-exported through `sdk/go` (`NewServiceModule`, `ServiceModule`, `ServiceModuleName`) so downstream hosts (go-quicbaas, go-trusted-platform) register it without importing `go-xkms/pkg`. Registration is additive: the legacy transport stacks keep serving until the Phase 4 cutover.

### Changed
- **go.work machinery fully removed (dependency-resolution cutover completion)**: Deleted `scripts/gen-gowork.sh`, `.devcontainer/scripts/ensure-gowork.sh`, every sibling bind-mount/`additional_contexts` block, and every `GOWORK=/tmp/go.work` reference across the Makefile, devcontainer, root `Dockerfile`, and all integration Dockerfiles/compose files. Container builds now resolve first-party modules from Gitea tags: runtime lanes get the `GOPRIVATE` + `insteadOf` environment (token from the gitignored `.devcontainer/.env`), image-build-time fetches use an optional `gomodauth` BuildKit secret (staged by `make stage-gomodauth`; never a layer, never build context). First-party pins bumped and exercised workspace-free: go-qrdb `v0.3.0-alpha` (root + `sdk/go`), go-codec `v1.4.0`, go-quicraft `v0.3.1-alpha` — in the root, `sdk/go`, and `xkey` modules.

### Changed
- **Typed-error migration (~6,050 sites)**: Replaced ad-hoc `fmt.Errorf` construction across the entire repository with the house typed-error pattern -- the new `pkg/errs` package (`Message`, `Wrapped`, `Detail`, `Affix`, `Joined`, all `errors.Is`/`errors.As`-transparent via `Unwrap`) plus per-package sentinel and typed errors. Breakdown: xkey 1,573 sites, cmd/ + sdk 785, pkg/ 3,689, with the remainder in tests, integration suites, and examples. Rendered messages are preserved byte-for-byte; wrapped causes keep participating in `errors.Is`/`errors.As` chains.
- **Health/validation adoption onto the qrdb SDK**: xkms now consumes the go-qrdb SDK health-check and configuration-validation surfaces instead of carrying local copies; roughly 2,950 LOC of dead parallel implementation was deleted.
- **SSH SDK TLS dedup**: The SSH client transports now share a single TLS configuration builder in `sdk/go/transport/tls.go`, removing the per-transport duplicated TLS setup.
- **Raft mTLS onto the qrdb SDK boundary**: Inter-node Raft mTLS provisioning now flows through the go-qrdb SDK `WithRaftMTLS` option instead of a local wiring path, keeping the locked SDK boundary intact.
- **Stale go-trusted-ca header sweep**: Rewrote the stale `go-trusted-ca` license/attribution headers left from the CA merge across 652 files to the canonical go-xkms header.
- **Floci replaces LocalStack for AWS KMS emulation**: The `awskms` integration suite and the shared `docker-compose.emulators.yml` now use `floci/floci` (MIT-licensed, ~24ms startup, successor to the sunset LocalStack Community Edition) instead of `localstack/localstack`. Floci is a drop-in on port 4566; the full asymmetric matrix (ECC P-256/P-384/P-521, RSA 2048/3072/4096, RSASSA-PSS, sign/verify/GetPublicKey) was validated against the emulator. `LOCALSTACK_ENDPOINT` is replaced by `FLOCI_ENDPOINT` (`AWS_ENDPOINT_URL` remains the primary override). The Azure Key Vault emulator and HashiCorp Vault services are unchanged — floci-az implements Key Vault secrets only (no `/keys` crypto operations), so it cannot replace the Azure emulator.

### Added
- **Local system SSH integration (xkey as a GUI over your local SSH setup)**: New `pkg/ssh/local` (re-exported via `sdk/go/client/ssh`) parses `~/.ssh/config` + `/etc/ssh/ssh_config` read-only (Host/HostName/User/Port/IdentityFile/IdentityAgent, Include, `%h/%d/%r/%p` tokens), discovers default `~/.ssh` identities (`id_rsa` … `id_ed25519_sk`), and signs through the system SSH agent (`$SSH_AUTH_SOCK`) — the only signing path for FIDO2 `sk-` keys — falling back to parsing unencrypted identity files. xkey's SSH view gains a read-only **Local** key source (agent + file keys) and a **"From ~/.ssh/config"** connections section; connecting to a config host honors the selected console mode (embedded console with agent signing, or system-terminal **passthrough** that runs plain `ssh <alias>` with zero overrides so native ProxyJump/IdentityFile/known_hosts semantics apply). CLI parity: `xkey ssh local hosts|keys`, `xkey ssh connect --local [--ssh-config-alias]`, profile `--key-source`/`--ssh-config-alias`.
- **Embedded SSH console trust-on-first-use (TOFU)**: The WebSocket console protocol gained a host-key confirmation round trip (`{"type":"hostkey",...,"mode":"confirm"|"notify"}` / `{"type":"hostkey-response","accept":bool}`). Host-key policy (`yes`/`ask`/`accept-new`) and known-hosts policy (barrier store / `~/.ssh/known_hosts` / both) now apply to the embedded console exactly as to the system terminal: `ask` shows an in-console Accept/Reject fingerprint prompt (60s server timeout), `accept-new` auto-pins with an informational notice, and a **changed** host key always hard-fails regardless of policy. Implemented via `known_hosts.CallbackWithConfirm` + new `ConsoleTarget.HostKeyPolicy`/`KnownHostsExtraFiles`/`KnownHostsSkipStore` in the SDK; TypeScript SDK `SSHConsoleClient.onHostKey` is fail-closed (no handler ⇒ reject).
- **Searchable SSH key picker (any backend + local keys) in xkey's connect/profile dialogs**: The New Connection and Profile dialogs replace the managed-keys-only `<select>` with one type-to-search combobox (`SSHKeySelect.svelte`) listing **xKey keys** (unified SSH store, any backend, labeled with algorithm + backend) and **Local keys** (every system ssh-agent key plus `~/.ssh` identity files), filtered by name/comment/fingerprint/path/backend — built for machines with many keys. A local selection persists as `key_source: "local"` + a new `local_identity` field (`Profile.LocalIdentity`): an identity file path, or `agent:<SHA256-fingerprint>` for an agent-held key (e.g. FIDO2 `sk-`). System-terminal connects pass a file identity as `ssh -i`; embedded-console connects resolve the pinned signer via the agent/identity file. The shared resolver is `sdk/go/client/ssh.ResolveLocalSigners` (`LocalKeySelector{Identity|Alias|Host}`), consumed identically by the GUI console service and the CLI; multi-signer public-key auth (`session`/`console`/`ConsoleTarget.Signers`, `OpenConsoleWithSigners`) offers every candidate in order, OpenSSH-style. CLI parity: `xkey ssh connect|console --identity <path|agent:fp>` (implies `--local`), `xkey ssh console --local`, profile `--identity`.

- **Opt-in persistent console sessions**: Embedded-console sessions are memory-only by default; a session specifically started with **Persistent session** enabled (New Connection checkbox, the *Persistent console session* profile option, or `xkey ssh profile add --persist-session`) is recorded in the shared barrier-routed SSH store (`pkg/ssh/sessions`, re-exported as `sdk/go/client/ssh.ConsoleSessionStore`) — title + reconnect origin only, never key material or live connection state. Persisted tabs are restored disconnected (Reconnect one click away, never auto-dialing at startup) whenever the SSH view loads: after navigation, a webview reload, or a full app restart; closing a persisted tab deletes its record. CLI parity: `xkey ssh sessions list|rm`. Coverage: store CRUD unit tests, console-service session tests, CLI integration tests proving GUI↔CLI store compatibility, Vite Playwright specs for the opt-in surfaces (default OFF), and live Playwright E2E proving a persisted session survives a reload and reconnects while a default session leaves no record.
- **Tabbed multi-session embedded SSH console**: The embedded console panel now manages multiple simultaneous sessions as tabs, like a system terminal. Every embedded connection (one-time, profile, or ssh_config host) opens its own tab with a `user@host` title, live/ended status dot, and per-tab close; a `+` in the tab strip opens the New Connection dialog. Inactive tabs stay mounted so their WebSocket/SSH sessions keep running with scrollback intact; an ended session's tab offers an in-place **Reconnect** (a fresh one-time ticket minted from the tab's remembered origin — reconnects to a pinned host are prompt-free). Backend hygiene: the console service purges abandoned (issued-but-never-connected) tickets after 2 minutes. Coverage: service-level concurrent-session WS test (`TestSSHConsoleE2E_ConcurrentSessions`) + ticket-TTL test, a concurrent two-process CLI integration test (`TestSSHConsoleConcurrentSessions`), Vite Playwright specs for the tab mechanics, and live Playwright E2E driving two real SSH sessions across tab switches plus the reconnect flow.

### Fixed
- **`ssh/console` Close returned io.EOF on peer-first teardown**: `Console.Close` closes stdin before closing the SSH session; when the remote command exits on that EOF first, `x/crypto/ssh` reports the already-closed channel as `io.EOF`. Close now treats that as a clean close (the session is terminated either way) instead of surfacing a spurious error.
- **Embedded SSH console dead on first contact (strict host-key default + unapplied Settings)**: `SSHConsoleService`'s built-in host-key policy was strict (`"yes"`) while the Settings page *displayed* "ask" without ever applying or persisting it — the value only reached the backend when the dropdown was touched, and reset on every restart. On a fresh install (empty pin store) every first-contact embedded connection therefore hard-failed before the TOFU prompt could appear, while the system terminal worked (its service already defaulted to "ask"). The console service default is now `"ask"` (invalid values also reset to it), and the host-key checking + known-hosts policies are persisted (`localStorage`) and re-applied to both SSH services at app startup, so the backend always enforces what Settings shows. Coverage that proves the console *works* end-to-end: service-level WS tests (`TestSSHConsoleE2E_*` — first-contact prompt/accept/reject, strict-policy regression, no-key agent flow), CLI integration tests (`TestSSHConsoleLocalIdentityFile`, `TestSSHConsoleNoKeyAgentFallback`, updated no-key semantics), and a live Playwright E2E (`SSH Embedded Console — live E2E`) that drives the real GUI against a real SSH server (`xkey/test/e2esupport/sshechod`): key picker → TOFU accept → live terminal echo → pinned reconnect, plus a reject path.
- **SSH connections without a key failed instead of using agent/password auth**: With an empty key store (or "No key" selected) the system-terminal connect tried to resolve a nameless xkey-managed key and failed before any terminal opened, and the embedded console opened a dead panel whose signer failure surfaced only as an opaque WebSocket 403. A key-less connection now behaves like typing `ssh user@host`: the system terminal runs a plain passthrough `ssh` (system agent or interactive password prompt), and the embedded console offers every local agent/identity signer, OpenSSH-style. Embedded-console signer resolution moved from the WebSocket upgrade to `OpenConsole` time, so a bad key reference (missing managed key, unknown agent fingerprint, passphrase-protected identity) surfaces as a real error notification in the dialog instead of a dead console panel; `openConsole`/`connectOneTime` failures now report the underlying reason. Same fallback in the CLI: `xkey ssh connect|console` without `--key` uses local identities instead of erroring.
- **xkey SSH store: wrong location, no encryption, GUI/CLI split**: The GUI opened its SSH store at a CWD-relative `"ssh"` path (ignoring the data directory) and never routed it through the barrier; the CLI used a separate hardcoded `~/.xkey-store/ssh`. Both now share one store via `xkey/pkg/sshstore` — barrier-routed (encrypted at rest, with one-shot migration of legacy plaintext stores to `*.pre-barrier.bak`) when the barrier is active, otherwise an engine store at `<data-dir>/ssh`. SSH wiring moved from `NewApp` into `initializeDataDir` so it no longer races the barrier unseal. First-contact embedded console connections no longer hard-fail with `pin not found` (see TOFU above).
- **Duplicate xterm.js in the xkey bundle**: `sdk/ts` (imported as source) pinned xterm v5 while the frontend shipped v6, so two Terminal implementations could bundle; unified on `@xterm/xterm@^6` + `@xterm/addon-fit@^0.11` with Vite `resolve.alias`/`dedupe` guaranteeing a single copy.
- **Unix gRPC socket server Stop/Start shutdown race**: If `Shutdown` ran while `startUnix` was still inside `unix.GRPCServer.Start` (before the gRPC server was assigned), `Stop` found a nil server, did nothing, and the subsequent `Serve` blocked forever — hanging daemon shutdown until the 30s force-stop and leaking the serving goroutine. `Stop` now records a stopped flag that `Start` checks under the same lock before serving, releasing the listener and socket as a clean shutdown. Regression test: `TestGRPCServer_StopBeforeStart`.

- **Real GCP Cloud KMS emulator lane (floci-gcp)**: The `gcpkms` integration suite now runs `TestGCPKMSEmulator` against `floci/floci-gcp` over genuine gRPC — real, locally verified RSASSA-PKCS1 and ECDSA P-256 signatures, symmetric AES-256-GCM round-trips, and key lifecycle — replacing mock-only coverage for those algorithms. Algorithms floci-gcp does not implement (EC P-384, RSA-PSS) remain covered by the mock and opt-in real-cloud suites. The GCP KMS backend gains an `Insecure` config option (requires a custom `Endpoint`; plaintext unauthenticated gRPC for local emulators only), also exposed as the `insecure` backend-registration key.
- **Pluggable cluster CA key custody (`ca_key_strategy`) — any node can issue**: A new `ClusterCAKeyStrategy` seam (`pkg/trust/clusterca`, re-exported via `sdk/go/clusterca`) decides where the cluster CA signing key lives and which nodes issue node certificates, so every product (xkmsd, quicbaasd) behaves identically from a one-line config choice. `barrier` (default) bootstraps the key node-local, then promotes it into the qrdb-routed replicated barrier-encrypted datastore — every node loads it (each decrypting with its own barrier), so **any node can issue**, not just the first. `hsm` keeps the key inside a shared PKCS#11 HSM that every node signs through by reference (key material never leaves the HSM; FIPS-grade). `tpm-kek` wraps the replicated CA key under a KEK derived from a cluster seed that the bootstrap node seals to its local TPM and delivers to each joining node via **TPM credential activation** (`MakeCredentialWithExternalEK`/`ActivateCredential`) during attested enrollment — hardware-rooted without a shared HSM. Seed delivery is intentionally decoupled from enroll-01 via a neutral `NodeSecretProvider` seam, an optional `EnrollmentSecretStrategy` interface (type-asserted, so `barrier`/`hsm` are unaffected), and a reusable post-enrollment `SecretDeliveryService` fetch — all re-exported through `sdk/go/clusterca`. All three strategies are wired live in both xkmsd and quicbaasd: the shared TPM (from the seal strategy) supplies the credential activator, the delivery endpoint is mounted on each node's server, and a joining node fetches + activates its wrapped seed after enrollment. A `tpm_simulator` integration test validates the real credential-activation round-trip. `tpm-kek` requires every node to have a TPM and fails closed otherwise. See `docs/cluster/README.md`.
- **Touch-free ACME-attested Raft cluster enrollment**: A new `cluster.raft_enrollment.acme` mode provisions inter-node Raft mTLS with the runtime TrustedCA as the single cluster trust anchor. The first node pre-stages the CA hierarchy, issues its own transport leaf, and caches the full CA certificate set (adopted on later boots so `Load` finds every intermediate without forking a second root); joining nodes prove TPM residency via enroll-01 to an existing node's ACME directory (no shared CA private key distributed). Node certificates carry their SPIFFE identity (`spiffe://<trust-domain>/node/<raft-address>`) as a URI SAN, and transport issuance routes through a dedicated cluster intermediate (`cluster_ca_cn`) — root signs intermediates only (FedRAMP/PCI posture). The shared provisioning toolkit (`pkg/trust/clusterca`, re-exported via `sdk/go/clusterca`) — including `NewNodeLocalBackends` for pre-node cluster CA key protection — is consumed identically by every product in the stack. enroll-01 (attestation-gated self-enrollment) and endorse-01 (EAB-admin-gated admission) remain distinct admission models. See `docs/cluster/README.md`.
- **Cluster CA key protection at rest**: The node-local cluster CA signing keystore (which must exist before the replicated datastore, so it lives outside the barrier) is protected via the canonical seal strategies through `cluster.raft_enrollment.ca_key_protection` (`""` auto → TPM/HSM → passphrase → refuse; `tpm2`/`pkcs11`; `passphrase`; or `none`). Auto mode never silently falls back to plaintext, and `config.ComplianceGaps` refuses a plaintext (`none`) cluster CA key unless the daemon is started with `--insecure`.
- **Node-barrier data-plane encryption (encrypted-at-rest key stores)**: On an embedded qrdb deployment (`storage.backend: qrdb`) with the barrier enabled and an auto-unseal credential (a boot passphrase or a TPM/HSM seal strategy), xkms now uses the qrdb node's own barrier, which `encfs`-encrypts the entire PebbleDB data plane — so the crypto backends' key stores (TLS, ACME, and general keys) are encrypted at rest, closing a plaintext-on-disk gap. This mirrors go-quicbaas so both products drive the identical shared seal mechanism (`pkg/server/node_seal.go`, `qrdb_node.go`). Falls back to xkms's own barrier for non-qrdb storage or when no auto-unseal credential is present.
- **Unified seal provisioning (config / CLI / env)**: `barrier.strategy`/`barrier.passphrase` config, `XKMS_SEAL_STRATEGY`/`XKMS_SEAL_PASSPHRASE` env vars, and the `xkmsd --seal-passphrase` flag (precedence CLI > env > config) provide the boot-time auto-unseal secret. TPM/hardware strategies auto-unseal from the device with no boot secret; the TPM open is shared with the general TPM2 backend (single device open).
- **Canonical hardware-seal autodetect (SDK)**: `sdk/go.BuildBestSealStrategy` / `ProbeSealStrategies` (`pkg/seal/autodetect.go`) are the single stack-wide implementation of the non-provisioning, single-open TPM probe; go-quicbaas's `seal_autodetect.go` now delegates to it (removing a duplicate).
- **Secure-by-default gap for un-unsealable barriers**: `config.ComplianceGaps` now flags a `qrdb` + barrier deployment that cannot auto-unseal (a passphrase strategy with no boot secret), so the daemon refuses to start it (leaving backend keys plaintext) unless `--insecure` is set. The canonical seal vocabulary (`awskms`/`gcpkms`/`azurekv`/`passphrase`) is now accepted across xkms credential-seal validation and go-trusted-platform's barrier config, with backward-compatible aliases.
- **Embedded SDK tenant-scope enable-encryption**: The qrdb SDK now exposes `node.WithTenantIsolation()` and `node.EnableEncryption(ctx, scope, opts)` for standalone and clustered nodes; embedded nodes now have full daemon parity for per-tenant encryption migration via the shared `pkg/server.BuildTenantInfra` composer.
- **Credential-free enable-encryption sources**: Tenants starting with `StrategySystemBarrier` (system-managed auto-unseal) or `StrategyNone` can now transparently migrate to keyed strategies (passphrase / shamir / hardware) without supplying unlock credentials; truly-shared-barrier tenants are rejected via `ErrSharedBarrierImmutable`.
- **qrdb SDK re-exports for entitlement errors**: `go-qrdb/sdk/go` now re-exports `ErrSharedBarrierImmutable`, `EntitlementError`, migration error sentinels, and the `EncryptionMigrator` interface for downstream integration.
- **Standalone DKEK Package**: New `pkg/dkek/` package provides backend-agnostic Device Key Encryption Key support using Shamir's Secret Sharing. Works with any storage backend, no longer tied to PKCS#11.
- **SymmetricKeyProvider parity**: All symmetric-capable backends (AWS KMS, GCP KMS, Azure KV, Vault, PKCS#11, TPM2, Software, Symmetric) now implement `SymmetricKeyProviderWithTracking` with `GetTracker()` for AEAD safety tracking.
- **TPM2 Backend SymmetricKeyProvider**: The TPM2 backend (`pkg/backend/tpm2/`) now implements `SymmetricKeyProvider` interface, exposing `GenerateSymmetricKey()`, `GetSymmetricKey()`, and `SymmetricEncrypter()` through the Backend layer.
- **XKMSServicer unit tests**: Comprehensive test suite for `pkg/xkms/` servicer (368+ tests, 80.5% coverage) covering keys, crypto, certificates, sealing, barrier, PIN, user, platform store, shares, custodian, policy, and password operations.
- **GUI CustodianService**: New `xkey/pkg/gui/services/custodian_service.go` wrapping the SDK CustodianGroupService for Wails frontend with event emission, input validation, and 30 unit tests.
- **GUI TenantService**: New `xkey/pkg/gui/services/tenant_service.go` wrapping the SDK TenantService for Wails frontend with event emission, barrier init/unseal support, and 29 unit tests.
- **Custodian/Tenant events**: New event types for custodian group lifecycle (created, deleted, member added/removed, shares distributed) and tenant lifecycle (created, deleted, barrier initialized/unsealed).

### Removed
- **YubiKey Backend**: Removed `pkg/backend/yubikey/` -- YubiKey PIV devices are now supported through the generic PKCS#11 backend with `libykcs11`. This eliminates redundant code and provides stronger cryptographic operations via native PKCS#11 AES-GCM instead of envelope encryption.
- **SmartCard-HSM Backend**: Removed `pkg/backend/smartcardhsm/` -- SmartCard-HSM devices are supported through the generic PKCS#11 backend. The DKEK (Device Key Encryption Key) functionality has been moved to the standalone `pkg/dkek/` package.
- **Secret Sharing Duplication**: Removed `pkg/crypto/secretsharing/` -- consolidated on `pkg/threshold/shamir/` as the single Shamir's Secret Sharing implementation.

### Migration Guide
- **YubiKey users**: Replace `backend: yubikey` configuration with `backend: pkcs11` and set `library: /usr/lib/libykcs11.so` (or appropriate path for your OS). All PIV slot operations work identically through the PKCS#11 interface.
- **SmartCard-HSM users**: Replace `backend: smartcardhsm` with `backend: pkcs11`. For DKEK functionality, use the `pkg/dkek` package directly or the `xkmsctl dkek` CLI commands which now work with any backend.

## [0.2.3-alpha] - 2026-01-15

### Added
- Go SDK (`sdk/go/`) with multi-protocol client support (REST, gRPC, QUIC, MCP, Unix)
- Virtual FIDO2 key binary (`cmd/xkey`) with Linux UHID support
- Linux UHID interface package (`pkg/uhid`) for virtual USB HID device emulation
- Native FIDO2 authenticator (`pkg/fido2/authenticator/`) with CTAP2 protocol support
- Virtual FIDO2 device factory and native enumerator in `pkg/fido2/`
- Integration tests for SDK, UHID, and xkey packages
- WebAuthn mock authenticator for integration testing
- CLI documentation (`docs/usage/cli/`) for all commands
- FIDO2 documentation (`docs/fido2/`)

### Changed
- Renamed `cmd/cli` to `cmd/xkmsctl` (CLI binary)
- Renamed `cmd/server` to `cmd/xkmsd` (daemon binary)
- Moved `pkg/cli/` to `cmd/xkmsctl/` (CLI is now a standalone command)
- Moved `pkg/client/` to `sdk/go/` (clients are now part of SDK)
- Moved gRPC proto files to `pkg/api/grpc/proto/`
- Updated all Dockerfiles to use `golang:bookworm` with `GOTOOLCHAIN=auto`
- Updated Go version to 1.25.6
- Improved devcontainer with UHID permissions for virtual FIDO2 testing
- Enhanced QUIC, MCP, and gRPC handlers with sealing operations
- Refactored TPM2 package to remove simulator build constraints

### Fixed
- Race conditions in gRPC server port field using atomic operations
- Race conditions in server instance field access with proper mutex locking
- FROST handler parameter validation across all API protocols
- UHID integration test permissions in devcontainer

## [0.2.2-alpha] - 2025-12-24

### Added
- **Unified Symmetric Backend**: New `pkg/backend/symmetric/` consolidating AES and ChaCha20-Poly1305
  - Single backend supporting AES-128-GCM, AES-192-GCM, AES-256-GCM
  - ChaCha20-Poly1305 and XChaCha20-Poly1305 support
  - Password-protected key storage with Argon2 key derivation
  - AEAD nonce tracking and bytes limit enforcement
  - Import/export functionality for key portability
- **Algorithm Type System**: New `pkg/types/algorithms.go` with comprehensive type definitions
  - `KeyAlgorithmString` for asymmetric key algorithm identifiers (RSA, ECDSA, Ed25519)
  - `EllipticCurve` constants (P224, P256, P384, P521, Curve25519)
  - `HashName` constants matching Go crypto standards
  - `SignatureAlgorithmName` for signature algorithm identifiers
  - `AEADAlgorithm` and `KeyWrapAlgorithm` for encryption operations
  - `CLIKeyType` for CLI key type parsing
  - Parsing and validation functions for all algorithm types
- **FROST Protocol Stubs**: Infrastructure for future FROST threshold signature support
  - Handler stubs for REST, gRPC, QUIC, Unix, and MCP protocols
  - Backend factory stubs for FROST initialization
  - CLI command stubs for FROST operations

### Changed
- **Test Coverage Improvements**: Increased coverage across 7 packages to 90%+ target
  - `pkg/types`: 66.6% → 97.0% (+30.4%)
  - `pkg/xkms`: 86.8% → 90.6% (+3.8%)
  - `pkg/backend/symmetric`: 88.4% → 90.0% (+1.6%)
  - `pkg/client`: 86.3% → 90.1% (+3.8%)
  - `pkg/crypto/ecies`: 89.6% (all reachable code covered)
  - `pkg/backup`: 89.7% → 91.0% (+1.3%)
  - `pkg/webauthn/http`: 87.9% (improved edge case coverage)
- **Consolidated AESAttributes**: Removed deprecated `AESAttributes` type, using `KeyAttributes` with `SymmetricAlgorithm` field
- **TPM2 Symmetric Tests**: Updated tests for symmetric key generation and encryption validation
- **Cloud Backend Tests**: Cleaned up symmetric encryption tests for AWS KMS, Azure Key Vault, GCP KMS, and Vault backends

### Removed
- **pkg/backend/aes/**: Deprecated AES-only backend (functionality moved to `pkg/backend/symmetric/`)
  - `aes.go`, `aes_test.go`, `aes_bench_test.go`
  - `aes_importexport_test.go`, `aes_tracking_test.go`
  - `errors.go`
- **test/integration/backend/aes_integration_test.go**: Replaced by symmetric backend integration tests

### Fixed
- **Code Formatting**: Fixed gofmt issues in test files blocking CI
- **Linting Errors**: Resolved staticcheck and ineffassign warnings
- **Build Errors**: Fixed undefined `AESAttributes` references after consolidation

## [0.2.1-alpha] - 2025-12-21

### Added
- **TPM2 ProdCaData**: New `ProdCaData` structure for carrying TPM attestation data (Quote, Signature, Nonce, PCRs) from client to server during IDevID enrollment
  - Enables server-side storage of client attestation state upon successful enrollment
  - Binary serialization with `PackProdCaData`/`UnpackProdCaData` functions
  - Conversion to/from `Quote` structure for TPM operations

### Changed
- **Unified Key ID Format**: Consolidated key ID parsing to 4-part format `backend:type:algo:keyname` with optional segments
  - Shorthand `my-key` now supported (equivalent to `:::my-key`)
  - All segments except keyname are optional
  - Refactored `ParseKeyID`, `ParseKeyIDToAttributes`, and validation to use unified format
- **XKMS Service API**: Refactored service functions to use unified key ID format
  - Added `BackendFor(attrs)` helper for backend resolution based on StoreType
  - Added `ParseCertificateID()` using unified format
  - Renamed `getKeystoreForKey` to `getKeystoreForKID` with proper 4-part parsing
  - `Signer()`, `Decrypter()`, `Key()` now use `BackendFor()` for backend resolution
- **TPM2 Provisioning**: Simplified golden measurement and platform policy handling
  - Removed deprecated file integrity monitoring code (use IMA via PCR 10 instead)
  - `Install()` now uses config's `EK.HierarchyAuth` for already-provisioned TPMs
  - Improved logging with INFO level for provisioning operations
  - `GoldenMeasurements()` returns empty if no PCRs configured (skip platform policy)
- **Client Config**: Changed default Unix socket path to `xkms-data/xkms.sock`, removed `APIKey` field (use JWT via FIDO2 flow)
- **Validation**: Updated `ValidateKeyReference()` to enforce 4-part key ID format

### Fixed
- **AWS KMS Lock Contention**: Fixed test timeout by implementing double-checked locking in `Backend.initClient()`
- **Azure Key Vault Lock Contention**: Applied same double-checked locking fix for consistency
- **CI Go Version**: Updated `Dockerfile.ci` from Go 1.24.4 to 1.25.5
- **TPM Test Config**: Added missing `GoldenPCRs` to `TestTPMOperations` config

## [0.2.0-alpha] - 2025-12-13

### Added
- **Key Versioning API**: Full key version lifecycle management across all client interfaces
  - `ListKeyVersions` - List all versions of a key with status and metadata
  - `EnableKeyVersion` / `DisableKeyVersion` - Enable or disable specific key versions
  - `EnableAllKeyVersions` / `DisableAllKeyVersions` - Bulk version state management
  - gRPC, REST, QUIC, and Unix socket client support
  - Proto definitions in `pkg/api/grpc/proto/xkmsv1/xkms.proto`
- **JWT Authentication Adapter**: `pkg/auth/jwt.go` for token-based authentication
  - Configurable issuer, audience, and signing key validation
  - Support for RS256, ES256, and EdDSA signing algorithms
- **Adaptive Authentication**: `pkg/auth/adaptive.go` for multi-method auth
  - Automatic fallback between authentication methods (mTLS → JWT → API Key)
  - Configurable authentication chain with priority ordering
- **WebAuthn JWT Generator**: `pkg/webauthn/jwt_generator.go` for token generation after FIDO2 authentication
- **CLI Certificate Commands**: `internal/cli/cert.go` for certificate management operations
- **TPM2 Backend Integration**: Server-side TPM2 backend factory and operations
  - `internal/server/backend_factory_tpm2.go` - TPM2 backend initialization
  - `internal/server/backend_tpm2.go` - TPM2 server operations
- **YubiKey Sealer Interface**: Hardware-backed data sealing for YubiKey PIV
  - `pkg/backend/yubikey/yubikey_sealer.go` - Envelope encryption sealing
  - RSA-OAEP key wrapping for DEK protection
  - AES-256-GCM authenticated encryption
- **YubiKey Symmetric Encryption**: AES-GCM envelope encryption using PIV keys
  - `pkg/backend/yubikey/yubikey_symmetric.go` - Full symmetric backend
  - DEK wrapping with RSA-OAEP, ECIES (P-256/P-384), and X25519
  - Ed25519 to X25519 key conversion for key agreement
- **Configurable Hardware-Backed RNG**: Support for TPM2 and PKCS#11 hardware random number generators
  - `pkg/crypto/rand/` Resolver interface now implements `io.Reader` for crypto/rand compatibility
  - New `RNGConfig` in server configuration for RNG source selection
  - Modes: `auto` (default), `software`, `tpm2`, `pkcs11`
  - Fallback mode support when primary RNG fails
  - Environment variable overrides: `XKMS_RNG_MODE`, `XKMS_RNG_FALLBACK`, `XKMS_RNG_TPM2_*`, `XKMS_RNG_PKCS11_*`
- **Unix Socket Client Package**: `pkg/client/` for Go applications to communicate with xkms server
- **CLI Configuration Tests**: `internal/cli/config_test.go` with comprehensive config validation
- **Extended CLI Integration Tests**: Multi-protocol and complete lifecycle tests
- **User Documentation**: `docs/usage/user.md` for end-user documentation
- **Daemon Configuration**: Complete daemon operation support for `xkmsd`
  - Configuration file support (`--config`, `XKMS_CONFIG`)
  - Signal handling: SIGTERM/SIGINT for graceful shutdown, SIGHUP for config reload
  - PID file management with automatic creation and cleanup
  - Runtime configuration reload without restart
  - Unix socket protocol selection (gRPC or HTTP)
  - systemd service file with security hardening
  - Installation script and comprehensive documentation in `configs/`
- **Comprehensive Test Suites**: New test files for sealer and symmetric operations
  - `pkg/backend/yubikey/yubikey_sealer_test.go` (14 test functions)
  - `pkg/backend/yubikey/yubikey_symmetric_test.go` (20 tests)
- **Deployment Documentation**: systemd and OpenRC service files for production deployments
  - `deploy/systemd/` - systemd service unit, sysusers, and tmpfiles configurations
  - `deploy/openrc/` - OpenRC init script and configuration for Alpine Linux
  - `deploy/README.md` - Comprehensive deployment guide with installation steps
- **Enhanced README**: Expanded quick start guide with FIDO2 admin setup
  - Server Quick Start section with first-time setup instructions
  - Complete CLI examples for key, certificate, and admin management
  - XKMS Service API overview with all service functions documented
  - Multi-backend configuration examples
- **Admin CLI Commands**: `internal/cli/admin.go` for administrator management
  - Create, list, delete admin users
  - Role assignment and permissions management
- **FIDO2 CLI Commands**: `internal/cli/fido2.go` for passwordless authentication setup
  - Register and manage FIDO2 credentials
  - Authenticate using hardware security keys
- **RBAC Middleware**: `internal/rest/rbac_middleware.go` for role-based access control
  - Permission-based route protection
  - Role hierarchy support
- **User Management API**: `internal/rest/user_handlers.go` for user operations
  - REST endpoints for user CRUD operations
  - Integration with RBAC system
- **Unix Socket HTTP Server**: `internal/unix/` for local IPC
  - HTTP server over Unix domain sockets
  - Handlers for all xkms operations

### Changed
- **Test Coverage Improvements**: Increased coverage across multiple packages
  - `pkg/versioning`: 76.1% → 93.9%
  - `pkg/client`: 79.1% → 86.1%
  - `internal/config`: 83.1% → 96.0%
  - Testable code (excluding hardware) now at 93.4% average coverage
- Extended environment variable configuration support for RNG, rate limiting, and logging
- **API Naming**: Renamed `XKMSFacade` to `XKMSService` for clarity
  - `FacadeConfig` → `ServiceConfig`
  - `facade.go` → `service.go`
  - Updated all documentation, tests, and code references
- **Documentation**: Updated terminology from "facade" to "service" throughout
- **Typed Errors**: Replaced all `fmt.Errorf` with typed errors in PIV backends
  - YubiKey: 37 typed error variables, ~139 replacements
  - Enables proper `errors.Is()` and `errors.As()` error handling
- Extended `Resolver` interface with `Read(p []byte) (n int, err error)` method for `io.Reader` compatibility
- Hardware RNG (TPM2/PKCS#11) can now be used as drop-in replacement for `crypto/rand.Reader`
- Updated example configurations with RNG settings documentation
- **Documentation Cleanup**: Streamlined architecture documentation
  - `docs/architecture/unified-keyid-jwk-integration.md` reduced from 1,580 to 245 lines
  - Removed all legacy/migration content, kept only current API documentation
- **CI/CD**: Added FIPS 140-2/3 compliant builds to CI and release workflows
  - BoringCrypto-enabled binaries for environments requiring FIPS certification

### Fixed
- **Makefile**: Fixed `bc` dependency error in coverage calculation (replaced with pure shell/awk)
- **Ed25519 to X25519 Conversion**: Fixed SHA256 → SHA512 for RFC 7748 compliance in YubiKey symmetric
- **TestMCPStreamingNotifications**: Fixed flaky integration test for async MCP notifications
- **PlatformPassword Race Condition**: Fixed concurrent cache access in `pkg/tpm2/password.go`
  - Multiple goroutines calling `Bytes()` could bypass cache and trigger excessive TPM unseal operations
  - Implemented double-checked locking pattern to ensure only one goroutine performs unseal when cache is empty
  - `TestPlatformPassword_CacheConcurrency` now passes with race detector enabled
- Improved error handling and logging for ignored HTTP write errors
- Integration test stability improvements across all backends
- **Configuration**: Server socket path now defaults to `/var/run/xkms/xkms.sock` to match client defaults
- **Configuration**: Added `xkmsd-dev.yaml` for development/testing with `/tmp` paths
- **Configuration**: Added `xkms-client.yaml` example client configuration
- **Scripts**: Moved test scripts from `scripts/` to `test/scripts/`

### Removed
- **API Key Authentication**: Removed `pkg/auth/apikey.go` (replaced by JWT adapter)
- **Logo**: Removed `logo.svg` from repository root
- `test/integration/encoding/README_FIX.md` - Development-only fix notes
- `pkg/metrics/implementation-summary.md` - Development-only implementation notes

### Known Limitations (Alpha)
- **TPM2 Server Integration**: The `pkg/tpm2` library is fully functional for direct Go usage, but server-side integration (REST/gRPC/CLI/MCP) is not yet complete. Use `pkg/tpm2` directly for TPM2 operations.
- **Vault Import/Export**: HashiCorp Vault Transit backend does not support key import/export operations
- **PKCS#11 Attestation**: Some attestation methods are not yet implemented

## [0.1.9-alpha] - 2025-12-07

### Added
- **WebAuthn/FIDO2 Server Support**: Complete server-side passwordless authentication
  - `pkg/webauthn/` - Core WebAuthn service with user, session, and credential management
  - `pkg/webauthn/http/` - HTTP handlers for REST API integration
  - Registration flow: begin/finish ceremonies with session management
  - Authentication flow: discoverable credentials and user-specific login
  - Pluggable store interfaces for UserStore, SessionStore, CredentialStore
  - Memory-based stores for development and testing
  - Full test coverage with testify mocks
- **WebAuthn REST API Endpoints**:
  - `GET /api/v1/webauthn/registration/status` - Check registration status
  - `POST /api/v1/webauthn/registration/begin` - Start registration ceremony
  - `POST /api/v1/webauthn/registration/finish` - Complete registration
  - `POST /api/v1/webauthn/login/begin` - Start authentication ceremony
  - `POST /api/v1/webauthn/login/finish` - Complete authentication
- **Shared Mock Infrastructure**: `pkg/xkms/mocks/mock_keystore.go` for unit testing
- **WebAuthn Integration Tests**: Docker-based tests in `test/integration/api/`
- **WebAuthn Documentation**: `docs/usage/webauthn.md`
- **Unified Rate Limiting**: Consistent rate limiting across all public APIs
  - Integrated rate limiting into REST server via middleware
  - Added gRPC unary and stream server interceptors for rate limiting
  - QUIC/HTTP3 server rate limiting via HTTP middleware
  - MCP JSON-RPC server connection-level rate limiting
  - New configuration options: `burst`, `cleanup_interval_sec`, `max_idle_sec`
  - Environment variable overrides: `KEYSTORE_RATELIMIT_ENABLED`, `KEYSTORE_RATELIMIT_REQUESTS_PER_MIN`, `KEYSTORE_RATELIMIT_BURST`

### Changed
- Refactored REST server tests to use shared mock infrastructure
- Improved test organization with centralized mocks
- Extended `RateLimitConfig` with additional options for burst and cleanup intervals

## [0.1.8-alpha] - 2025-12-06

### Changed
- **Storage Independence**: Removed go-objstore dependency, go-xkms now has its own storage implementations
  - Local `pkg/storage/memory.go` provides in-memory storage backend
  - Local `pkg/storage/file/` provides file-based storage backend
  - Storage interface remains compatible with go-objstore for higher-level app integration
- **Docker Cleanup**: Removed all GOPRIVATE workarounds from integration test Dockerfiles
  - Cleaned up main Dockerfile (removed sed/GOPRIVATE/GOPROXY hacks)
  - All integration tests now use standard Go module proxy

### Removed
- `pkg/storage/objstore_adapter.go` - go-objstore adapter (no longer needed)
- `pkg/tpm2/store/objstore_*.go` - All go-objstore adapters for TPM store
- `pkg/tpm2/store/factory.go` - go-objstore factory (replaced with local implementations)
- `pkg/tpm2/store/testing.go` - go-objstore test helpers
- GOPRIVATE environment variables from all Dockerfiles

### Dependencies
- Removed go-objstore dependency entirely (go-xkms is now self-contained for storage)

## [0.1.7-alpha] - 2025-12-05

### Added
- **Unified Sealer Interface**: Backend-agnostic sealing abstraction across all backends
  - `pkg/tpm2/sealer.go` - TPM2 sealer with PCR policy support
  - `pkg/backend/pkcs8/sealer.go` - Software sealer using HKDF + AES-256-GCM
  - `pkg/backend/pkcs11/sealer.go` - HSM hardware-backed AES-GCM sealing
  - `pkg/backend/awskms/sealer.go` - AWS KMS cloud-managed encryption
  - `pkg/backend/azurekv/sealer.go` - Azure Key Vault symmetric key sealing
  - `pkg/backend/gcpkms/sealer.go` - GCP KMS cloud-managed encryption
  - `pkg/backend/vault/sealer.go` - HashiCorp Vault Transit engine encryption
- **JWT SigningMethodSigner**: Hardware-backed JWT signing via `crypto.Signer` interface
  - Supports RS256/384/512, PS256/384/512, ES256/384/512, EdDSA
  - `SignWithSigner()` and `SignWithSignerAndKID()` convenience methods
- **Certificate Display Functions**: `pkg/certstore/types.go` with OID parsing, key usage display
- **Composite Sealing**: `pkg/xkms/composite_seal.go` for multi-backend seal operations
- **TPM2 Enhancements**: Certificate conversion, type re-exports, store abstraction
- **Logging Package**: Structured logging infrastructure (`pkg/logging/`)
- **Architecture Documentation**: Storage interfaces and BlobStorer refactoring guides

### Changed
- Extended `pkg/types/types.go` with Password, SealData, and Sealer interfaces
- Refactored internal TPM store with cleaner interfaces and helpers
- Improved overall test coverage from 85.8% to 91.2%

### Fixed
- Test coverage gaps across multiple packages:
  - `pkg/certstore`: 46.1% → 90.2%
  - `pkg/encoding/jwt`: 59.5% → 94.3%
  - `pkg/types`: 62.0% → 96.1%
  - `pkg/backend/threshold`: 72.5% → 81.7%
  - `pkg/storage/file`: 86.8% → 92.3%

## [0.1.6-alpha] - 2025-11-22

### Added
- Unified service pattern for simplified multi-backend management
- Backend factory pattern with auto-detection and configuration
- Comprehensive test coverage for service and factory (40+ test cases)
- Input validation for all API endpoints to prevent injection attacks
- Path traversal protection in file storage backend

### Changed
- Simplified API: `server.Initialize()` instead of `server.InitializeService()`
- Refactored xkms initialization with auto-backend detection
- Updated documentation and examples to reflect simplified API
- Improved code coverage from 72.8% to 92.5% in xkms package

### Security
- Centralized validation at service layer protects ALL public APIs (REST, gRPC, QUIC, CLI, MCP)
- All user inputs validated before reaching any backend or storage layer
- Created shared `pkg/validation` package for consistent validation across codebase
- Service layer validates all keyIDs, backend names, and key references
- Defense in depth: Storage layer also validates (though service should prevent bad input)
- Rejects special characters, null bytes, and directory traversal attempts
- Backend names: whitelist pattern `[a-z0-9\-]+` only (max 64 chars)
- KeyIDs: whitelist pattern `[a-zA-Z0-9_\-\.]+` only (max 255 chars)
- Key references support "backend:key-id" format with validation of both parts
- File storage protected against path traversal attacks
- Log injection prevention via sanitization of all logged user input

### Fixed
- Test coverage gaps in service and backend factory code
- Documentation examples now demonstrate clean, simple API usage
- Potential path traversal vulnerability in file storage operations

## [0.1.5-alpha] - 2025-11-19

### Changed
- Replaced minimal TPM2 implementation with full production-grade TPM support
- Complete TPM 2.0 integration with hierarchies, policies, and provisioning
- Enhanced TPM attestation and cryptographic operations
- Updated all security-critical dependencies to latest versions
  - golang.org/x/crypto: v0.42.0 → v0.45.0
  - google.golang.org/grpc: v1.76.0 → v1.77.0
  - AWS SDK v2, Prometheus, OpenTelemetry, TPM libraries
- Updated golangci-lint to v2.6.2 with action v7 for Go 1.25 compatibility
- Fixed TPM2 backend API compatibility with new config structure
- Removed redundant release tarballs (direct binary downloads only)

### Fixed
- Fixed TPM2 integration test build tags to properly include `tpm2` tag requirement
- Fixed TPM2 event log parsing to use absolute paths
- Resolved all 51 linting errors preventing CI builds (17 errcheck, 34 staticcheck)
  - Added proper error handling for unchecked error returns
  - Fixed JSON marshaling of function types (SessionCloser)
  - Resolved duplicate package imports and syntax errors
  - Suppressed false positive style warnings for embedded field accessors

## [0.1.4-alpha] - 2025-11-18

### Changed
- Internal refactoring and optimizations

## [0.1.3-alpha] - 2025-11-18

### Changed
- Refactored KeyAttributes to common library for better code reuse
- Improved type organization and reduced import cycles

## [0.1.2-alpha] - 2025-11-18

### Added
- Threshold cryptography package with Shamir Secret Sharing
- Split and combine secrets with configurable threshold

## [0.1.1-alpha] - 2025-11-17

### Added
- Quantum-safe signing support (post-quantum cryptography)
- Key encapsulation mechanisms (KEM) for quantum resistance

## [0.1.0-alpha] - 2025-11-14

### Overview

Initial alpha release of go-xkms - a production-ready cryptographic key and certificate management library for Go with 10 backends, 5 client interfaces, and dual licensing (AGPL-3.0 + Commercial).

### Added

#### Core Features
- Unified KeyStore interface for consistent key and certificate operations across all backends
- CompositeKeyStore pattern combining backend storage with certificate management
- Thread-safe concurrent operations with proper synchronization primitives
- Pluggable architecture for easy backend and storage extension

#### Key Management
- **Asymmetric Keys**: RSA (2048/3072/4096), ECDSA (P-256/P-384/P-521), Ed25519
- **Symmetric Keys**: AES-GCM (128/192/256-bit) with AEAD support
- **Operations**: Generate, store, retrieve, rotate, delete, import/export, wrap/unwrap
- **Standards**: Implements Go's `crypto.Signer` and `crypto.Decrypter` interfaces
- **Protection**: Password-protected PKCS#8 key storage with secure key derivation

#### Cryptographic Backends (10 Production-Ready)
1. **PKCS#8**: File-based asymmetric key storage
2. **AES**: File-based symmetric encryption backend
3. **Software**: Pure Go implementation for testing
4. **PKCS#11**: Hardware Security Module (HSM) integration
5. **SmartCard-HSM**: CardContact SmartCard-HSM with DKEK support
6. **TPM2**: Trusted Platform Module 2.0 with hierarchies and policies
7. **YubiKey**: YubiKey PIV (Smart Card) support
8. **AWS KMS**: Amazon Key Management Service integration
9. **GCP KMS**: Google Cloud Key Management Service integration
10. **HashiCorp Vault**: Vault Transit Engine integration

All backends support symmetric encryption (AES-GCM) and AEAD operations.

#### Certificate Management
- **CRUD Operations**: Store, retrieve, delete, list X.509 certificates
- **Certificate Chains**: Full chain management, building, and validation
- **CRL Support**: Certificate Revocation List management and checking
- **Validation**: Certificate verification with configurable `x509.VerifyOptions`
- **Hardware Storage**: Native PKCS#11 HSM and TPM2 NV RAM certificate storage
- **Hybrid Mode**: Automatic failover between hardware and external storage
- **Capacity Monitoring**: Certificate storage capacity management

#### Client Interfaces (100% API Coverage)
- **REST API**: HTTP/HTTPS web services with Fiber framework
- **gRPC**: High-performance RPC with Protocol Buffers
- **QUIC**: HTTP/3 over QUIC for ultra-low latency
- **CLI**: Full-featured command-line interface with Cobra
- **MCP**: Model Context Protocol (JSON-RPC) for AI integration

All interfaces expose the complete KeyStore API (17/17 methods).

#### Cryptographic Operations
- **Signing**: RSASSA-PSS, RSASSA-PKCS1-v1_5, ECDSA-SHA2, Ed25519
- **Verification**: Multi-algorithm signature verification
- **Asymmetric Encryption**: RSA-OAEP, RSA-PKCS1v15
- **Symmetric Encryption**: AES-128/192/256-GCM with nonce and tag management
- **AEAD**: Authenticated Encryption with Additional Data support
- **Hash Functions**: SHA-256, SHA-384, SHA-512, SHA3

#### Encoding & Interoperability
- **JWK**: JSON Web Key encoding/decoding (RSA, ECDSA, Ed25519, symmetric)
- **JWT**: JSON Web Token generation and validation (RS256, RS384, RS512, ES256, ES384, ES512, EdDSA)
- **JWE**: JSON Web Encryption with key wrapping (RSA-OAEP, AES-GCM)
- **PKCS#8**: Private/public key encoding with password protection
- **PEM**: PEM format encoding/decoding
- **Cross-Library Testing**: Verified interoperability with jose-go, go-jose, jwt-go

#### Security & Access Control
- **Authentication**: mTLS, API Key, NoOp (configurable per interface)
- **Authorization**: RBAC (Role-Based Access Control) integration
- **Audit Logging**: Comprehensive audit trail with structured logging
- **Policy Engine**: Configurable security policies
- **Metrics**: Prometheus-compatible metrics export
- **Correlation IDs**: Request tracing across all interfaces

#### Storage Abstraction
- **File Storage**: Production file-based storage with atomic operations
- **Memory Storage**: In-memory storage for testing
- **Filesystem Interface**: Custom FS implementation support (similar to io/fs)
- **Atomic Operations**: Safe concurrent file operations

#### Testing & Quality
- **Unit Tests**: 93.3% average code coverage across 25+ packages
- **Integration Tests**: 151 passing tests across all 10 backends
- **Benchmark Tests**: Performance benchmarks for critical operations
- **Docker Integration**: Complete Docker Compose test environments
- **Security Scanning**: gosec integration for vulnerability detection
- **Linting**: golangci-lint with comprehensive rulesets

#### Build System
- **Makefile**: 50+ targets for building, testing, and deployment
- **Version Injection**: Automatic version embedding in binaries via ldflags
- **Build Tags**: Conditional compilation for optional backends
- **Binary Builds**: CLI and 5 server binaries with proper versioning
- **Shared Library**: CGO-based libxkms.so with version numbering
- **Cross-Platform**: Linux and macOS support (Windows experimental)
- **CI/CD Ready**: GitLab CI configuration included

#### Documentation
- Getting Started guide with step-by-step instructions
- Backend-specific configuration guides (10 backends)
- Certificate Management best practices
- Symmetric Encryption guide
- API Parity documentation (REST/gRPC/QUIC/CLI/MCP)
- Build System documentation
- 15+ working examples covering all features

#### Licensing
- **Dual Licensed**: AGPL-3.0 (open source) + Commercial License
- **Copyright**: Jeremy Hahn & Automate The Things, LLC
- **Source Headers**: All 502 Go files updated with dual-license notice
- **Commercial Options**: Available from Automate The Things, LLC
- **SPDX Compliant**: Proper license identifiers throughout

### Changed
- Updated from Apache 2.0 to dual licensing model (AGPL-3.0 + Commercial)
- Reorganized documentation structure to match standard patterns
- Consolidated type definitions into pkg/types to prevent import cycles
- Enhanced error handling with typed errors and proper error wrapping

### Fixed
- Import/export functionality across all backends
- Symmetric encryption support in cloud KMS backends (AWS, GCP, Azure)
- Test coverage gaps in backend implementations
- Race conditions in concurrent operations
- Memory leaks in long-running server processes

### Security
- All source code scanned with gosec
- No high-severity vulnerabilities
- Secure random number generation for all cryptographic operations
- Protection against timing attacks in key operations
- Safe handling of sensitive data with proper zeroing

### Known Limitations (Alpha Release)
- API may change before v1.0.0 (backward compatibility maintained where possible)
- Some cloud KMS operations require active network connectivity
- TPM2 integration requires hardware TPM or software simulator (swtpm)
- YubiKey support requires physical device
- Windows support is experimental and not fully tested
- Azure Key Vault backend requires valid Azure credentials

### Performance
- Key generation: <100ms for RSA-2048, <50ms for ECDSA-P256, <10ms for Ed25519
- Signing: <10ms for RSA, <5ms for ECDSA, <1ms for Ed25519
- Symmetric encryption: <1ms for AES-256-GCM (1KB payload)
- Certificate operations: <5ms for storage/retrieval

### Contributors
- Jeremy Hahn (@jeremyhahn)

### Links
- Repository: https://github.com/jeremyhahn/go-xkms
- Documentation: https://github.com/jeremyhahn/go-xkms/tree/master/docs
- Commercial Licensing: licensing@automatethethings.com
- AGPL-3.0 License: https://www.gnu.org/licenses/agpl-3.0.html

[0.2.3-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.2.3-alpha
[0.2.2-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.2.2-alpha
[0.2.1-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.2.1-alpha
[0.2.0-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.2.0-alpha
[0.1.9-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.9-alpha
[0.1.8-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.8-alpha
[0.1.7-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.7-alpha
[0.1.6-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.6-alpha
[0.1.5-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.5-alpha
[0.1.4-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.4-alpha
[0.1.3-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.3-alpha
[0.1.2-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.2-alpha
[0.1.1-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.1-alpha
[0.1.0-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.0-alpha

---

## [go-trusted-ca] - merged 2026-04-16

The go-trusted-ca repository was merged into go-xkms. All ACME-related
functionality now lives under `pkg/acme/`. The following sections are
imported from go-trusted-ca's CHANGELOG for historical reference. They
record that project's own releases under **go-trusted-ca's** numbering,
never go-xkms's, so no go-xkms version ever shipped them.

This heading is bracketed, and their headings sit one level below it, on
purpose. `make release` extracts a version's notes with
`sed -n "/## \[<version>\]/,/^## \[/p"`, so a release section runs to the
next line beginning `## [`. Without a bracketed heading here the oldest
go-xkms release would run to end of file and publish this appendix as its
own release notes (go-xkms#356).

### go-trusted-ca [Unreleased] (at merge)

#### Added

##### API Documentation
- **Swagger UI** at `/docs` for interactive API exploration
- **ACME API OpenAPI spec** (`/openapi/acme-api.yaml`) - Full RFC 8555 documentation
- **Admin API OpenAPI spec** (`/openapi/admin-api.yaml`) - Administrative endpoints
- Spec switching via query parameter (`?spec=admin-api`)

##### Monitoring & Observability
- **Grafana Dashboard** (`deploy/grafana/dashboard.json`)
  - SLO tracking (99.9% availability, 99% challenge success)
  - Error budget tracking
  - Request latency heatmaps (p50, p95, p99)
  - Certificate issuance metrics
  - Challenge validation rates by type
  - System resource monitoring (CPU, memory, goroutines, GC)

##### Multi-Arch Docker Builds
- GitHub Actions workflow for automated multi-arch builds
- Support for `linux/amd64` and `linux/arm64`
- Trivy security scanning on every build
- SBOM (Software Bill of Materials) generation
- Build provenance attestation

---

### go-trusted-ca [0.1.0-alpha](https://github.com/jeremyhahn/go-trusted-ca/releases/tag/v0.1.0-alpha) - 2026-01-02

#### Added

##### ACME Server (RFC 8555 Compliant)
- Full RFC 8555 ACME protocol implementation
- Directory endpoint with capability discovery
- Account management (create, update, deactivate, key rollover)
- Order workflow with authorization and challenge validation
- Certificate issuance and revocation
- Nonce management and replay protection

##### Challenge Types
- **HTTP-01**: Standard domain validation via HTTP token
- **DNS-01**: Domain validation via DNS TXT records
- **device-attest-01**: TPM 2.0 device attestation per draft-acme-device-attest
- **enroll-01**: TCG-compliant IDevID enrollment for TPM-equipped devices
- **endorse-01**: Endorsement Key certificate provisioning

##### Multi-Tenancy
- Tenant isolation with dedicated CAs
- Per-tenant key management via go-xkms KMS
- RBAC role-based access control
- RBAC policies with CEL expressions

##### Admin API
- RESTful management interface
- Tenant lifecycle management
- Policy and role administration
- CA status and health monitoring

##### Storage Backends
- All go-xkms backends supported:
  - Local filesystem (PKCS#8)
  - TPM 2.0 hardware protection
  - PKCS#11 HSM integration
  - AWS KMS
  - GCP Cloud KMS
  - Azure Key Vault
  - HashiCorp Vault
- Certificate storage via go-objstore

##### Security
- JWT-based authentication
- TLS 1.3 support
- Rate limiting with RFC 8555 compliance
- Proxy header support (X-Forwarded-For, X-Real-IP)

##### Deployment
- Single-node embedded mode
- Raft-based clustering via QRDB
- Docker container support
- Prometheus metrics endpoint

##### Developer Experience
- Comprehensive test coverage (90%+ on core packages)
- Integration test suite with Docker
- Example configurations and quickstart guide

#### Dependencies
- go-xkms v0.2.2-alpha
- go-objstore v0.1.4-alpha
- go-qrdb (local development)

#### Known Limitations
- TCG-CSR-IDEVID parsing partially implemented
- Client package coverage at 74.8% (TPM functions require integration tests)
