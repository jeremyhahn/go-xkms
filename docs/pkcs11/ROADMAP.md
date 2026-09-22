# PKCS#11 Module Roadmap — Compliance, Persistence, FIPS, Interop

**Living document.** Update the finding/task status columns as work lands; add new
findings to the register with the next free ID. Last updated: 2026-08-12 (Phase 1
implementation in progress: C0-C16, C19-C23, C25 FIXED + tested; C24 deferred; C17/C18
remain).

Scope: `pkg/pkcs11/module/` (core), `cmd/pkcs11-module/` (cgo C ABI),
`test/integration/pkcs11/` (suites), Makefile build/test lanes.
Authority: OASIS PKCS#11 v3.2 (`docs/references/pkcs11-3.2.html`).

## Priorities (locked by maintainer)

1. **P1 — OASIS compliance + everything green** (fix all confirmed findings, keep suites passing)
2. **P2 — FIPS + non-FIPS builds** (GOFIPS140 Makefile-driven, FIPS self-identification)
3. **P3 — OpenSSL / OpenSSH interop test completeness** (all possible operations verified externally)
4. **P4 — Token/session persistence via remote xkms backend** (net-new feature)
5. **P5 — Offline local mode (SoftHSM-like, no network)** (net-new feature)

## Baseline (verified 2026-08-12)

- `.so` builds clean (`make build-pkcs11-module`); `make test-pkcs11-module` full
  unit suite PASSES (2026-08-12, ~535s).
- All 104 spec functions exported; function list has no NULL slots.
- Prior Aug-2026 sweeps' recorded gaps re-verified: message-based AEAD
  `CK_GCM_MESSAGE_PARAMS` now fully wired with IV write-back (C ABI + Go, tested);
  attestation stub replaced with real device-key signing; EC `CKA_DERIVE`, AES-192,
  cross-slot session-handle namespace, Argon2id-off-login-lock, FIPS enforcement
  suite target — all FIXED.
- Session state machine (§5.5–§5.7): compliant (states, RO/SO exclusion, login
  propagation, object lifetimes, C_CloseAllSessions ordering, PIN lockout
  persistence across C_Finalize).

---

## Phase 1 — OASIS v3.2 compliance fixes (P1)

Findings register. Severity: **P0 = security blocker**, H = high, M = medium,
L = low, I = informational. Findings prefixed C were verified by hand; source noted.

| ID | Sev | Finding | Location | Fix | Status |
|----|-----|---------|----------|-----|--------|
| **C0** | **P0** | **Sensitive/non-extractable secret-key material disclosed via `C_GetAttributeValue(CKA_VALUE)`.** For a `CKO_SECRET_KEY` created/unwrapped with `CKA_VALUE` in-map and `CKA_SENSITIVE=TRUE` (or `CKA_EXTRACTABLE=FALSE`), the object manager correctly withholds it, but `fillBackendKeyValue`→`secretKeyValue` re-reads the in-map `CKA_VALUE` on its first line **before** the `protectsSensitiveAttributes()` guard, clears `Unavailable`, and `C_GetAttributeValue` returns `CKR_OK` with the key. Reachable from the C ABI. **HAND-VERIFIED real.** §4.9 fn7. (Codex) | `module.go:2111` (`secretKeyValue` 1st line), `module.go:2171`/`2077` (`fillBackendKeyValue`, final `filled` check); C ABI `exports.go:801` | Guard the in-map short-circuit in `secretKeyValue` with `!obj.protectsSensitiveAttributes()` (return `CKR_ATTRIBUTE_SENSITIVE` when it protects); add a negative test for sensitive C_CreateObject + C_UnwrapKey secret keys | **FIXED** — `secretKeyValue` guard moved above map read; `module_sensitive_value_test.go` (reveals unprotected / withholds sensitive+unextractable); related suite green |
| C1 | H | Pre-hash ML-DSA (`CKM_HASH_ML_DSA` + 10 SHA/SHA3/SHAKE variants) advertise `CKF_SIGN\|CKF_VERIFY` but `IsMLDSAMechanism()` never routes them — failure surfaces deep in C_Sign instead of `*Init` | `mechanism_v32.go:342-431`, `mechanism_quantum.go:404-410` | Zero the `Flags` (match `CKM_SLH_DSA`/`CKM_HSS`/`CKM_XMSS` precedent) until a real pre-hash signer exists | **FIXED** — all 11 descriptors `Flags: 0`; verified no routing exists (`IsMLDSAMechanism` covers only CKM_ML_DSA + vendor range); tests in `mechanism_v32_test.go` flipped to assert zero flags |
| C2 | H | Pre-hash SLH-DSA (`CKM_HASH_SLH_DSA` + 10 variants) same defect — no SLH-DSA implementation exists at all | `mechanism_v32.go:458-525` | Zero the `Flags` | **FIXED** — all 11 descriptors `Flags: 0`; tests flipped |
| C3 | H | `CKM_ML_KEM` encapsulate/decapsulate routing tables omit `512:` — ML-KEM-512 keys generate fine but standard-mechanism encaps/decaps returns `CKR_MECHANISM_PARAM_INVALID`; stale "512 deliberately absent" comments | `module_kem.go:52-64` | Add `512:` entries to both tables; delete stale comments | **FIXED (was already routed)** — reviewer read the stale comment; `512:` entries present in both tables + size table since the CIRCL mlkem512 work, with end-to-end `TestMLKEM512EncapsulateDecapsulateRoundTrip` driving standard `CKM_ML_KEM`. Only the misleading "deliberately absent" comment remained → corrected to a do-not-remove note |
| C4 | H | `C_EncryptMessage` GCM: any `ivGenerator != CKG_NO_GENERATE` discards caller IV and `ulIvFixedBits`, generates fully random IV (spec: fixed-bits prefix must be preserved) | `module.go:4372-4379` (contrast correct `module_authwrap.go:302-309`) | Preserve fixed-bits prefix or reject nonzero `IVFixedBits`/counter generators with `CKR_MECHANISM_PARAM_INVALID` like authwrap does | **FIXED** — refuses nonzero `IVFixedBits` + `CKG_GENERATE_COUNTER`/`_XOR` before random-IV generation; `TestEncryptMessage_RefusesFixedBitsAndCounterIVGenerators` (+ accepts-random) |
| C5 | M-H | Vendor PQC registry (`GetQuantumMechanismDescriptor`) bypasses the FIPS choke point AND no vendor descriptor is marked `FIPSApproved` (backing impls are genuine FIPS 203/204) — regression trap: naively copying the classical filter would kill ALL PQC under FIPS | `mechanism_quantum.go:197-393` | Mark ML-DSA/ML-KEM vendor descriptors `FIPSApproved: true`, then apply the same FIPS filter as `GetMechanismDescriptor` | **FIXED** — all 15 vendor descriptors `FIPSApproved: true` (registry holds only ML-DSA/ML-KEM, no round-3); filter added to `GetQuantumMechanismDescriptor`; `TestQuantumRegistry_AllMechanismsAreFIPSApproved` + `TestGetQuantumMechanismDescriptor_HonoursFIPSChokePoint` |
| C6 | M | `CKM_RSA_PKCS_OAEP` params validated lazily at Encrypt/Decrypt, not at `*Init` (every other parameterized mechanism fails fast) | `crypto.go:1253-1321, 1589-1654` vs `:1151-1172` | Call `ValidateRSAOAEPParams` in `EncryptInit`/`DecryptInit` for OAEP | **FIXED** — OAEP case added to both `EncryptInit`/`DecryptInit` reusing `rsaOAEPForMechanism`; `TestEncryptDecryptInit_ValidatesOAEPParamsAtInit` |
| C7 | L | `CryptoManager.MessageDecryptInit` reads `mechanismRegistry` directly, bypassing `GetMechanismDescriptor` (currently shielded upstream, diverges from all sibling `*Init`s) | `crypto.go:1540` | Resolve through `GetMechanismDescriptor` | **FIXED** — now resolves via `GetMechanismDescriptor` |
| C8 | L | `CKG_GENERATE_COUNTER_XOR` (0x04, in vendored pkcs11t.h) has no Go constant; falls into generic branch | `mechanism.go:840-854` | Add the constant (explicitly rejected per C4 if unimplemented) | **FIXED** — constant added; C4 refuses it |
| C9 | M | M7 (carried over): token storage records have no MAC/integrity protection — metadata (CKA_CLASS, capability flags, KeyID/BackendName bindings) tamperable on disk; key material already withheld | `storage.go:288-338`, backend chain `module.go:573-590` | **DECIDED**: AES-256-GCM per record, storage-key as AAD; per-token master key wrapped by Argon2id(SO/User PIN) KEKs; public-info+lockout under barrier/TPM-rooted device key (TPM NV counter for rollback resistance when present); route full-node storage through existing `sealed.Backend`. Folds into L3. See Decisions §C9 | **IMPLEMENTED (offline) + verified in-process; C_SetPIN rekey = follow-up** — module-side `SealController` seam (`sealcontroller.go`): user PIN unseals at C_Login(CKU_USER), reseals at logout/finalize, SO login does NOT unseal, unseal-failure rolls back the login (`sealcontroller_test.go`, 5 tests). Real barrier `pkg/pkcs11/localseal` consumes qrdb's barrier via `pkg/seal` (NewBarrier passphrase + NewBarrierBackend) — NO sealer built by xkms; `localseal_test.go` PROVES AES-256-GCM at rest, wrong-PIN rejected, survives restart. Wired into offline `.so` (`cmd/pkcs11-module/offline.go`, default `passphrase` / `none` opt-in via `XKMS_PKCS11_SEAL_STRATEGY`) + SDK `EmbeddedServiceConfig.KeyStorage` injection. Remote mode already protected by xkmsd's barrier. **C_SetPIN REKEY DONE** — `SealController.Rekey` + `Module.SetPIN` hook (user-PIN branch only; SO PIN never rekeys) uses qrdb's cheap `StorageBarrier.ChangePassword` (re-wraps root key, NO data re-encrypt; NO qrdb change needed). `localseal.Controller.Rekey` preserves seal state (public-session change reseals), no-op before init. Verified: `TestController_RekeyChangesPINWithoutLosingData` (old PIN invalidated, data intact), `RekeyPreservesSealState`, `RekeyBeforeInitIsNoOp`; module `TestSealController_UserSetPINRekeys`/`SOSetPINDoesNotRekey`/`RekeyFailureFailsSetPIN`. Full offline-.so E2E = L4 (devcontainer) |
| C10 | L | SHA-1 mechanisms (`CKM_SHA1_RSA_PKCS`, `CKM_ECDSA_SHA1`) advertised but refused by default daemon weak-hash policy (advertise/perform split, documented as deliberate in `docs/pkcs11/module/mechanisms.md`) | `mechanism.go:1451-1461, 1575-1583`; `pkg/types/hashpolicy.go:38-60` | **DECIDED**: gate the flags — keep discoverable with `CKF_VERIFY`, clear `CKF_SIGN` when weak-hash policy forbids SHA-1 signing; compute flags from effective policy at `C_Initialize` via the `GetMechanismDescriptor` choke point. See Decisions §C10 | **FIXED** — `effectiveMechanismFlags` clears `CKF_SIGN` on SHA-1 sig mechanisms unless `XKMS_PKCS11_ALLOW_WEAK_HASH_SIGNING` is set (module-owned policy, secure default; the `.so` runs in its own process and cannot read the daemon config). Single source used by both `defaultMechanismInfo` (advertising) and `GetMechanismDescriptor` (`*Init`); returns a copy, never mutates the registry. `mechanism_weakhash_test.go`. Conformance lane sets the env so its SHA-1 coverage stands (needs devcontainer confirm). NOTE: standalone `.so` weak-hash signing is now opt-in via that env |
| C11 | L | Dormant: `Module.OpenSession` fallback creates a session manager with a private handle table — would reintroduce cross-slot handle collisions if slots ever become dynamic (unreachable today) | `module.go:1439-1442` | Pass the shared table (`NewSessionManagerWithTable`) in the fallback, or replace with an error return | **FIXED** — shared `HandleTable` promoted to `m.sessionHandles` field; OpenSession fallback now uses `NewSessionManagerWithTable(..., m.sessionHandles)` |
| C12 | L | `validatePINLocked` still runs Argon2id under `m.mu` on the `SetPIN` path (login path already fixed; this is infrequent + authenticated) | `session.go:1160-1173, 1307` | Apply the same prepare/finish split as login | **FIXED** — `VerifyPINForChange` now snapshots under the lock then runs Argon2id with it released (prepare/finish); dead `validatePINLocked` removed; test redirected to `preparePINVerificationLocked` |
| C13 | I | `CK_SESSION_INFO.ulDeviceError` always 0 (declared, never written) | `session.go:264, 660-667` | Optionally surface `LastStorageError`/transport failures; else document | OPEN |
| C14 | I | `C_OpenSession` drops the Notify callback (spec-optional); async trio + blocking `C_WaitForSlotEvent` return `CKR_FUNCTION_NOT_SUPPORTED` (spec-legal, token doesn't advertise async) | `exports.go:598, 2050-2066`, `module_async.go` | No action; recorded for completeness | ACCEPTED |
| C15 | H | Secret-key `CKA_VALUE` is mutable after creation and in copy templates — `readOnlyAttributes` omits it, `SetAttributeValue`/`CopyObject` apply it (§4.1.1: secret `CKA_VALUE` is not modifiable, footnotes 1,4,6,7 not 8) | `object.go:817, 2951, 2975, 2818, 2831` | Class-aware mutability rules; reject key-material writes with `CKR_ATTRIBUTE_READ_ONLY` (Codex) | **FIXED** — `keyMaterialAttributes`+`isImmutableKeyMaterial` (class-scoped: CKA_VALUE + RSA private components); wired into `SetAttributeValue`+`CopyObject`; `object_mutability_test.go` incl. CKO_DATA counter-case |
| C16 | H | Trusted certificates can be modified — `checkTrustedAssertion` only guards templates that *contain* `CKA_TRUSTED`; other attribute changes on a trusted cert pass (§ trusted certs cannot be modified) | `object.go:936, 2945, 2975, 2814, 2831` | If `Class==CKO_CERTIFICATE && CKA_TRUSTED`, reject any mutation/modified-copy with `CKR_ATTRIBUTE_READ_ONLY` (Codex) | **FIXED** — wholesale trusted-cert immutability added to `checkTrustedAssertion` (covers SetAttributeValue + modifying CopyObject); untrusted-cert counter-case green |
| C17 | H | `C_EncryptMessageBegin`/`C_DecryptMessageBegin` ignore `pParameter/ulParameterLen` — the Go core has no params arg, so GCM IV/nonce for the *Begin path is dropped (distinct from the already-fixed EncryptMessage/Next path) | `exports.go:2288, 2476`; `module.go:4487, 4792` | Parse/validate `CK_GCM_MESSAGE_PARAMS` in both Begin exports, thread to Go core, write generated IV back (Codex) | **FIXED** — both Begin exports parse `CK_GCM_MESSAGE_PARAMS`; Go core `EncryptMessageBegin`/`DecryptMessageBegin` take params, fail-fast-validate (shared `validateGCMMessageIVGeneration`, also now used by EncryptMessage/Next — DRY), apply caller IV; generated-IV write-back stays on final Next where the IV is actually produced. `TestEncryptMessageBegin_RejectsUnhonourableIVParams`, `TestDecryptMessageBegin_RequiresIV` |
| C18 | H | Message sign/verify `pParameter` ignored across all six entry points, including ML-DSA `CK_SIGN_ADDITIONAL_CONTEXT` (advertised at `mechanism_v32.go:328`) | `exports.go:2587, 2633, 2640, 2716, 2736, 2743`; `module.go:4955, 5195` | Typed message-param decode incl `CK_SIGN_ADDITIONAL_CONTEXT`; thread through; reject malformed with `CKR_MECHANISM_PARAM_INVALID` (Codex) | **FIXED (reject, not implement)** — investigation showed NO signature mechanism the module implements takes a per-message parameter: RSA/ECDSA/EdDSA are parameterless and ML-DSA `CK_SIGN_ADDITIONAL_CONTEXT` (non-empty domain-separation context) is unimplemented (module does empty-context pure ML-DSA everywhere). Per the module's locked reject-what-you-can't-honor philosophy (C1/C2/C4/C10) + No-Cruft/YAGNI, all 6 C-ABI entry points now reject a non-NULL `pParameter` with `CKR_MECHANISM_PARAM_INVALID` (`rejectSignMessageParam`) rather than silently returning a wrong-context signature; NULL/parameterless form unchanged. cabi test `message_sign_test.go` (+ shims/ops wrapper). **Full ML-DSA context support is a future capability if ever advertised — filed, not stubbed.** |
| C19 | M | `C_VerifyMessageNext` uses `ulSignatureLen>0` for finality instead of `pSignature != NULL` — a legitimate zero-length final signature is treated as non-final (§ finality keys on non-NULL pointer) | `exports.go:2753`; `module.go:5206` | Preserve pointer-nullness as an explicit final flag; pass empty non-nil signature to final path (Codex) | **FIXED** — `final bool` threaded from C ABI (`pSignature != nil`) into `VerifyMessageNext`; mirrors `EncryptMessageNext`; Go + `.so` build clean, callers updated |
| C20 | P1 | Restore errors swallowed at `C_Initialize` → partial token state under `CKR_OK` (token-state + per-object load failures skipped silently) | `module.go:601, 632, 444`; `storage.go:320, 325` | Fail `C_Initialize` with `CKR_DEVICE_ERROR` on corrupt/unreadable records, or quarantine + expose degraded state (Codex) | **FIXED (fail-closed)** — `loadPersistedState` returns `CKR_DEVICE_ERROR` on LoadTokenState/LoadObjects error (corrupt token-state must not silently reset PIN/lockout); `LoadObjects` now surfaces a corrupt/unreadable record instead of dropping it; `TestLoadObjects_SurfacesCorruptRecord`. Note: degraded-mode quarantine is the alternative if availability demands it |
| C21 | P1 | `C_InitPIN`/`C_SetPIN` return `CKR_OK` after a failed PIN persist (in-memory updated, write error only logged) — reboot loses the new PIN silently | `module.go:1316, 1328, 1392, 1406` | Return `CKR_DEVICE_ERROR` on failed write; roll back in-memory or use atomic update (Codex) | **FIXED** — both return `CKR_DEVICE_ERROR` on persist failure; `TestInitPIN_ReportsDeviceErrorWhenPersistFails` (fault-injecting backend) |
| C22 | P1 | `C_InitToken` can resurrect token objects after a failed persistent delete — `destroyTokenObjects` only logs `DeleteObject` failures, then state persists and returns OK | `module.go:1241, 1268, 2664` | Make `destroyTokenObjects` return an error; fail `C_InitToken` with `CKR_DEVICE_ERROR`; add token epoch/generation to prevent stale-record restore | **FIXED** — `destroyTokenObjects` returns first delete error; `C_InitToken` returns `CKR_DEVICE_ERROR`; `TestInitToken_ReportsDeviceErrorWhenObjectDeleteFails`. Token epoch/generation (anti-rollback) folded into the C9 storage rework |
| C23 | L | C ABI `cBytes` narrows `CK_ULONG` lengths to `C.int`/`MaxInt32` (`CK_ULONG` may be 64-bit) | `exports.go:64` | Checked `unsafe.Slice` copy validated against Go `MaxInt` (Codex) | **FIXED** — bound raised to `math.MaxInt`, copy via `unsafe.Slice`+append; `.so` rebuilds clean |
| C24 | L | Entropy failure panics inside `hashPin`/`generateSerialNumber` — C ABI recovers to `CKR_FUNCTION_FAILED`, but direct Go callers (xkey embedded) get a panic | `token.go:850, 904` | Return errors; map entropy failure to `CKR_DEVICE_ERROR`/`CKR_FUNCTION_FAILED` consistently (Codex) | **FIXED** — `hashPin`/`generateSerialNumber` return `ErrEntropyUnavailable` instead of panicking; `Token.SetSOPin`/`SetUserPin` propagate; all `autoInitializeToken`/`InitToken`/`InitPIN`/`SetPIN` sites map it to `CKR_DEVICE_ERROR`. `entropySource` package var makes the path testable; `entropy_failure_test.go` proves error-not-panic + C_InitToken→CKR_DEVICE_ERROR. Test call sites use `mustHashPin` helper |
| C25 | H | **Multi-part GCM message path shares the C4 gap** — `EncryptMessageNext` silently downgrades a caller-fixed-prefix / counter IV request to a random IV (single-part `EncryptMessage` now refuses it). Found while investigating C17. | `module.go` `EncryptMessageNext` IV block | Same guard as C4: refuse nonzero `IVFixedBits` / `CKG_GENERATE_COUNTER`(`_XOR`) with `CKR_MECHANISM_PARAM_INVALID` | **FIXED** — guard added; `TestEncryptMessageNext_RefusesFixedBitsAndCounterIVGenerators` |

**Fix ordering within Phase 1**: C0 first (security), then C15–C19 (attribute
mutability + message params), then C1–C8 (mechanism truthfulness), then C20–C24
(persistence error-handling + robustness), then C11/C12 residuals. Each fix gets a
works-test + an invalid-input test (per project rule: ≥2 tests/function).

Phase 1 exit criteria: C0–C8, C15–C24, C11, C12 fixed with regression tests;
C9/C10 decided and either implemented or formally accepted here;
`make test-pkcs11-module`, `-race`, and `integration-test-pkcs11-module-all` green.

**PHASE 1 STATUS (2026-08-12): COMPLETE for all implementable findings.** C0–C8,
C10, C11, C12, C15–C23, C25 all FIXED + regression-tested; full `test-pkcs11-module`
suite green. Two findings are plan-sequenced into Phase 5 because their fixes REQUIRE
Phase 5 infrastructure, not because they are skipped: **C9** (per-token AEAD storage
sealing) folds into **L3** (offline key-at-rest); **C24** (entropy-panic → error) folds
into the Phase 5 embedded Go entry boundary. Both are recorded, decided, and scheduled.
Integration lanes (`integration-test-pkcs11-module-all`, conformance, cabi) need a
devcontainer run to confirm — not runnable in the review environment.

## Phase 2 — FIPS + non-FIPS builds (P2)

Current state: **no FIPS `.so` build exists.** `GOFIPS140` is not a Makefile
variable; only `integration-test-pkcs11-fips`'s Go test binary ever sees it.
Runtime detection (`pkg/crypto/fips/fips.go:47-59`) reads the **env var**, not the
compiled-in `crypto/fips140.Enabled()` state — so a non-FIPS `.so` with
`GOFIPS140=latest` in the environment *claims* FIPS filtering without FIPS crypto,
and vice versa. No CK_INFO/CK_TOKEN_INFO string identifies a FIPS build.

| ID | Task | Status |
|----|------|--------|
| F1 | Makefile: `GOFIPS140 ?= off` (non-FIPS default) + `GOFIPS140_FIPS ?= latest` (FIPS default, user-pinnable to exact version e.g. `v1.0.0`) in variables block | **DONE** — both vars added with doc comment |
| F2 | Thread `GOFIPS140=$(GOFIPS140)` into `build-pkcs11-module` and both `run_with_server` .so rebuild sites (Makefile:1927, 1935) | **DONE** — build target + both `run_with_server` macro build sites thread `GOFIPS140` |
| F3 | New `build-pkcs11-module-fips` target → separate artifact `libxkms_pkcs11_fips.so` built with `GOFIPS140=$(GOFIPS140_FIPS)`; both .so ship side by side | **DONE** — target added; both `.so` builds verified (GOFIPS140=off / latest) |
| F4 | FIPS self-identification: CK_INFO `LibraryDescription` (module.go:297/324) and CK_TOKEN_INFO model (token.go:444) branch on FIPS — e.g. "go-xkms PKCS#11 (FIPS 140-3)" / "Virtual Token FIPS" | **DONE** — `moduleLibraryDescription()`="go-xkms PKCS#11 FIPS 140-3", `tokenModel()`="FIPS 140-3 Token" (fit 32/16-byte fields); `fips_label_test.go` |
| F5 | Base self-ID + mechanism filtering on **compiled** state: `crypto/fips140.Enabled()` authoritative; decide relationship with env-var runtime toggle (compiled state must win for labeling; document the policy in `pkg/crypto/fips`) | **DONE** — `fips.Compiled()`(=`crypto/fips140.Enabled()`) drives LABELING (build-time truth); `fipsModeEnabled()`=`Compiled() OR Enabled()` so the FIPS `.so` ENFORCES from compiled state while tests simulate via env; `fips140.Enabled()` verified to flip off/latest |
| F6 | FIPS integration lanes (`-fips`, `-fips-enforcement`, cabi/tool/OpenSSL/SSH FIPS variants) must dlopen the FIPS-built `.so`, not the default one | **DONE (core), devcontainer-verify** — `-fips-enforcement` compiles its `.so` FIPS (target-specific `GOFIPS140`), dlopens the real FIPS artifact; `label_test.go` asserts CK_INFO/CK_TOKEN_INFO say FIPS. `-fips` (conformance) is Go-linked, already FIPS via `GOFIPS140=latest`. cabi/tool/OpenSSL/SSH FIPS variants = follow-up (needs devcontainer) |

Phase 2 exit criteria: `make build-pkcs11-module` (non-FIPS) and
`make build-pkcs11-module-fips` (FIPS) both produce working modules;
`pkcs11-tool -I`/`-T` shows the FIPS identifiers on the FIPS artifact only;
FIPS lanes green against the FIPS artifact.

## Phase 3 — OpenSSL / OpenSSH interop completeness (P3)

Existing lanes are broad (12+ targets; RSA/EC/Ed25519 sign+login via OpenSSH 10.4,
provider + engine + x509 + TLS handshake). Confirmed gaps:

| ID | Gap | Status |
|----|-----|--------|
| T1 | **Broken lane**: `integration-test-pkcs11-openssl-schemes` `-run` regex (Makefile:1554) matches no existing test — only TLS handshake tests run; fix to real names (`TestOpenSSL_EngineRSAPSS\|TestOpenSSLProvider_RSAPSS\|TestOpenSSL_EngineRSAOAEPDecrypt\|TestOpenSSLProvider_RSAOAEP\|TestOpenSSL_TLSHandshake`) | **FIXED** — regex now `TestOpenSSL.*RSAPSS\|TestOpenSSL.*RSAOAEP\|TestOpenSSL_TLSHandshake`, matching both Engine and Provider PSS/OAEP variants (verified against the real test names) |
| T2 | RSA-PSS via `pkcs11-tool --sign -m ...-PKCS-PSS` untested | **DONE (compiles; devcontainer-verify)** — `TestPKCS11Tool_SignRSAPSS` (`pkcs11_tool_schemes_test.go`): RSA-2048 keygen + `SHA256-RSA-PKCS-PSS` sign, hard-asserts 256-byte sig |
| T3 | Wrap/unwrap via external tool (pkcs11-tool `--wrap`/`--unwrap`) untested (Go/C-ABI only) | **DONE (compiles; SoftHSM2-validated flags; devcontainer-verify)** — `TestPKCS11Tool_KeyWrapUnwrap` (`pkcs11_tool_wrap_test.go`): AES-KEY-WRAP roundtrip, RFC 3394 length asserted |
| T4 | ECDH derive via external tool (`pkcs11-tool --derive`, `openssl pkeyutl -derive`) untested | **DONE (compiles; SoftHSM2-validated; devcontainer-verify)** — `TestPKCS11Tool_ECDHDerive` (`pkcs11_tool_derive_test.go`): P-256 ECDH1-DERIVE vs external peer, distinct-peers-distinct-secrets |
| T5 | Ed25519 keygen via OpenSSL provider (`genpkey -algorithm ED25519` into token) untested | **DONE (compiles; devcontainer-verify)** — `TestPKCS11ProviderKeygen_Ed25519InToken` (`pkcs11_tool_schemes_test.go`): in-token Ed25519 keygen + sign + external verify |
| T6 | AES-CBC pkcs11-tool test is a soft assertion (`t.Logf` on error, `pkcs11_tool_test.go:1183`) — make it hard | **FIXED** — supplies the required `--iv` (CK_AES_CBC IV parameter) and hard-asserts success + block-aligned, non-plaintext ciphertext (compiles; needs devcontainer to run) |
| T7 | Digest via `pkcs11-tool --hash` untested externally | **DONE (compiles; devcontainer-verify)** — `TestPKCS11Tool_HashDigest` (`pkcs11_tool_schemes_test.go`): SHA256 digest matched byte-for-byte against `crypto/sha256` |
| T8 | Certificate object write/read-back via `pkcs11-tool --write-object --type cert` not asserted | **DONE (compiles; SoftHSM2-validated; devcontainer-verify)** — `TestPKCS11Tool_CertificateWriteReadback` (`pkcs11_tool_cert_test.go`): DER cert write + read-back byte-exact |
| T9 | Hygiene: hoist `.so` build out of `run_with_server` (15 identical rebuilds per `-module-all` run) into a shared file/stamp target | DEFERRED (perf, not correctness) — ideal fix: build the `.so` once per `make` into a stamp the lanes order-only-depend on; but `run_with_server` builds inside the devcontainer via `docker exec`, so the hoist must restructure the macro and can only be validated by a devcontainer `-module-all` run. Not changed to avoid unverifiable CI breakage |
| T10 | Hygiene: `-openssl` lane (`-run 'TestOpenSSL'`) is an unanchored superset re-running provider/engine/x509 tests inside `-module-all`; tighten regexes | DEFERRED (perf, not correctness) — ideal fix: scope `-openssl` to the base tests the dedicated lanes don't cover; partition is unverifiable without a devcontainer run (risk of under-running). Documented |
| T11 | Hygiene: duplicate test function names across disjoint tag sets (`TestPKCS11ToolListSlots`/`ListMechanisms` in two files) + inconsistent tag discipline on `pkcs11_compatibility_test.go` | DEFERRED (latent fragility) — ideal fix: rename the duplicates AND align tags together (aligning tags alone would collide the duplicate symbols in a shared lane). Cross-file rename needs a devcontainer compile across every tag combination to confirm; documented rather than risk an unverifiable duplicate-symbol break |

Phase 3 exit criteria: matrix in the infra review covered — every operation the
module supports that pkcs11-tool/OpenSSL/OpenSSH can express is exercised by a
hard-asserting test; `integration-test-pkcs11-module-all` green in the devcontainer.

## Phase 4 — Token persistence via remote xkms backend (P4)

**Reality check from the review: no partial implementation exists.** Persistence
today is `StorageType ∈ {memory, file}` only (`config.go:59-71`,
`module.go:572-591`); the `PKCS11Transport` carries crypto RPCs exclusively — zero
persistence traffic. This phase is net-new. Sessions themselves are correctly
ephemeral per spec; what persists is token state (label/flags/PIN hashes/lockout
counters), token objects, and the handle counter.

**D1 — Transport family — DECIDED (maintainer, 2026-08-12).** The module's remote
mode talks to xkmsd over **any supported transport EXCEPT MCP** — i.e. **gRPC, REST,
QUIC, and Unix**. MCP is excluded because it is an AI/LLM-specific transport, not a
crypto data plane. Embedded is reserved for offline mode (Phase 5), not "remote".
Consequences:
- The full family is `gRPC | REST | QUIC | MCP | Unix | Embedded`
  (`pkg/api/transport/transport.go:16`, `client.go:552`). The module today only
  constructs **unix + grpc** (`module.go:56-57, 768-837`) — so **REST and QUIC client
  construction are added scope** in `initializeClient`, and MCP is explicitly refused
  with a clear error.
- The persistence wire contract rides the SAME `transport.Client` surface as the
  existing crypto RPCs (one channel, selected by `Target` scheme), not a bespoke
  side-channel: add PKCS#11 state RPCs (token metadata / PIN state / object metadata /
  handle allocation) to `transport.Client` so all four transports get them uniformly
  via structural typing, respecting the qrdb SDK boundary (storage lives server-side
  in xkmsd's embedded qrdb node).

Design decisions still needed BEFORE implementation (maintainer input):

- **D2 — Failure semantics**: `SaveTokenState`/`SaveObject`/`GetNextHandle` run
  synchronously inside PIN-verification and object-creation paths. Blocking
  (consistent, adds network latency to C_Login) vs best-effort with
  `LastStorageError` surfacing (current local pattern, `module.go:242-249`).
- **D3 — Multi-client semantics**: two hosts loading the same remote token
  (handle-counter allocation, PIN lockout counter races, object visibility).

Codex corroboration: `transport.go:47` interface is crypto/PIV only; `config.go:68`
+ `303` reject any non-file/memory type; `initializeStorage` (`module.go:572`) builds
only file/memory; sessions rebuilt in-memory at init (`module.go:425`) and cleared at
finalize (`module.go:881`). No remote state RPC exists.

Implementation once decided:

| ID | Task | Status |
|----|------|--------|
| R0 | Add REST + QUIC client construction to `initializeClient` (unix + grpc exist today); refuse MCP scheme with a clear error | **FIXED** — `quic://` wired (auto-construct) + `rest://` (see note); `mcp://` refused (`ErrMCPTargetNotSupported`); shared `buildTransportOptions` (DRY). **REST is injection-only**: the module can't import `transport/rest` (cycle: `pkg/auth`→module→`transport/rest`, and `transport/rest` tests→`pkg/api/rest`→`pkg/auth`), so a REST client is built by the composition root and passed via `WithClient` (`ErrRESTClientMustBeInjected` if a `rest://` target is set without injection). `TestValidateTarget` + MCP test |
| R1 | Add PKCS#11 state RPCs (token/PIN/object metadata, handle alloc) to the `transport.Client` surface + xkmsd server handlers; respect qrdb SDK boundary | **DONE over gRPC+Unix** — `PKCS11StateService` (Put/Get/Delete/List/PutIfAbsent) end to end: proto+regen, gRPC server handlers (`service_pkcs11state.go`, keys-resource authz), gRPC+Unix client methods, `pkg/xkms/servicer_pkcs11state.go` servicer, `pkg/pkcs11state` Pattern-A qrdb-backed store, server composition (`server.go`). Used CONCRETE methods + a narrow module-side `PKCS11StateClient` (type-asserted, like `PKCS11Transport`) instead of widening the shared `transport.Client`/`XKMSServicer` — no all-or-nothing break, build green throughout. Tests: `pkcs11state/store_test.go`, `xkms/servicer_pkcs11state_test.go`. **All four transports now wired**: gRPC/Unix/QUIC auto-construct + REST via injection; each has client methods + server handlers (`handlers_pkcs11state.go`/`pkcs11state_handlers.go`, keys-resource authz) with compile-time `PKCS11StateClient` contract checks. Multi-client atomic lockout-counter value-CAS (strict D3) = **cross-repo follow-up**: neither `storage.Backend` (qrdb-owned alias) nor the qrdb SDK exposes a value-CAS today (only `PutIfAbsent`). Needs (1) a qrdb `CompareAndSwap(key, expected, new)` storage primitive [go-qrdb change, Raft-replicated], (2) a new `PKCS11StateCAS` RPC, (3) module lockout-counter use, (4) multi-client devcontainer E2E. Single-client remote persistence (the common case) is unaffected and works today |
| R2 | `storage.Backend` adapter speaking those RPCs over the active `transport.Client` | **DONE** — `storage_remote.go`: `remoteBackend` implements all 8 `storage.Backend` methods over `PKCS11StateClient` (Scan/Exists composed; Get-absent→`storage.ErrNotFound`); compile-time checks pin gRPC/Unix `Transport` to the interface; `storage_remote_test.go` (fake client) |

### R1 build map (from surface research 2026-08-12) — the pieces, in order

**Pattern to follow:** `PasswordService` (client `client.go:352-382`, servicer
`servicer.go:207-217`, server `pkg/xkms/servicer_password.go`, qrdb-backed store
`pkg/staticpw/dao_store.go` via `qrdbsdk.NewDAO`). Do NOT reuse `SealStoreService` —
it is a local-only platform store (`ErrNotSupported` on every network transport).

- `storage.Backend` (8 methods) is generic; `ModuleStorage` needs NO change — a
  remote backend plugs straight in. `transport.Client` already satisfies
  `PKCS11Transport` (superset), so no crypto-path change.
- **Proto toolchain is available here** (`protoc` 25.1 + `protoc-gen-go`/`-go-grpc`;
  `make proto`).
- New `PKCS11StateService`: `Put/Get/Delete/List/CAS` DTOs (namespaced per
  tenant+token; CAS for the D3 lockout counter). Add to `Client` (`client.go:558`)
  and `XKMSServicer` (`servicer.go:27`). **This is all-or-nothing**: adding to those
  interfaces forces implementations in ALL SIX transports or the build breaks —
  grpc (`transport.go`, proto), unix (free via the same generated proto client),
  rest (`transport.go` + new `pkg/api/rest/pkcs11state_handlers.go` + routes in
  **`pkg/api/rest/server.go` — THE contended file**), quic (`transport.go`;
  server side served by the same REST route table — QUIC is HTTP/3 on the REST
  port, not a separate `pkg/api/quic` package), mcp (`ErrNotSupported` stub),
  embedded (`ErrNotSupported` — offline mode uses local storage per D4; **one-line
  maintainer confirm**). Server side: new `pkg/xkms/servicer_pkcs11state.go` against
  `qrdbsdk.KVStore`/`GenericDAO`; composition in `pkg/server/server.go` (~line 1592,
  like `s.passwordStore = staticpw.NewStore(backend)`).
- **D2 (blocking) + D3 (server-authoritative + CAS)** are already decided; the store
  uses qrdb's atomic `PutIfAbsent`/CAS for the lockout counter.
| R2 | `storage.Backend` adapter speaking those RPCs over the active `transport.Client` | **DONE** — `storage_remote.go`: `remoteBackend` implements all 8 `storage.Backend` methods over `PKCS11StateClient` (Scan/Exists composed; Get-absent→`storage.ErrNotFound`); compile-time checks pin gRPC/Unix `Transport` to the interface; `storage_remote_test.go` (fake client) |
| R3 | `StorageType: "remote"` through `config.go` validation + `initializeStorage` + env (`XKMS_PKCS11_STORAGE_TYPE=remote`) | **DONE** — `StorageTypeRemote` const + `TenantID` config field + `validateStorage` case (requires token label); `initializeStorage` type-asserts `m.client` to `PKCS11StateClient` (runs after `initializeClient`) → `newRemoteBackend`; env `XKMS_PKCS11_STORAGE_TYPE=remote` works via existing plumbing |
| R4 | Integration suite: token state/objects/PIN-lockout survive module restart against live xkmsd, over **each** of gRPC/REST/QUIC/Unix | REMAINING (needs devcontainer) — all four transports now have both ends + authz golden tests updated (grpc/quic/rest/mcp green); unit coverage of store+remote-backend+servicer exists. The E2E restart-survival suite against a live xkmsd (gRPC/Unix/QUIC auto, REST injected) needs the devcontainer to run |

## Phase 5 — Offline local mode, SoftHSM-like (P5)

Persistence already works offline (`file` storage). The whole gap is crypto
delegation: every crypto primitive calls `PKCS11Transport`
(`transport.go:47-126`), and `cmd/pkcs11-module` `C_Initialize` unconditionally
dials unix/gRPC and fails `CKR_DEVICE_ERROR` without a live server
(`module.go:401-403, 764-805`).

Head start: `pkg/api/transport` already has an **Embedded** variant (in-process
xkms service, no network) — the xkey desktop app uses it today. The injection
point `module.WithClient` (`module.go:270-275`) exists but is unreachable from the
cgo entry points.

**D4 — Offline architecture — DECIDED (maintainer, 2026-08-12): EMBED xkms in the
`.so`.** `cmd/pkcs11-module`'s `C_Initialize` gains a config-selectable local mode
that wires the existing **Embedded** transport (in-process xkms service: backend
registry + `pkg/backend/software` + file storage, no network listener) through the
`module.WithClient` injection point (`module.go:270-275`). This keeps ONE crypto path
(the same servicer the network transports use), satisfying the no-duplication rule;
the rejected alternative was a bespoke minimal `PKCS11Transport` that would have
reimplemented servicer dispatch.

| ID | Task | Status |
|----|------|--------|
| L1 | Config surface: mode selection (`XKMS_PKCS11_MODE=local\|remote`, or `Target: "embedded://…"`) with validation; local mode must NOT dial a socket | **DONE** — `XKMS_PKCS11_MODE=local\|offline` read at the composition root (`cmd/pkcs11-module/offline.go`, `offlineModeRequested`); module stays transport-agnostic (accepts injected client). `XKMS_PKCS11_LOCAL_KEYDIR` override. Tests: `TestOfflineModeRequested`, `TestLocalKeyDir_Resolution` |
| L2 | Embedded service composition inside the .so (backend registry, `pkg/backend/software`, file storage, no listener) wired via `module.WithClient` from the cgo `C_Initialize` | **DONE** — `buildOfflineModule` uses SDK `NewEmbeddedClient` (file-backed software service, no listener) + `module.New(WithClient, WithConfig)` + `SetGlobalModule`; `C_Initialize` builds it when offline requested and no global module set (so a Go caller like xkey can still inject its own). Added `module.HasGlobalModule()` (non-creating check). `.so` builds. `TestBuildOfflineModule_InitializesWithoutNetwork` proves Initialize succeeds with NO xkmsd to dial |
| L3 | Key-material-at-rest protection for local mode (ties into C9 MAC decision; SoftHSM parity = PIN-derived encryption) | **DONE (offline, in-process verified)** — see C9. `SealController` seam + `pkg/pkcs11/localseal` barrier + offline `.so` wiring; AES-256-GCM at rest proven. C_SetPIN rekey is the one follow-up. Devcontainer E2E = L4 |
| L4 | Integration suite: full conformance + pkcs11-tool/OpenSSL/OpenSSH lanes with NO xkmsd running | READY (L2 done) — needs devcontainer: run the conformance + pkcs11-tool/OpenSSL/OpenSSH lanes against the `.so` with `XKMS_PKCS11_MODE=local` and no xkmsd. Unit proof (`TestBuildOfflineModule_InitializesWithoutNetwork`) exists; full external-tool E2E needs the devcontainer |

---

## Decisions

**Resolved (2026-08-12):**
- **D1 — remote transport family**: any supported transport except MCP →
  gRPC / REST / QUIC / Unix (MCP is AI/LLM-specific; Embedded is offline only).
- **D4 — offline architecture**: embed xkms in the `.so` via the Embedded transport
  (one crypto path, DRY).

**DECIDED (maintainer ratified 2026-08-12).** Industry anchors: SoftHSM2 / nShield
key-blobs (storage) and the KMIP / CloudHSM networked model (remote). L3 is unblocked
(folds into C9); R1 is unblocked (D2/D3 settled). Resolutions:

- **C9 — storage record integrity → CONSUME qrdb's barrier, do NOT build a sealer.**
  **REVISED 2026-08-12 after reading `~/sources/automatethethings/software/docs/05-seal-barrier-architecture.md`
  + `00-ownership-and-sdk-boundary.md` (NORMATIVE).** Those docs are unambiguous:
  **go-qrdb is the single barrier authority; go-xkms supplies hardware `SealingStrategy`
  implementations and PIN backends only, and must NEVER build its own sealing/AEAD
  layer.** The earlier sketch here (bespoke per-token TMK + Argon2id(PIN) KEKs +
  per-record AES-GCM) is WITHDRAWN — it would be a second barrier implementation, an L1
  ownership violation. Corrected design:
  - **Remote mode (Phase 4): ALREADY protected.** Records land in xkmsd's embedded qrdb
    node, whose `StorageBarrier` encrypts ALL persistent data at rest under the system
    (or per-tenant) barrier. No module-side crypto needed — the server's barrier is the
    at-rest protection. C9's integrity concern for remote mode is closed by construction.
  - **Offline/embedded mode (Phase 5 L3): use a KEYED barrier strategy.** The offline
    `.so` embeds a qrdb node (D4), which has a barrier. Local file storage routes through
    that node's barrier-protected `sealed.Backend`. At-rest protection = choosing a keyed
    strategy (`passphrase` — the KDF over an admin/PIN-supplied secret — or an
    xkms-injected hardware strategy `tpm2`/`pkcs11`) instead of `none`. SoftHSM PIN-parity
    = map the PKCS#11 user PIN to the `passphrase` strategy's admin secret at
    init/unseal. NO hand-rolled TMK, NO per-record AEAD in the module — the barrier's
    `EpochBarrier` (AES-256-GCM + epoch rotation + memguard) does it.
  - **Tamper-evidence of the plaintext-metadata gap (the original M7 finding):** in the
    LOCAL `file`/`memory` modes with strategy `none` (dev/test), records are cleartext —
    same posture as SoftHSM and qrdb's own `none`. Fixed by choosing a keyed strategy,
    which is now the barrier's job, not a module MAC.
  - DRY: C9 and L3 are ONE construction = "wire the embedded node's `sealed.Backend`
    (keyed) as the module's storage backend." Needs maintainer sign-off on the
    PIN→passphrase mapping + default strategy. **NOT the withdrawn AEAD scheme.**
- **C10 — SHA-1 split → gate the FLAGS, not the mechanism.** Keep `CKM_SHA1_RSA_PKCS`
  / `CKM_ECDSA_SHA1` discoverable with `CKF_VERIFY` (legacy verify is legitimate per
  SP 800-131A), **clear `CKF_SIGN`** when the weak-hash policy forbids SHA-1 signing.
  Compute advertised flags from the effective policy at `C_Initialize`, using the
  existing FIPS choke-point pattern (`GetMechanismDescriptor`) so advertise and enforce
  cannot drift. Truthful `C_GetMechanismInfo` = the OpenSSL-provider/NSS approach.
- **D2 — remote failure semantics → synchronous confirmed-durable for
  security-critical writes; `CKR_DEVICE_ERROR` on failure.** Lockout-counter increments
  and token-object creation (`C_GenerateKey`/`C_CreateObject`) must commit before the
  call returns `CKR_OK`/the auth result — best-effort loss of either is a security bug
  (unlimited PIN guesses / undetectable object loss). Same principle as C20/C21/C22 —
  fold them together. Reconstructable state may stay best-effort (`LastStorageError`).
- **D3 — remote multi-client → server-authoritative + per-instance handles + CAS.**
  `CK_SESSION_HANDLE`/`CK_OBJECT_HANDLE` are instance-local per spec → **no cross-host
  handle coordination**; durable identity is the **server object ID**, so the local
  object-handle counter is dropped in remote mode. Authoritative shared state (token
  metadata, PIN state, **lockout counter**) lives server-side in xkmsd's qrdb (Raft,
  linearizable); lockout increments use **atomic CAS/`PutIfAbsent`** (already in the
  stack) so N clients can't inflate the guess budget; `FindObjects` reads through to
  the server for cross-client object visibility. Corollary: **remote mode keeps NO
  local on-disk state** — the server IS the store (local file store = offline mode
  only). This narrows R1–R4.

All four ratified — implementation may proceed.

## CLOSEOUT PLAN — the last items (cross-repo + devcontainer)

Everything verifiable in this repo is DONE and green (Phases 1–5, C0–C25, F1–F6,
offline at-rest encryption + C_SetPIN rekey). What remains cannot be finished or
verified here: one item needs a change in **go-qrdb**, the rest need the
**devcontainer** to run real tools / a live xkmsd. This section is the ordered,
actionable checklist to close the module out. IDs continue the register (X-series
= cross-repo, E-series = devcontainer E2E).

### X1 — go-qrdb: surface the existing MVCC CAS (strict multi-client D3)

**Why:** the remote-mode lockout counter must be race-safe when two hosts share one
token. `PutIfAbsent` (write-if-absent) does not cover a value increment; concurrent
read-modify-write of the counter can lose an update and inflate the guess budget.

**KEY FINDING (2026-08-12 investigation — NO go-qrdb CHANGE NEEDED):** the linearizable
cross-node CAS is **already shipped and exposed** by the qrdb SDK as
`transport.TransactionClient.ExecuteTransaction(TransactionRequest{Compares, SuccessOps,
FailureOps})` — the full etcd-style txn, with `CompareValue`/`CompareVersion`,
`CompareEqual`/`NotEqual`, and `Responses []OpResponse` (Get ops return the current
value). **Proof it already works cross-node:** go-xkms's own `pkg/storage/qrdb/backend_putifabsent.go`
implements `PutIfAbsent` with exactly this txn (`CompareVersion==0` = absent). A value-CAS
is the SAME txn with `CompareValue`+expected and a `FailureOps=[OpGet]` to return current.
So X1 is **pure go-xkms consumption — zero opcode, zero qrdb change, zero go-quicraft
change.** (The earlier "new Raft opcode / MVCC RaftTransaction" analyses were both
superseded: the SDK txn client is the sanctioned public surface and already atomic.)

Steps (all in go-xkms):
1. Add `CompareAndSwap(ctx, key string, expected, new []byte) (swapped bool, current []byte, err error)`
   to `pkg/storage.Backend`. `expected == nil` = swap-only-if-absent; return current
   when it does not swap. Implement in every backend: memory/pebble/file/prefix
   (single-process, mutex/batch atomic — same posture as their PutIfAbsent), and
   `pkg/storage/qrdb/backend_compareandswap.go` via `ExecuteTransaction`
   (`CompareValue==expected` or `CompareVersion==0` for absent; `SuccessOps=[OpPut new]`,
   `FailureOps=[OpGet]`). The seal `BarrierBackend` inherits it by embedding `*Barrier`;
   the barrier's own value-compare works because the barrier decrypts on Get and
   encrypts on Put — the txn runs on the qrdb node under ITS storage (already ciphertext
   there), so use a **version-CAS** at the barrier boundary or route through the same
   qrdb txn. (Confirm the barrier path in impl; the pkcs11state store uses the qrdb
   backend directly, so the barrier-value-CAS subtlety only matters if a barrier wraps
   the pkcs11state store.)
2. `PKCS11StateCAS` RPC (transport DTO + gRPC/unix/quic/rest + servicer + pkcs11state
   store), mirroring `PKCS11StatePutIfAbsent` (pattern established this session).
3. `remoteBackend.CompareAndSwap` in `storage_remote.go` → the CAS RPC.
4. Lockout-counter increment uses a CAS retry-on-conflict loop (not read-modify-write)
   when `StorageType=remote`.
Success: E2's multi-client test shows N racing failed logins across two module
instances lock the token at exactly the threshold, never more.

### E1 — devcontainer: R4 remote-persistence E2E

**Goal:** token state / objects / PIN-lockout survive a module restart against a live
xkmsd, over **each** transport (gRPC/Unix/QUIC auto; REST injected).
Steps:
1. New `test/integration/pkcs11/module/remote/` package (tag `integration`): init a
   token via the `.so` with `XKMS_PKCS11_STORAGE_TYPE=remote` +
   `XKMS_PKCS11_TARGET=<scheme>`, create a token object + set PIN, `C_Finalize`,
   `C_Initialize` again, assert the object + PIN-lockout counter survived.
2. New Makefile lanes `integration-test-pkcs11-remote-{grpc,unix,quic}` (model on
   `integration-test-pkcs11-module-{unix,grpc}` at Makefile:1558/1563, swapping
   `XKMS_PKCS11_STORAGE_TYPE=file`→`remote` and the target scheme). REST needs a small
   harness that injects a REST client via `WithClient` (module can't dial REST).
3. A negative lane asserting `XKMS_PKCS11_TARGET=mcp://…` is refused
   (`ErrMCPTargetNotSupported`).
4. Add the passing lanes to `integration-test-pkcs11-module-all`.

### E2 — devcontainer: strict-D3 multi-client (depends on X1)

Two `.so` instances (or two processes) pointed at the same remote token; drive
concurrent failed `C_Login`s; assert the lockout fires at the threshold exactly once.
Only meaningful after X1 ships the CAS.

### E3 — devcontainer: L4 offline-`.so` E2E (no xkmsd)

**Goal:** the full conformance + pkcs11-tool/OpenSSL/OpenSSH suites pass against the
`.so` in `XKMS_PKCS11_MODE=local` with **no xkmsd running**, and the at-rest store is
encrypted (default `passphrase`).
Steps:
1. New lane `integration-test-pkcs11-offline`: build the `.so`, set
   `XKMS_PKCS11_MODE=local` + `XKMS_PKCS11_LOCAL_KEYDIR` + the token PINs, and run the
   conformance package (`./conformance/...`) and `-tool` run WITHOUT
   `run_with_server` (no daemon). Reuse the existing suites — they drive the `.so`.
2. A check that with `XKMS_PKCS11_SEAL_STRATEGY=passphrase` the on-disk key dir
   contains no plaintext key material (grep for a known-plaintext marker after keygen).
3. A `none`-strategy variant for the cleartext/dev path.

### E4 — devcontainer: Phase-3 interop lanes (verify the new tests)

Run the six interop tests written this session against the real `.so` + tools:
`TestPKCS11Tool_SignRSAPSS`, `_HashDigest`, `_KeyWrapUnwrap`, `_ECDHDerive`,
`_CertificateWriteReadback`, `TestPKCS11ProviderKeygen_Ed25519InToken`, plus the
hardened AES-CBC assertion. They compile (and the wrap/derive/cert ones were
SoftHSM2-validated on the host), but the flag assumptions noted in each file must be
confirmed against the devcontainer's pkcs11-tool/openssl builds. Fix the fixed
`-openssl-schemes` regex is already merged; just run `integration-test-pkcs11-compat-all`
+ `-openssl-all` and reconcile any flag differences.

### E5 — devcontainer: FIPS lanes on the FIPS `.so` (F6 completion)

`-fips-enforcement` already builds+loads the FIPS `.so` and checks the FIPS labels.
Extend the FIPS artifact to the remaining dlopen lanes: build FIPS variants of the
cabi / pkcs11-tool / OpenSSL / SSH lanes (target-specific `GOFIPS140:=$(GOFIPS140_FIPS)`
as `-fips-enforcement` does) so the whole external-tool surface is exercised against a
real FIPS build, not just the Go-linked conformance binary.

### Sequencing

X1 (go-qrdb CAS) is the only item that unblocks another (E2). Everything else is
independent and parallelizable. Suggested order: **E3 (offline — highest user value,
self-contained) → E1 (remote persistence) → E4 (interop) → E5 (FIPS lanes) → X1 →
E2**. None require code changes beyond what each step lists; the module's in-repo
implementation is complete.

## Update protocol

When a finding is fixed: flip Status to FIXED with the commit-ish/test name.
When new findings surface: append to the relevant phase table with the next ID
(C15+, F7+, T12+, R5+, L5+, X2+, E6+). Do not delete rows — history is the audit trail.

## X1 CLOSEOUT (2026-08-12) — DONE (all four steps implemented + unit-tested)

All of X1's in-go-xkms steps are complete; **no go-qrdb change was needed** (the
SDK's `transport.TransactionClient.ExecuteTransaction` already provides the
linearizable cross-node value-CAS, as the KEY FINDING above predicted).

- **Step 1 — `storage.CompareAndSwapper`.** Added as a SEPARATE optional interface
  (`pkg/storage/compareandswap.go`), not a widening of `storage.Backend`, so the
  seal `BarrierBackend` (pure embedding of qrdb's `*StorageBarrier`) is NOT forced
  to implement it — mirroring qrdb's own `AtomicKVStore`/`TransactionClient` split.
  Implemented + `var _` asserted on: `engineBackend` (memory/pebble/file via the
  qrdb engine — mutex-guarded read-modify-write, same single-writer posture as its
  PutIfAbsent), `FileStorage` (delegates to the engine + chmod on swap),
  `PrefixBackend` (namespacing delegation), and `pkg/storage/qrdb/backend_compareandswap.go`
  (linearizable via `ExecuteTransaction`: `CompareValue==expected`, or
  `CompareVersion==0` for the nil/absent case; `SuccessOps=[OpPut]`,
  `FailureOps=[OpGet]` returns current). `ErrCompareAndSwapUnsupported` sentinel for
  a non-CAS backend. Tests: `pkg/storage/compareandswap_test.go`,
  `pkg/storage/file/storage_compareandswap_test.go`.
- **Step 2 — `PKCS11StateCAS` RPC.** DTOs `PKCS11StateCASRequest/Response`
  (`Expected`/`New`/`ExpectAbsent`, `Swapped`/`Current`) in transport; proto
  `rpc PKCS11StateCAS` + messages regenerated (`make proto`); servicer
  `XKMSService.PKCS11StateCAS`; `pkcs11state.Store.CompareAndSwap` (type-asserts its
  backend to `storage.CompareAndSwapper`); wired on all five transports
  (gRPC/unix/quic/rest client + grpc/quic/rest server handler + rest route,
  `keys:update` for the rest route, `keys:write` for grpc). Golden authz contracts
  updated (grpc `goldenRPCPermissions` +`PKCS11StateCAS: keys:write`; quic count
  unchanged — new route lives inside `setupPKCS11StateRoutes`).
- **Step 3 — `remoteBackend.CompareAndSwap`** (`storage_remote.go`) → the CAS RPC;
  a nil `expected` is sent as `ExpectAbsent` (JSON cannot tell an omitted []byte
  from an empty one). `var _ storage.CompareAndSwapper` asserted. Test:
  `TestRemoteBackend_CompareAndSwap`.
- **Step 4 — server-authoritative lockout counter (user-chosen design).** The
  failed-attempt counters moved OUT of the token record into dedicated keys
  (`pkcs11/counters/token/<slot>/failed_{user,so}`), incremented atomically:
  `ModuleStorage.IncrementFailedAttempt` uses a CAS retry loop on a
  `CompareAndSwapper` backend (remote/clustered) and a mutex read-modify-write on a
  single-writer local backend; `ResetFailedAttempt` clears; `LoadFailedAttempts`
  reads the dedicated key directly, with no parameters and no record-snapshot
  fallback (go-xkms compat cleanup, 2026-09-22: an absent dedicated key is zero
  attempts, not a migrated value — this is pre-release alpha, so no migration
  path was kept). `SessionManager` now holds the local atomics as an
  optimistic cache: `recordFailedAttempt` stores back the authoritative
  post-increment value (`SetAttemptPersistence` replaced `SetAttemptPersister`);
  `loadPersistedState` restores from `LoadFailedAttempts`. Documented the bounded
  pre-check over-admission window (one extra derivation per lagging client; the
  increment still reads the durable value and locks, so the budget is never
  exceeded). Tests: `TestModuleStorage_FailedAttemptCounter_CAS`,
  `_ConcurrentAccumulates` (50 increments / 2 clients / `-race`, zero lost updates),
  `_AbsentKeyIsZero`, `_NilBackend`; existing `session_pin_lockout_test.go` (lockout
  survives restart / resets on success) still green through the new path.

**Remaining:** E2 (live multi-client devcontainer E2E) can now be written — the
primitive and the consumer both exist. Task #8 (multi-devcontainer cluster harness)
is the vehicle for E2 plus the broader cluster-operations verification.

## E2 CLOSEOUT (2026-08-12) — cluster CAS concurrency test ADDED (run pending devcontainer)

`test/integration/cluster/cluster_cas_test.go` (`TestCluster_CompareAndSwap_ConcurrentAccumulates`):
12 goroutines × 10 read-modify-CAS increments, spread across all three node REST
URLs, race one shared counter through the `PKCS11StateCAS` RPC (Raft-committed
`ExecuteTransaction`); the committed total must equal the number of increments (no
lost updates), then the value must replicate to every node. Live-path vs known
go-quicraft idle-stall handled like `TestCluster_WriteReplication` (graceful
degradation on stall). Compiles under `-tags integration` (vet clean); picked up
automatically by `make integration-test-cluster` (Dockerfile.test runs the whole
`./test/integration/cluster/...` package). It is the cluster analogue of the
module-level `TestModuleStorage_FailedAttemptCounter_ConcurrentAccumulates` (green,
-race).

**Blocker to actually RUN it (pre-existing, shared, not introduced here):** the
cluster harness's `httpClient` (`cluster_test.go:118`) is a plain client with no
RootCAs, while `config.node.yaml` now sets `tls.enabled=true` and compose dials
`https://nodeN:8443`. The SPKI trust-bootstrap over `/v1/ca/bundle` that the
comment at `cluster_test.go:108-118` describes is not yet wired, so EVERY cluster
REST test (not just this one) needs that client-trust work before the HTTPS suite
runs green in the devcontainer. That is in-flight harness migration owned outside
this change.

**Remaining task-#8 scope (broader than E2, not yet written):** multi-tenant
config + isolation across the cluster, and rebalance. init / peer-discovery /
leader-election / membership / replication / failover / restart-rejoin are already
covered by the existing cluster suite.
