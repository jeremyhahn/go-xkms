# Virtual FIDO2 Authenticator — Engineering Contract

> **Status: NORMATIVE** · Feature: `virtual-authenticator` · Module: `go-xkms/xkey` · Last verified: 2026-09-28

## Exported surface

### `pkg/fido2/uhid`

Linux UHID device creation and the HID report wire format:
`uhid_linux.go` (real), `uhid_stub.go` (non-Linux builds), `types.go`,
`serialize.go`, `errors.go`.

### `pkg/fido2/authenticator`

The CTAP2 implementation. One file per command:

| Command | File |
|---|---|
| `authenticatorMakeCredential` | `cmd_makecredential.go` |
| `authenticatorGetAssertion` | `cmd_getassertion.go` |
| `authenticatorGetInfo` | `cmd_getinfo.go` |
| `authenticatorClientPIN` | `cmd_clientpin.go` |
| `authenticatorCredentialManagement` | `cmd_credmgmt.go` |
| `authenticatorConfig` | `cmd_config.go` |
| `authenticatorReset` | `cmd_reset.go` |

Supporting: `authenticator.go`, `authdata.go`, `crypto.go`, `config.go`,
`errors.go`, `hid_adapter.go`, `pin_protocol.go`,
`pin_protocol_v1.go`, `migration.go`.

Extensions: `ext_hmac_secret.go`, `ext_deviceconfig.go`.

Storage seams: `storage.go` (the `StatefulCredentialStorage` /
`ListableStorage` / `ClearableStorage` interfaces), `storage_memory.go`
(`NewMemoryStorage`, the `--storage memory` default), `storage_backend.go`
(`BackendStorage`, adapting any `xkms.StorageBackend` — file or
barrier — to credential storage; this is the one type both the GUI and the
standalone daemon construct, so there is no separate DAO-backed store to
diverge from it), and `dao_rp_policy_store.go` (RP policy storage; unrelated
to credentials). `entity.go` and `dao_credential_store.go` — an unused
`GenericDAO`-backed credential store with zero non-test callers — were
deleted (#181); `BackendStorage` was always the production seam for both the
GUI and the daemon.

Key material: `key_manager.go`, `key_wrapper.go`, `keybackend/`.

PIN state lives on the authenticator as `state.PINHash` with a fixed
`PINHashSize` (`cmd_config.go:474`), and `key_manager.go:253` carries a
`PINSyncPending` path that re-initializes the user PIN when a sync was deferred.

### `pkg/fido2/authenticator` — exported Go surface

Constructor: `authenticator.go:256` `NewAuthenticator(config *Config) (*Authenticator, error)`.
Returns `ErrUserPresenceHandlerRequired` (`user_presence.go:28`) when
`config.UserPresenceHandler` is nil.

#### `Config` fields (`config.go:338`)

| Field | Type | Effect |
|---|---|---|
| `AAGUID` | `[16]byte` | attestation GUID reported in `getInfo` |
| `SupportedAlgorithms` | `[]int` | COSE algorithms advertised/accepted (default `[ES256]`) |
| `MaxCredentials` | `int` | cap on stored credentials (default 100) |
| `MaxResidentCredentials` | `int` | cap on discoverable credentials, must not exceed `MaxCredentials` (default 25) |
| `PINMinLength` | `int` | minimum PIN length (default 4, the CTAP2 floor) |
| `PINMaxRetries` | `int` | PIN attempts before lockout (default 8) |
| `EnablePIN` | `bool` | enables PIN-based user verification (default true) |
| `EnableResidentKey` | `bool` | enables discoverable credentials (default true) |
| `EnableCredentialManagement` | `bool` | enables `authenticatorCredentialManagement` (default true) |
| `EnableHMACSecret` | `bool` | enables the `hmac-secret` extension (default true) |
| `AlwaysUV` | `bool` | forces UV on every operation regardless of RP request (default false) |
| `UserPresenceHandler` | `UserPresenceHandler` | required — no default; see the constructor error above |
| `TokenInitWindow` | `time.Duration` | trust-on-first-use window for establishing the SO PIN; `0` selects `DefaultTokenInitWindow` and it cannot be disabled |
| `UserPresenceTimeout` | `time.Duration` | timeout for an interactive presence/verification request (default 30s) |
| `RequireUserPresence` | `bool` | require a touch even after a verified PIN, like hardware keys (default false) |
| `EnableUserIntentCheck` | `bool` | prompts for presence before returning `ErrPINRequired`, so a user can decline and fall through to another key (default false) |
| `KeyBackend` | `keybackend.FIDO2KeyBackend` | pluggable key backend; nil uses the legacy `crypto.go` path |
| `AttestationFormat` | `string` | `none`, `packed`, or `tpm`; an unprovisioned or uncertified attestation key falls back to `none` (default `none`) |
| `Storage` | `CredentialStorage` | required; must be set before `Validate()` |
| `Logger` | `*slog.Logger` | structured logging for CTAP2 commands; nil disables it |
| `OnCredentialCreated` | `func(cred *StoredCredential)` | callback after `MakeCredential` stores a new credential |
| `OnAssertionCompleted` | `func(rpID string)` | callback after a successful `GetAssertion`; used by AutoFill to suppress refiring |
| `UnifiedPIN` | `bool` | propagates the host PIN service's user PIN to this authenticator's CTAP2 PIN hash on set/change/verify |
| `PolicyIntegrityProvider` | `PolicyIntegrityProvider` | HMAC-signs and verifies RP policy integrity |
| `RPPolicyStore` | `RPPolicyStore` | per-RP policy storage |
| `Transports` | `[]string` | transports advertised in `getInfo` |
| `EnableEnterpriseAttestation` | `bool` | enables enterprise attestation |
| `EnableLargeBlobs` | `bool` | enables the `authenticatorLargeBlobs` command |
| `MaxLargeBlobArray` | `int` | max size of the large-blob array |
| `FirmwareVersion` | `uint32` | reported in `getInfo` key `0x0E`; encoded `major*10000 + minor*100 + patch` (default 0, not reported) |

#### Exported `*Authenticator` methods

| Method | Location | Purpose |
|---|---|---|
| `Close` | `authenticator.go:630` | releases authenticator resources |
| `ProcessCBOR` | `authenticator.go:497` | dispatches one raw CTAP2 CBOR command |
| `ProcessCBORWithContext` | `authenticator.go:524` | same, with cancellation/deadline; holds `cmdMu` for the whole call |
| `MakeCredential` | `cmd_makecredential.go:1475` | in-process `authenticatorMakeCredential` |
| `GetAssertion` | `cmd_getassertion.go:1539` | in-process `authenticatorGetAssertion` |
| `ClearAssertionState` | `cmd_getassertion.go:1376` | drops `getNextAssertion` enumeration state |
| `SetPINVerifier` | `authenticator.go:378` | installs a `PINVerifier` |
| `SetFIDO2PINHash` | `authenticator.go:387` | sets the CTAP2 PIN hash directly (unified-PIN path) |
| `SyncPINHash` | `authenticator.go:413` | re-syncs the PIN hash after a deferred change |
| `SetInitialPIN` | `cmd_clientpin.go:475` | in-process counterpart of `setPIN`; refuses with `ErrPINAlreadySet` if one exists |
| `IsPINSet` | `authenticator.go:845` | reports whether a user PIN is configured |
| `PINRetries` | `authenticator.go:880` | remaining PIN attempts |
| `GetPinUvAuthToken` | `cmd_clientpin.go:1329` | returns the current `pinUvAuthToken` |
| `VerifyPinUvAuthToken` | `cmd_clientpin.go:1421` | verifies a token's HMAC over `clientDataHash` |
| `AuthorizePinUvAuthToken` | `cmd_clientpin.go:1447` | checks and consumes a token for a permission/RP |
| `CanAuthorizePinUvAuthToken` | `cmd_clientpin.go:1480` | checks without consuming |
| `IsTokenInitialized` | `token.go:111` | reports whether the SO PIN has been established |
| `TokenFlags` | `token.go:119` | PKCS#11-style `CKF_TOKEN_INITIALIZED` / `CKF_SO_PIN_*` view |
| `InitializeToken` | `token.go:176` | establishes the SO PIN (`xkey fido2 init-token`) |
| `ChangeSOPIN` | `token.go:219` | replaces the SO PIN, proving the current one (`xkey fido2 change-so-pin`) |
| `UnlockSO` | `token.go:254` | authenticates the Security Officer for the current process |
| `AttestationCSR` | `attestation.go:172` | generates the attestation key and its CSR (`xkey fido2 provision-attestation`) |
| `InstallAttestationCertificate` | `attestation.go:212` | installs the CA-issued chain onto the device |
| `GetKeyManager` | `authenticator.go:432` | returns the `KeyManager` |
| `PolicyManager` | `authenticator.go:438` | returns the `PolicyManager` |
| `RPPolicyStore` | `authenticator.go:444` | returns the configured `RPPolicyStore` |
| `Storage` | `authenticator.go:886` | returns the configured `CredentialStorage` |
| `Config` | `authenticator.go:674` | returns the effective `*Config` |
| `GetState` / `State` | `authenticator.go:405`, `authenticator.go:831` | returns the live `*AuthenticatorState` |
| `AAGUID` | `authenticator.go:838` | returns the configured AAGUID |
| `SetOnCredentialCreated` | `authenticator.go:657` | installs the credential-created callback |
| `SetOnAssertionCompleted` | `authenticator.go:667` | installs the assertion-completed callback |
| `SetEnableUserIntentCheck` | `authenticator.go:682` | toggles `EnableUserIntentCheck` at runtime |
| `SetRequireUserPresence` | `authenticator.go:689` | toggles `RequireUserPresence` at runtime |
| `SetAlwaysUV` | `authenticator.go:696` | toggles `AlwaysUV` at runtime |
| `SetUserPresenceHandler` | `authenticator.go:708` | swaps the presence handler, returns the previous one |
| `UserPresenceHandler` | `authenticator.go:717` | returns the current presence handler |
| `HasMatchingCredentials` | `authenticator.go:760` | inspects a raw command for matching credentials without executing it |
| `NeedsPINBeforeTouch` | `authenticator.go:804` | reports whether a command needs the PIN before requesting presence |

#### Storage and key-backend interfaces

| Interface | Location | Contract |
|---|---|---|
| `CredentialStorage` | `config.go:77` | `Store`/`Load`/`LoadByRPID`/`Delete`/`Count`/`CountDiscoverable` |
| `CredentialIndexer` | `config.go:107` | optional in-memory credProtect index for fast existence checks |
| `StatefulCredentialStorage` | `storage.go:48` | `CredentialStorage` plus `SaveState`/`LoadState`/`Close` |
| `ListableStorage` | `cmd_reset.go:212` | optional `ListAll() ([][]byte, error)` |
| `ClearableStorage` | `cmd_reset.go:204` | optional `Clear() error` |
| `RPPolicyStore` | `rp_policy.go:54` | `SetPolicy`/`UpdatePolicy`/`GetPolicy`/`DeletePolicy`/`ListPolicies` |
| `KeyHandle` | `keybackend/keybackend.go:54` | opaque key reference: `CredentialID`/`Algorithm`/`BackendID` |
| `FIDO2KeyBackend` | `keybackend/keybackend.go:99` | `Type`/`Capabilities`/`GenerateCredentialKey`/`Sign`/`LoadKey`/`DeleteKey`/`ExportPrivateKey`/`ImportPrivateKey`/`Close` |
| `FIDO2AttestingKeyBackend` | `keybackend/keybackend.go:135` | `FIDO2KeyBackend` plus `GenerateAttestationKey`/`GetAttestationStatement`/`AttestationCertificateChain` |

Concrete implementations: `BackendStorage` (`storage_backend.go`, over any
`xkms.StorageBackend`), `MemoryStorage` (`storage_memory.go`),
`MemoryRPPolicyStore` (`rp_policy_memory.go`), `BackendRPPolicyStore`
(`rp_policy_backend.go`), `DAORPPolicyStore` (`dao_rp_policy_store.go`).

#### Exported error sentinels

The table below groups the package's sentinels by defining file with
representative names. `errorToStatus` (below) is the map from
sentinel to CTAP2 status byte for every one of them.

| File | Count | Representative sentinels |
|---|---|---|
| `errors.go` | 29 | `ErrInvalidCommand`, `ErrInvalidParameter`, `ErrCredentialNotFound`, `ErrOperationDenied`, `ErrPINRequired`, `ErrPINInvalid`, `ErrPINBlocked`, `ErrUserPresenceRequired`, `ErrUserVerificationRequired`, `ErrCredentialExcluded` |
| `storage.go` | 7 | `ErrStorageClosed`, `ErrCredentialExists`, `ErrStateNotFound`, `ErrInvalidCredentialID`, `ErrInvalidRPIDEmpty` |
| `rp_policy.go` | 5 | `ErrRPPolicyNotFound`, `ErrRPPolicyInvalidRPID`, `ErrRPPolicyNil`, `ErrRPPolicyStoreClosed`, `ErrRPBlocked` |
| `so_pin.go` | 7 | `ErrSOPINRequired`, `ErrSOPINInvalid`, `ErrSOPINBlocked`, `ErrSOPINAuthBlocked`, `ErrSOPINNotSet`, `ErrSOPINPolicyViolation`, `ErrSOPINAlreadySet` |
| `token.go` | 2 | `ErrTokenUninitialized`, `ErrTokenInitWindowClosed` |
| `key_manager.go` | 9 | `ErrKeyManagerAlreadyInitialized`, `ErrKeyManagerLocked` |
| `user_presence.go` | 6 | `ErrUserPresenceHandlerRequired`, `ErrUserPresenceDenied`, `ErrUserPresenceTimeout` |
| `cmd_clientpin.go` | 6 | ClientPIN subcommand errors (e.g. `ErrPINNotSet`, `ErrUnsupportedPINProtocol`) |
| `cmd_config.go` | 7 | `authenticatorConfig` subcommand errors |
| `cmd_credmgmt.go` | 6 | `ErrCredMgmtNotEnabled`, `ErrNoEnumerationInProgress` and related |
| `cmd_getassertion.go` | 8 | GetAssertion request-validation errors |
| `cmd_makecredential.go` | 10 | MakeCredential request-validation errors |
| `cmd_largeblobs.go` | 10 | `ErrLargeBlobs*` family |
| `ext_hmac_secret.go` | 4 | `ErrHMACSecretUserPresenceRequired`, `ErrHMACSecretInvalidInput`, `ErrHMACSecretSaltAuthMismatch`, `ErrHMACSecretInvalidSalt` |
| `ext_deviceconfig.go` | 3 | `deviceConfig` extension errors |
| `pin_protocol.go` / `pin_protocol_v1.go` | 8 | PIN protocol negotiation errors |
| `key_wrapper.go` | 7 | key-wrap/unwrap errors |
| `hid_adapter.go` | 6 | CTAPHID transport errors |
| `attestation.go` | 2 | `ErrAttestationOverrideUnsupported`, `ErrAttestationUnavailable` |
| `authenticator.go` | 5 | top-level construction/processing errors |
| `authdata.go`, `crypto.go`, `config.go`, `rp_policy_update.go` | 1–2 each | authenticator-data, crypto, config-validation, policy-update errors |

#### CTAP2 status mapping

`errorToStatus` (`authenticator.go:910`, called from `errorResponseFromError`,
`authenticator.go:904`) maps every sentinel above to one of the exported
`Status*` byte constants (`authenticator.go:47` onward) via `errors.Is`, with
`StatusOtherError` (`0x7F`) as the default for anything unmapped. Groups:

| Status | Sentinels mapped to it |
|---|---|
| `StatusPINRequired` | `ErrPINRequired`, `ErrSOPINRequired`, `ErrKeyManagerLocked` |
| `StatusPINInvalid` | `ErrPINInvalid`, `ErrSOPINInvalid` |
| `StatusPINBlocked` | `ErrPINBlocked`, `ErrSOPINBlocked` |
| `StatusPINNotSet` | `ErrPINNotSet`, `ErrSOPINNotSet` |
| `StatusPINPolicyViolation` | `ErrPINPolicyViolation`, `ErrSOPINPolicyViolation` |
| `StatusPINAuthInvalid` / `StatusPINAuthBlocked` | `ErrPINAuthInvalid` (wrapped by `ErrHMACSecretSaltAuthMismatch`) / `ErrSOPINAuthBlocked` |
| `StatusNotAllowed` | `ErrSOPINAlreadySet`, `ErrKeyManagerAlreadyInitialized`, `ErrTokenUninitialized`, `ErrTokenInitWindowClosed` |
| `StatusOperationDenied` | `ErrOperationDenied`, `ErrRPBlocked`, `ErrAttestationUnavailable`, `ErrEnterpriseAttestationNotEntitled`, `ErrUserPresenceDenied` |
| `StatusUnsupportedOption` | `ErrAttestationOverrideUnsupported`, `ErrUnsupportedOption` (wrapped by `ErrHMACSecretUserPresenceRequired`) |
| `StatusIntegrityFailure` | `ErrPolicyTamperLocked`, `ErrPolicyTampered`, `ErrLargeBlobsChecksumInvalid` |
| `StatusNoCredentials` | `ErrCredentialNotFound`, `ErrNoCredentials`, `ErrNoEnumerationInProgress` |
| `StatusUserActionTimeout` / `StatusKeepaliveCancel` | `ErrUserPresenceTimeout` / `context.Canceled` |
| `StatusUPRequired` / `StatusUVBlocked` | `ErrUserPresenceRequired` / `ErrUserVerificationRequired`, `ErrUVBlocked` |
| `StatusCredentialExcluded` | `ErrCredentialExcluded` |
| `StatusUnsupportedExtension` | `ErrUnsupportedExtension` |
| `StatusMissingParameter` | `ErrMissingClientDataHash`, `ErrMissingRP`, `ErrMissingRPID`, `ErrMissingUser`, `ErrMissingUserID`, `ErrMissingPubKeyCredParams`, `ErrMissingCredentialID`, `ErrMissingRPIDHash`, `ErrMissingUserInfo` |
| `StatusKeyStoreFull` | `ErrResidentKeyLimitReached`, `ErrCredentialLimitReached` |
| `StatusLimitExceeded` / `StatusUnsupportedAlgorithm` | `ErrLimitExceeded` / `ErrUnsupportedCryptoAlgorithm`, `ErrNoSupportedAlgorithm` |
| `StatusLargeBlobStorageFull` / `StatusInvalidSeq` | `ErrLargeBlobsStorageFull` / `ErrLargeBlobsInvalidSeq` |
| `StatusOtherError` (default) | `ErrStorageClosed`, `ErrStorageError`, and anything not explicitly matched |

## Configuration — `xkey fido2` flags

Defaults are constants at `xkey/cmd/xkey/cmd/fido2.go:164-170`.

| Flag | Default | Meaning |
|---|---|---|
| `--storage` | `memory` | `memory`, `file`, or `barrier` |
| `--storage-path` | `~/.xkey/data/fido2` | path for file storage and the authenticator profile, resolved through the shared xkey data-directory chain (`resolveFIDO2StoragePath`, `fido2.go`; honors `XKEY_HOME`/`XKEY_DATA_DIR`) rather than the process's working directory (go-xkms#929) |
| `--barrier-password-stdin` | `false` | read the barrier password for encrypted storage from standard input |
| `--barrier-password-file` | `""` | read it from a file's first line |
| `--name` | `xKey (go-xkms)` | device name the OS sees |
| `--serial` | `""` | device serial; generated when empty |
| `--pin` | `true` | require a PIN |
| `--set-pin-stdin` | `false` | read the initial PIN to establish from standard input (needs `--pin`; refused if a PIN is already set) |
| `--interactive` | `false` | interactive setup |
| `--require-touch` | `true` | require user presence |
| `--timeout` | `30s` | operation timeout |
| `--backend` | `software` | `software`, `tpm2`, or `phone` |
| `--tpm-device` | `/dev/tpmrm0` | TPM device path |
| `--attestation` | `none` | `none`, `packed`, or `tpm` |
| `--phone-device` | `""` | specific paired phone; default is the default phone |
| `--password-store` | `~/.xkey/data/staticpw` | static password store path — the same store `xkey password` uses (`passwordStoreFeature`, `password.go`); resolved through the shared xkey data-directory chain, never the working directory (go-xkms#929) |
| `--socket` | `$XDG_RUNTIME_DIR/xkey/xkey.sock` | IPC socket |
| `--default-password` | `""` | password name typed on a bare touch |
| `--notify-command` | `""` | custom notification command |
| `--notify` | `dialog` | `dialog`, `passive`, `log`, or `none` |
| `--unified-pin` | `true` | propagate the host PIN service's user PIN to this authenticator's CTAP2 PIN hash on set/change/verify (`authenticator.Config.UnifiedPIN`); not a PKCS#11 or file PIN sync — go-xkms has one governing PIN backend per device, see go-xkms#307 |
| `--cdp` | `false` | Chrome DevTools virtual-authenticator bridge |
| `--cdp-host` | `localhost` | DevTools host |
| `--cdp-port` | `9222` | DevTools debugging port |

**`--storage memory` is the default**, which means credentials do not survive a
restart unless you choose `file` or `barrier`. That is a safe default for a
first run and the wrong one for daily use.

## Invariants

- **The device is a real CTAP2 authenticator**, not an emulation of a specific
  vendor's. `--attestation` reports what it is.
- **User presence is required, and the handler that collects it is named,
  never defaulted.** `NewAuthenticator` returns
  `ErrUserPresenceHandlerRequired` without one. The daemon installs a
  `SocketHandler` (answered by a dialog or `xkey touch`) or, under
  `--interactive`, an `InteractiveHandler`; a programmatic device passes
  `NewAutoGrantHandler()` explicitly at its construction site.
  `--require-touch` defaults true and only ever narrows the request: off, a
  verified PIN stands in for the touch, and a ceremony with no PIN still asks.
- **User verification is performed, never asserted.** The UV flag is set when
  the ceremony carried a verified PIN or the key backend verified a human
  itself; `getInfo` reports `uv=false` where a PIN is the verification method
  so a browser collects it. No flag or setting reports verification the
  authenticator did not do. A backend that verifies inside its own key
  operation never mints a `pinUvAuthToken`: subcommand `0x06` is refused
  (#1145; see
  [`fido2/engineering.md`](../fido2/engineering.md#minting-a-pinuvauthtoken-pin-only-go-xkms1145)).
- **The relying party cannot distinguish backends.** `software`, `tpm2` and
  `phone` present identically over CTAP2, so the strength claim is the
  operator's to make honestly.
- **Credential storage and key material are separate seams.** `BackendStorage`
  holds credential records; `keybackend` holds key material. Do not merge them.
- **Key material never transits the ordinary Go heap through the wrapper.**
  `KeyWrapper` has no method that takes or returns a plaintext slice:
  `WrapFrom(src *secure.Buffer)` reads from protected memory the caller owns
  (#387) and `UnwrapInto(wrapped, dst)` writes into a destination the caller
  sized before any borrow (#291). Protected-buffer borrows must not nest, so a
  wrap of one protected key under another goes through `wrapFromProtected`,
  which releases the key borrow before the plaintext borrow is taken. The
  invariants and the deadlock rule are spelled out in
  [`fido2/engineering.md`](../fido2/engineering.md#key-material-handling-in-memory).
- **`--storage memory` loses credentials on exit.** No warning is emitted; it is
  the documented default.
- **go-qrdb's seal barrier is the only at-rest encryption in this stack; xkey
  adds no per-credential wrap of its own on top of it (#181).** `--storage
  barrier` and the GUI's barrier-backed branch construct `BackendStorage`
  over the barrier's `xkms.StorageBackend`, so credential JSON is encrypted
  by the barrier exactly like every other barrier-routed store. `--storage
  file` and the GUI's pre-`barrier init` fallback construct the same
  `BackendStorage` over a plain file backend instead — a `0600` file with no
  encryption of its own, which is a legitimate configuration, not a bug.
  Both plain-file construction sites (`createFIDO2Storage`'s
  `FIDO2StorageTypeFile` case in `xkey/cmd/xkey/cmd/fido2.go`, and the
  no-barrier branch of `initializeDataDir` in `xkey/pkg/gui/app.go`) log one
  `slog.Warn` naming the exposure and pointing at `xkey barrier init` every
  time the store is opened — never a refusal, never a silent fallback.
  `--storage memory` never touches disk and is exempt. `BackendStorage`
  itself (`storage_backend.go`) carries no logger and emits no warning of its
  own; the warning is deliberately at the two call sites that know whether a
  barrier is present, not inside the shared storage type. `xkey fido2
  status`'s `EncryptedAtRest` field (`fido2_status.go`) reports this
  per-store: `true` for `barrier`, `false` for `file` and `memory`.
- **CTAP2 is one command at a time per channel, and the authenticator itself
  now enforces it, not just the transport.** `Authenticator.cmdMu`
  (`authenticator.go`) is held for the whole of `ProcessCBORWithContext` —
  including any user-presence wait the command performs — so a second command
  cannot begin until the first has fully returned. This closes a TOCTOU gap
  (#323): `AuthorizePinUvAuthToken`'s check (`checkPinUvAuthTokenLocked`) and
  its spend (`consumePinUvAuthToken`, `cmd_clientpin.go`) are two separate
  acquisitions of `mu` with a possible user-presence prompt in between, so two
  concurrent commands presenting the same `pinUvAuthToken` could previously
  both pass authorization before either consumed it — a race the detector
  cannot see, because every individual access to the token state is correctly
  synchronized under `mu`; the flaw was that the check and the use were two
  critical sections instead of one. `cmdMu` closes the window by construction
  instead of narrowing it, which also makes the `cmdCtx.Store`/`defer
  Store(nil)` single-command assumption true. The accepted trade: a command
  blocked on user presence blocks every other queued command for the whole
  wait, not just its own critical section — matching how a real CTAP
  authenticator behaves, since it never processes a second command while
  waiting on the first's touch. Every `requestUserPresence` call site releases
  `mu` before it blocks, so `cmdMu` is the only lock held across the wait — see
  `ProcessCBORWithContext`'s doc comment. The HID adapter's own per-channel
  serialization above `cmdMu` is unaffected and still applies.
- **PIN state is `state.PINHash` with a fixed size** — treat it as the
  authenticator's own credential, distinct from the barrier or the OS.
- **A first PIN has one establishment path.** The CTAP `setPIN` subcommand
  (after its wire-level `pinUvAuthParam` proof) and the in-process
  `Authenticator.SetInitialPIN` (the `--set-pin-stdin` seeding) both end in
  `establishPINLocked` (`cmd_clientpin.go`): minimum length, retry-counter
  reset, outstanding `pinUvAuthToken` invalidation, then persistence. Neither
  replaces an existing PIN — `SetInitialPIN` refuses with `ErrPINAlreadySet`,
  and the daemon surfaces that as `ErrFIDO2PINAlreadySet` — so a restart with
  `--set-pin-stdin` against a persistent store cannot silently rewrite the PIN or
  reset its retry counter. There is no testing-only PIN setter (#377).
- **A first SO PIN has one establishment path too.** The CTAP
  `authenticatorConfig` vendor subcommand `setSOPIN` and the in-process
  `Authenticator.InitializeToken` (which `xkey fido2 init-token` calls) are the
  same method: `handleVendorSetSOPIN` passes straight through to it. It refuses
  an initialized token with `ErrKeyManagerAlreadyInitialized` under the state
  lock, so establishment never replaces. `Authenticator.ChangeSOPIN`
  (`xkey fido2 change-so-pin`, vendor `changeSOPIN`) is the only successor path
  and proves the current PIN by authenticated decryption of the wrapped Admin
  Key, spending a persisted retry on failure. `authenticatorReset` is the only
  way back to uninitialized (#233).
- **`state.SOPINManager.IsSet` is the single source of truth for "initialized".**
  Initialization *is* establishing the SO PIN; a second boolean would only be a
  second thing to disagree. `Authenticator.TokenFlags` derives the PKCS#11
  `CKF_TOKEN_INITIALIZED` / `CKF_SO_PIN_*` view from it, and renders an
  uninitialized token as `uninitialized` rather than as an empty flag set — "no
  flags" and "no Security Officer required" must never read alike.
- **The SO PIN is never stored in the device's own password store.** That store
  is unlocked by the user PIN, and the SO PIN's job is to reset a forgotten user
  PIN; keeping one inside the other makes the recovery credential recoverable
  only by the credential it recovers (#290). It is entered at the prompt and
  held nowhere else.
- **CTAP 2.1 §6.9's bounds on first initialization are real over a transport and
  vacuous on the offline CLI path.** `poweredUpAt` is set in
  `NewAuthenticator`, so a command that constructs the authenticator opens the
  window itself, and the presence prompt asks the operator who just typed the
  PIN. `xkey fido2 init-token` therefore names the control that does apply —
  file permissions on the state directory — instead of reporting a bound that
  cannot fire. Its presence handler is still explicit and interactive, never an
  auto-grant, so a denial refuses.

## Error semantics

`pkg/fido2/authenticator/errors.go` and `pkg/fido2/uhid/errors.go`. CTAP2 status
codes are returned to the consumer, so failures surface as `CTAP2_ERR_*` in a
browser's console rather than as Go errors.

**Fail closed:** no user presence within `--timeout`, wrong PIN, PIN retries
exhausted, an unavailable backend (TPM absent, phone unpaired), or a credential
not present. None of them fall back to a weaker path — in particular, a `tpm2`
backend that cannot reach its TPM does not silently become `software`.

## Persistence

- **`memory`** — nothing survives the process. `storage_memory.go`.
- **`file`** — under `--storage-path` (default `~/.xkey/data/fido2`,
  resolved through the shared xkey data-directory chain, go-xkms#929).
  `BackendStorage` over a plain `xkms.StorageBackend`; plaintext at rest
  (see the at-rest invariant above).
- **`barrier`** — the same `BackendStorage` over the barrier's
  `xkms.StorageBackend` instead; encrypted, keyed by the barrier password.

Credential records go through `storage_backend.go`'s `BackendStorage`; key
material through `keybackend` to software, TPM or phone. RP policies are
`dao_rp_policy_store.go`.

`migration.go` handles moving between earlier PIN-state layouts —
`xkey/pkg/gui/migration.go` documents the historical paths
(`<dataDir>/pin-state.json` for the CLI path, `<dataDir>/tpm/pin_state.json`
for the GUI/TPM path) and the deprecated `FilePINManager` they came from.

## Test strategy

- **Unit** — per-command suites in `pkg/fido2/authenticator`, plus PIN protocol,
  extensions, key wrapping, `BackendStorage`, and the RP policy DAO store.
- **UHID** — `pkg/fido2/uhid` serialization and device tests; the stub build is
  compiled on non-Linux.
- **Browser end to end** — Playwright specs against the CDP bridge, and
  `go-xkms/test/integration/webauthn-browser`.
- **Cross-module** — `go-xkms/test/integration/logins` drives xkey against a
  real relying party.

## Observability

`--notify` selects how the user-presence prompt reaches a human: `dialog`
(interactive), `passive` (desktop notification), `log`, or `none`.
**`--notify none` combined with `--require-touch true` produces an
authenticator that waits silently for a touch nobody was asked for** — the
symptom is a browser that hangs until the timeout. `--notify-command` overrides
with a custom command.
