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
