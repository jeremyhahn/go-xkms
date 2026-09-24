- **Every non-GUI production FIDO2 authenticator now writes to an audit
  log; previously only the GUI did.** `Authenticator.SetAuditLogger` (#766)
  landed with exactly one caller — the xKey GUI's `PostBarrierUnseal` path
  (#803) — so the `xkey fido2` virtual USB device daemon and the headless
  browser-extension daemon (`xkey extension serve`) created FIDO2 credentials
  and seeded user PINs with no `OpFIDO2CredentialCreated`/`OpPINSeeded`
  record and no write-failure refusal (#688), even though both are
  full production entry points a user runs directly. `xkey/cmd/xkey/cmd/fido2.go`
  (`newFIDO2Device`) now wires `audit.NewSlogLogger`, the same slog-backed
  logger already used for `AutoFillService` in `extension_serve.go`, into
  every authenticator it constructs; `extension_serve.go`
  (`runExtensionServe`) now wires that same logger instance into the
  headless daemon's authenticator instead of leaving it unaudited. Both
  daemons now refuse to establish a PIN or create a credential when the
  audit write fails, matching the GUI and the authenticator package's own
  write-failure policy. The offline token/attestation operator verbs
  (`fido2 init-token`, `fido2 change-so-pin`, `fido2 provision-attestation`)
  do not create credentials or seed the CTAP2 user PIN, so they are
  unaffected. go-xkms#804.
