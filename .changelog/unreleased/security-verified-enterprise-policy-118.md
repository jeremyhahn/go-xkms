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
