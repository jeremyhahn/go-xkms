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
