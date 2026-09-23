- **BREAKING: `pkg/backend/phone`'s attestation platform no longer defaults
  to `"android"` — it must be set explicitly.** `Config.Validate()`
  (`pkg/backend/phone/config.go`) previously defaulted an empty
  `AttestationConfig.Platform` to `DefaultPlatform` ("android") "for
  backward compatibility"; it now returns the new typed
  `ErrMissingAttestationPlatform` instead. The `DefaultPlatform` constant is
  deleted. A caller that configures `Config.Attestation` (attestation
  verification is opt-in — a nil `Attestation` still skips verification
  entirely, unchanged) must now name `Platform` explicitly ("android" or,
  in future, "ios").