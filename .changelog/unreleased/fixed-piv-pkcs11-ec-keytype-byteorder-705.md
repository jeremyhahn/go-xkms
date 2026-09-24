- **`pivcert/pkcs11`'s PIV slot model reported every EC or Ed25519 key as
  `"Unknown"` instead of its real algorithm.** `decodeCKKeyType` decoded
  the `CKA_KEY_TYPE` attribute as big-endian, but PKCS#11 returns `CK_ULONG`
  attributes as the platform's raw little-endian bytes (see the identical,
  correct `ckULong` helper in `pkg/backend/pkcs11`). `CKK_RSA` is `0`, so
  the bug was invisible for RSA keys regardless of byte order; any non-zero
  key type (`CKK_EC`, the Ed25519 vendor type) reassembled to the wrong
  number and fell through `keyTypeString`'s type switch to `"Unknown"`,
  which `pivctl`/the SDK's slot-occupancy view then showed for every EC or
  Ed25519 PIV slot on a real token. Fixed to decode little-endian, matching
  `pkg/backend/pkcs11`'s `ckULong`. A SoftHSM-backed regression test
  (`TestPIVSlotModel_SlotOccupancy_ECKey`) asserts an EC P-256 PIV slot
  reports `"ECDSA P-256"`, and `TestDecodeCKKeyType`'s fixtures now use
  little-endian byte patterns instead of the big-endian ones that had
  masked the bug (go-xkms#705).
