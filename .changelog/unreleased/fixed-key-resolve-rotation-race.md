- **A key operation racing a rotation no longer fails with
  `KeyVersionMissingError`.** Resolving a key lists the backend's keys and then
  reads the version record; a rotation landing between the two left the
  record's new current version unlisted, so an encrypt, sign or other use
  concurrent with `RotateKey` could fail with `version N of key ... has no
  backend key`. A rotation creates the backend key before it records the
  version, so resolution now lists again when the record's current version is
  missing. Code: `pkg/xkms/key_versions.go` (`resolveKeyOf`).
