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
