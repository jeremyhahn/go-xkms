- **BREAKING: `pkg/ssh/known_hosts` no longer trusts or creates fingerprint-only
  (v1) host-key pins — every pin now carries, and is matched against, the full
  SSH wire-format public key.** `Store.Add` rejects a `*Pin` with no
  `PublicKey` with the new `*PublicKeyRequiredError`, so a fingerprint-only
  pin can no longer be created. `Verify` no longer compares
  `keys.Fingerprint(received)` against `Pin.Fingerprint`; it compares
  `received.Marshal()` against `Pin.PublicKey` byte-for-byte (the fingerprint
  fields are still populated and still appear in `*MismatchError` for safe
  logging, but they are no longer what decides trust). `decodeEnvelope`
  (`pkg/ssh/known_hosts/store.go`) now returns the new `*LegacyPinError` for
  any stored envelope that predates envelope v2 (no `pub` field) instead of
  silently reconstructing a `Pin` with an empty `PublicKey` — `Get` and
  `Verify` (single-host lookups) fail closed with it, telling the caller the
  host must be re-pinned (`Store.Remove` then `Store.Add` with a current
  `PinFromPublicKey`). `Store.List` skips a legacy pin rather than aborting
  the whole scan, so one host needing re-pinning does not hide every other
  pin in scope from discovery/export tooling. Every transport that creates a
  pin now requires the full key too: `sdk/go/client/ssh.AddKnownHostRequest`
  and `Pin` both gained a required `PublicKey` field (embedded transport
  returns the new `*MissingPublicKeyError` / `*InvalidPublicKeyError` when
  it's missing or unparsable); `xkmsctl ssh known-hosts add` dropped its
  `--fingerprint`/`--algorithm` flags for `--key`/`--file`, which supply an
  `authorized_keys`-format line; and the gRPC `SSHAddKnownHostRequest` /
  `SSHPin` messages gained a `public_key` field so the gRPC transport can
  carry it end to end (regenerated via `make proto`). `xkey ssh host-keys add`
  dropped the same `--fingerprint`/`--algorithm` flags for `--key`/`--file`,
  mirroring xkmsctl; xkey's own TOFU accept path (`pkg/ssh/console`, already
  present in the root module) already pinned the full key it had in hand and
  needed no change, and a repo-wide grep found no other xkey producer of a
  known-hosts pin (GUI services, pairing, and `pkg/sshstore` never construct
  one — they only route an already-full-key `*Pin` through the store).