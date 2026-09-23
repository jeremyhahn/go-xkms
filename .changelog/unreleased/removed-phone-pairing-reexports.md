- **`xkey/pkg/phone`'s `pkg/pairing` re-export shim is gone — BREAKING for
  any external importer of the `phone.X` aliases.** `pairing_reexports.go`
  (roughly 415 type, var, const and function aliases forwarding
  `pkg/pairing`'s wire protocol under the `phone` package name) and the
  `type Transport = pairing.Transport` alias in `transport.go` are deleted
  outright (owner rule 2026-09-22: no backward compatibility). Every
  in-tree caller that referenced a forwarded symbol as `phone.X` now
  imports `xkey/pkg/pairing` and references `pairing.X` directly; symbols
  the `phone` package genuinely owns (`PhoneKeyBackend`, `BLETransport`,
  `USBTransport`, `TCPPairingServer`, `ScanResult`,
  `BLECapableTransport`, `PeripheralRequestHandler`, and its own sentinel
  errors) are unaffected and stay `phone.X`. `handshake_fingerprint_binding_test.go`,
  which existed solely to pin the deleted re-export surface for #82, is
  deleted with it — the regression it guarded against (a re-export that
  silently stops forwarding) cannot recur once there is no re-export layer.
  Rewritten: ~63 files across `xkey/cmd/xkey/cmd`, `xkey/pkg/gui/services`,
  `xkey/test/integration/{ble,phone}`, and the root module's
  `pkg/backend/phone`, `pkg/api/transport/usb`, `pkg/server`,
  `cmd/xkmsctl`; plus ~25 files inside `xkey/pkg/phone` itself that used
  the aliases unqualified. A consumer outside this repository that still
  imports `phone.NoiseSession`, `phone.Request`, `phone.HandshakeConfig`,
  `phone.MethodPing`, or any of the other forwarded protocol types must
  switch to `xkey/pkg/pairing` directly; there is no compatibility path.
