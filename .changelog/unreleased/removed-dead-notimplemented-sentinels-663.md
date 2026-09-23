- **Deleted two unreferenced `ErrNotImplemented` sentinels — BREAKING.**
  `frost.ErrNotImplemented` (`pkg/keyprovider/frost/errors.go`) and
  `escrow.ErrNotImplemented` (`pkg/escrow/errors.go`) had zero production
  call sites; the frost sentinel is superseded by the new
  `frost.ErrThresholdSigningNotSupported` (see the FROST signer entry
  above). Test doubles that referenced `frost.ErrNotImplemented` now use a
  package-local `errMockUnimplemented` in
  `pkg/keyprovider/frost/config_test.go`. Fixes go-xkms#663.
