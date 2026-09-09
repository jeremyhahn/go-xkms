- **`tofu` verifies an endpoint on the TLS path (#139).** The strategy was
  implemented purely as a CA-bundle fetch, so it could not verify the one
  thing it is most natural for: first contact with a device that presents a
  self-signed certificate and serves no bundle, such as a BMC.
  `bootstrap.NewTOFUTLSConfig(ctx, pinStore, "host:port", confirm)` is the
  endpoint verifier, mirroring `NewSPKIPinTLSConfig` and `NewDANETLSConfig`:
  the first connection captures the leaf's SPKI pin, offers it to the
  confirm hook, and persists it; every later connection must present it,
  session tickets are disabled so resumption cannot bypass the check, and a
  pin store that fails for any reason other than "no pin" is an error, never
  a fresh capture. The pin record is the one truststrap's bundle-fetching
  TOFU bootstrapper writes, so both paths share a store. The resolver's TLS
  dispatch for `tofu` now uses it, with the endpoint (or the scope's
  server-url) as the key, while the PEM path keeps fetching a bundle: the
  same split `dane` and `spki` already have. Re-exported through
  `sdk/go/bootstrap` with typed errors `TOFUEndpointError`,
  `TOFUPinStoreError`, `TOFUPinMismatchError` and `ErrTOFUPinStoreRequired`.
