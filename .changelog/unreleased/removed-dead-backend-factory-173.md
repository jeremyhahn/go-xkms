- **The uncalled backend factory is gone (#173).**
  `pkg/server/backend_factory.go`'s `Initialize`, its `BackendConfig` /
  `BackendFactoryConfig` types, `createBackend` and the seven
  `backend_factory_<backend>.go` constructors (with their `_stub.go`
  siblings) had no production caller: the live path is `server.go`'s
  `initializeBackends` calling `initXBackend` in `backend_<backend>.go`.
  The dead factory modelled backends with operator-supplied names and a
  randomized default that the live server never had, and three readers
  reasoned from it to wrong conclusions in one review. Its tests go with
  it; the two live storage helpers it housed, `createStorage` and
  `createStorageAt`, move to `storage_factory.go`, and the docs now point
  at the real construction path.
