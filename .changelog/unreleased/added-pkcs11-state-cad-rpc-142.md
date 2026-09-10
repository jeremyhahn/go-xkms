- **The PKCS#11 remote state plane gains a guarded delete (#142).**
  `PKCS11StateCAD` removes a token-state record only if it still holds the
  value the caller observed, with the guard evaluated by xkmsd on its own
  store, where the writes of every host sharing one server-side token
  serialise. It is the release half of `PKCS11StatePutIfAbsent`'s guarded
  create. Wired end to end: transport DTOs `PKCS11StateCADRequest` /
  `PKCS11StateCADResponse`, the gRPC RPC (`keys:write`), the REST and QUIC
  route `POST /api/v1/pkcs11state/compare-and-delete` (keys resource,
  `delete` action), the gRPC, Unix, REST and QUIC client transports,
  `XKMSService.PKCS11StateCAD`, and `pkcs11state.Store.CompareAndDelete`,
  which refuses with `ErrCompareAndDeleteUnsupported` rather than emulating
  the guard on a backend that lacks it. The module's remote storage backend
  now implements `storage.CompareAndDeleter` over the RPC and is held to the
  shared conformance suite; its `PKCS11StateClient` contract gains the method,
  so a transport that does not carry it fails the build. An absent key or a
  different value answers `deleted=false` without an error; a nil `expected`
  is never a wildcard, matching a stored empty value only.
