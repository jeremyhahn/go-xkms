- **transport: `BeginRegistrationRequest.Username` is now `Email` (#192).**
  The field carried the canonical email login key under a name that said
  otherwise, and a caller that read the name literally enrolled a credential
  against the wrong account. The Go field, the gRPC/Unix proto field
  (field 1, binary-compatible) and the REST/QUIC JSON key are now `email`.
  For one release the JSON decoder still accepts the legacy `username` key
  and the Go client sends both keys with the same value, so old clients
  and old servers both keep working across a rolling upgrade; a body
  carrying both keys with different values is refused with
  `transport.ErrRegistrationLoginKeyConflict` instead of a silently chosen
  value. The Go SDK re-export follows the rename; the TypeScript SDK never
  exposed this request. The legacy key is removed in the following release.
