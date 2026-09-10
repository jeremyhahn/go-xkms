- **transport: `BeginAuthenticationRequest.Username` and `FinishAuthenticationRequest.Username` are now `Email` (#518).**
  Both carried the canonical email login key under a name that said
  otherwise, the same defect the registration request had. The Go fields,
  the gRPC/Unix proto fields (numbers unchanged, binary-compatible) and the
  REST/QUIC JSON keys are now `email`. For one release the JSON decoders
  still accept the legacy `username` key and the Go client sends both keys
  with the same value; a body carrying both keys with different values is
  refused with `transport.ErrAuthenticationLoginKeyConflict`. The three
  ceremony requests resolve their login key through one shared decoder
  path. The legacy key is removed in the following release.
