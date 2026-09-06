- **`/api/v1/auth/me` returns the canonical email login key.** Since #190 made
  email the tenant-unique key the stack resolves accounts by, a client asking
  "who am I" got back a username it cannot re-authenticate with — a UI
  pre-filling a WebAuthn re-auth prompt had to display one identifier while the
  ceremony required another. `authMeResponse`
  (`pkg/api/rest/handlers_auth.go`) and the TypeScript `AuthMeResponse`
  (`sdk/ts/src/types/auth.ts`) now carry `email`, fed from
  `Identity.Metadata["email"]`. Every path that establishes an identity
  populates it alongside `username`: the qrdb-backed mTLS user projection
  (`pkg/auth/mtls.go`, `pkg/auth/qrdb_userstore.go`), the PIV certificate
  login, the WebAuthn token adapter (`pkg/api/rest/host.go`) and JWT generator
  (`pkg/webauthn/jwt_generator.go`), and the JWT authenticator's claim
  extraction (`pkg/auth/jwt.go`). The token issuer
  (`pkg/auth/token/issuer.go`) mints and re-reads an `email` claim on both
  halves of a pair — through one shared claim builder rather than two copies of
  the same block — so the key survives a refresh. OIDC already mapped the
  standard `email` claim and needed no change. An absent email stays absent: a
  principal with none (a service or bootstrap account bound only by
  certificate) yields no field rather than a value fabricated from the
  username. Verified by `make test-rest` (1046 passing), `./pkg/auth/...`,
  `./pkg/webauthn/...` and the TypeScript SDK suite; documented in
  `docs/webauthn/api.md`. (#194)
