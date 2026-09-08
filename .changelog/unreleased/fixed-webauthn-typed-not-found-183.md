- **The WebAuthn user store no longer decides "no such user" by substring
  (#183).** `isUserNotFound` matched any error whose text contained
  "not found", "ErrCodeNotFound" or "no rows", so a transport failure such
  as "connection not found" or "tenant not found" was reported as
  `ErrUserNotFound`: the registration ceremony then created a duplicate
  account, and a consumer's rollback guard could delete a credential it did
  not create. Classification is now typed, per go-qrdb#286's measured
  contract: `*transport.UserNotFoundError` (REST),
  `*transport.KeyNotFoundError` (gRPC, MCP, embedded) and the embedded DAO
  not-found are absences; QUIC's opaque `*transport.RequestError` is
  recognised only when its message is, by exact prefix, one of the user
  service's own canonical forms. Everything else is an error. The credential
  store was already typed; the two classifiers now agree.
