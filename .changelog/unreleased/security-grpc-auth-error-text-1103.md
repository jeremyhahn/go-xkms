- **The gRPC transport no longer echoes internal error text to an
  unauthenticated or unauthorized caller.** `pkg/api/grpc/server.go`'s
  `authenticationUnaryInterceptor` and `authenticationStreamInterceptor`
  formatted `codes.Unauthenticated` with `"authentication failed: %v"`
  against the raw error `auth.Authenticator.AuthenticateGRPC` returned, so a
  user-store failure, a barrier failure, or the specific reason a
  certificate was rejected reached the client response. `pkg/api/grpc/service.go`'s
  `Service.authorize` — the single gate behind all 150+ RPC handlers — had
  the same defect on both its `codes.Unauthenticated` and
  `codes.PermissionDenied` paths, echoing the qrdb-backed authorizer's error
  text verbatim (`TestAuthz_AuthorizeDenied` asserted on the literal denial
  string, confirming the leak). Both interceptors now return the fixed
  `errAuthenticationFailed` ("authentication failed") message and log the
  cause server-side via the existing `s.logger.Warn`, already in place but
  previously logged in addition to, not instead of, leaking the same text to
  the client. `authorize` now returns the fixed `ErrAuthenticationRequired`
  ("grpc: authentication required") or `ErrAccessDenied`
  ("grpc: access denied") message and records the real reason in the audit
  event's `Details["reason"]`, so the cause stays in the audit trail rather
  than the client response — matching `pkg/api/rest/middleware.go`'s
  `AuthenticationMiddleware` and `pkg/api/rest/rbac_middleware.go`'s
  `RBACMiddleware`, which already followed this pattern. The QUIC transport
  serves the same `AuthenticationMiddleware` over HTTP/3 (`pkg/server/server.go`),
  so it was already unaffected; the ACME admin gRPC plane
  (`pkg/acme/api/server/interceptor_authz.go`) was already generic. Files:
  `pkg/api/grpc/{server,service,errors}.go`. Verified by new tests
  `TestAuthenticationUnaryInterceptor`/`TestAuthenticationStreamInterceptor`'s
  "does not leak internal error text to the client" subtests (a marker
  string in the authenticator's error is asserted absent from the gRPC
  status message and present in a captured `slog` logger), and updated
  `TestAuthz_AuthorizeDenied`/`TestAuthz_AuthorizeUnauthenticated`/
  `TestAuthz_GenerateKeyDenied`, which now assert the fixed message and that
  the denial reason lands in the audit event instead. go-xkms#1103.
