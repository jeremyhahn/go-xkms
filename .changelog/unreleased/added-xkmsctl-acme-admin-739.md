- **`xkmsctl acme` administers the ACME certificate authority: accounts,
  issued certificates, EAB, and CA status/stats.** Brings `xkmsctl` to
  parity with go-trusted-ca's retired `cactl` for `account list/get/disable`
  and `cert list/get/revoke`, and adds `eab create/get/delete/list` — scoped
  to a tenant, since go-xkms's ACME server is multi-tenant where
  go-trusted-ca's never was — plus `status`/`stats`. Every verb goes through
  the existing ACME admin SDK (`sdk/go/acme`, `sdk/go/acme/client/admin`),
  never `pkg/acme/*` directly, connecting to the ACME server's own HTTPS
  listener via the new `--acme-server`/`--acme-transport` flags (distinct
  from xkmsd's own `--server`/`--transport`, since the two services listen
  on different addresses). A permission denial from `pkg/acme/admin`'s
  `PermissionGate` surfaces as a typed `ACMEAdminForbiddenError` and a
  missing resource as `ACMEAdminNotFoundError`, both distinguishable from
  the generic per-verb failure sentinel via `errors.As`. Fixed a gap in the
  SDK's embedded transport along the way:
  `sdk/go/acme/transport/embedded`'s error parser only recognized RFC 8555
  ACME URN error types, so every admin-domain problem response (which uses
  its own `urn:trusted-ca:error:*` types) silently collapsed to
  `CodeUnknown`, losing the 403/404 distinction the REST transport already
  preserved via its HTTP-status fallback; the embedded transport now falls
  back the same way, so admin clients get identical typed errors over both
  transports. New `*_run_test.go` per verb group drives the real SDK
  embedded transport end to end (real serialization, response mapping, and
  error classification) against a map-dispatched test double of the SDK's
  `embedded.AdminServicer` interface, covering success, not-found, and
  permission-denied for every verb. Documented in
  `docs/acme-issuance/cli.md`. go-xkms#739.
