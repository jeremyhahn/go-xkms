# RFC 8555 compliance map

> **Status: REFERENCE** · Feature: `acme-issuance` · Repo: `go-xkms` · Last verified: 2026-10-12

Where each RFC 8555 section ([rfc-8555.txt](rfc-8555.txt)) is implemented and
which conformance test exercises it. This is a map, not a certificate: it
records file locations, not pass counts or coverage figures, which drift on
every commit. The wire contract itself is
[acme-issuance/api.md](../acme-issuance/api.md).

| Section | Topic | Implementation | Conformance test |
|---|---|---|---|
| 6.2 | Request authentication (JWS, `jwk` xor `kid`) | `parseSignedRequest` and `parseJWS` (`pkg/acme/server/handlers/service.go:1133`, `:1257`); both `kid` and `jwk` rejected (`ErrKIDAndJWKNotAllowed`, `service.go:60`) | `test/integration/rfc8555/rfc8555_6_2_test.go` |
| 6.4 | Request URL integrity | `requestURL` (`service.go:1120`); mismatch rejected with `ErrJWSURLMismatch` (`service.go:87`) | `rfc8555_6_4_test.go` |
| 6.5 | Replay protection (nonces) | `mintNonce` / `redeemNonce` (`service.go:901`, `:909`); `pkg/acme/server/handlers/new_nonce.go` | `rfc8555_6_5_test.go`, `rfc8555_7_2_test.go` |
| 6.7 | Errors (problem documents) | error-type → ACME problem-type table `acmeTypeMap` (`pkg/acme/errors/acme.go:48`) | `rfc8555_6_7_test.go` |
| 7.1 | Directory and resources | `pkg/acme/server/handlers/directory.go` | `rfc8555_7_1_test.go` |
| 7.3 | Accounts (create, `onlyReturnExisting`, update, deactivate, EAB) | `new_account.go`, `account.go`, `external_account_binding.go` | `rfc8555_7_3_test.go` |
| 7.3.5 | Account key rollover | `key_change.go` | `pkg/acme/server/handlers/key_change_test.go` |
| 7.4 | Orders, finalize, certificate download | `new_order.go`, `handler_order.go`, `orders_list.go`, `order_finalize.go`, `certificate.go` | `rfc8555_7_4_test.go`, `order_finalize_test.go` |
| 7.5 | Authorizations and challenges | `authorization.go`, `challenge.go`; challenge validators under `pkg/acme/challenges/` | `rfc8555_7_5_test.go`, `challenge_test.go` |
| 7.6 | Revocation | `revoke_cert.go` | `rfc8555_7_6_test.go` |
| 8.1 | Key authorizations | `KeyAuthorization`, `JWKThumbprint` (`service.go`) | `rfc8555_8_1_test.go` |

Handler files are in `pkg/acme/server/handlers/`; conformance tests are in
`test/integration/rfc8555/` and run under `make integration-test`.

Several `rfc8555_*` tests exercise entities and helpers (`pkg/acme/entities`,
the handler helpers) rather than a running server. Full request/response
flows are covered by the handler unit tests beside each file above.

The problem-type table maps several internal error types onto
`serverInternal` (for example duplicate, conflict, unknown serial,
storage failure) and adds the non-RFC types `invalidProfile` and
`badAttestationStatement` (`pkg/acme/errors/acme.go:49-99`). The server does
not emit `autoRenewalCanceled`; that constant exists only on the client side
(`pkg/acme/client/errors.go:104`).
