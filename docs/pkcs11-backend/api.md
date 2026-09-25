# PKCS#11 Backend — API

> **Status: NORMATIVE** · Feature: `pkcs11-backend` · Repo: `go-xkms` · Last verified: 2026-09-24

This backend adds **no new routes, RPCs, or MCP methods**. It is reached
through the generic key-management API documented in
[`../key-management/api.md`](../key-management/api.md) — read that file
first, especially §"How the six transports are shaped" and the capability
matrix. This page covers only what is specific to selecting and using
`pkcs11` as the backend.

## Selecting the backend

Backend selection is a request field, not a route:

- Requests that carry a JSON body naming the operation (e.g.
  `POST /api/v1/keys` to generate) include a `"backend"` field directly in
  that body — `GenerateKeyRequest.Backend` (`pkg/api/transport/types.go:70`,
  `json:"backend"`).
- Requests without a meaningful body, or where the body is pure payload
  (list, get, delete, sign, verify, rotate, encrypt/decrypt, export), take
  `?backend=` as a REST query parameter
  (`pkg/api/rest/handlers_key.go:429,492,564,670,725,978,984,1026,1069,1097`
  read `r.URL.Query().Get("backend")`). gRPC/QUIC/MCP carry the equivalent
  `Backend` field on their own request messages.

```bash
curl -X POST https://kms.example.com:8443/api/v1/keys \
  -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"key_id":"demo","backend":"pkcs11","key_type":"signing","algorithm":"ecdsa","curve":"P-256"}'

curl https://kms.example.com:8443/api/v1/keys?backend=pkcs11 \
  -H 'Authorization: Bearer <token>'

curl -X POST https://kms.example.com:8443/api/v1/keys/demo/sign?backend=pkcs11 \
  -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"digest":"<base64>"}'
```

An empty/omitted backend on any of these routes uses the daemon's default
backend (`software` unless configured otherwise) — it never implicitly
means `pkcs11`, even when `pkcs11` is the only hardware backend enabled.

## Availability

`GET /api/v1/backends` / `GET /api/v1/backends/{id}` (see
`../key-management/api.md`'s capability matrix) report whether `pkcs11` is
present. It is present only when `xkmsd` was built with `-tags pkcs11`
**and** `backends.pkcs11.enabled: true` succeeded at startup — see
[`engineering.md`](engineering.md). A request naming `backend=pkcs11` when
it is absent gets the generic "backend not registered" error
(`../key-management/api.md`'s error-mapping table:
`ErrInvalidBackend`/404-class, depending on transport), not a
PKCS#11-specific one.

## Errors specific to this backend

The generic status/error mapping in `../key-management/api.md` applies. The
typed errors this backend can surface underneath a generic "backend
failure" (`500`/`Internal`) include the ones listed in
[`engineering.md`](engineering.md) §"Errors" — most visibly
`backend.ErrKeyNotExportable` (export attempted on a
non-extractable/non-exportable key) and
`backend.ErrAsymmetricKeyExportNotAllowed` (`ExportKeyMaterial` on
anything but a `CKO_SECRET_KEY`).

## Not reachable over any network transport

`Initialize(soPIN, userPIN)` (first-time token setup) and direct
`WithSOSession` operations are not exposed as API calls at all — token
provisioning is operator/vendor-tooling work, done once before `xkmsd`
starts, never a request a caller can make against a running daemon. See
[`cli.md`](cli.md) for the out-of-band provisioning steps.
