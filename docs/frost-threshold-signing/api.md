# FROST Threshold Signing — API

> **Status: NORMATIVE** · Feature: `frost-threshold-signing` · Repo: `go-xkms` · Last verified: 2026-09-25

Transport model: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped". **Read
[`architecture.md`](architecture.md) §"Two independent surfaces" first**: every
endpoint below requires the daemon to have a backend registered whose
`Type()` is `types.BackendTypeFrost`, and nothing in `xkmsd`'s standard
configuration path (`pkg/config`, `pkg/server`) can produce one today. All
handlers are real and fully implemented; what is missing is the daemon-side
wiring to reach them, not the handlers themselves.

All three surfaces below require `-tags frost`; without it, REST returns
`501 Not Implemented` with `"FROST support not compiled - rebuild with
'-tags frost'"`, and the gRPC/MCP stub methods return the equivalent typed
error (`pkg/api/rest/handlers_frost_stub.go`,
`pkg/api/grpc/service_frost_stub.go`, `pkg/api/mcp/handlers_frost_stub.go`).

## Capability matrix

| Capability | REST | gRPC | MCP | Embedded (`sdk/go` type re-export) |
|---|---|---|---|---|
| Generate key | `POST /api/v1/frost/keys` | `FrostGenerateKey` | `frost.generateKey` | `frost.NewBackend(...).GenerateKey` |
| Import key package | `POST /api/v1/frost/keys/import` | `FrostImportKey` | `frost.importKey` | — (no importer type is re-exported; use `frost.NewKeyStore(...).StoreKeyPackage`) |
| List keys | `GET /api/v1/frost/keys` | `FrostListKeys` | `frost.listKeys` | `(*FrostBackend).ListKeys` |
| Get key | `GET /api/v1/frost/keys/{id}` | `FrostGetKey` | `frost.getKey` | `(*FrostBackend).GetKey` |
| Delete key | `DELETE /api/v1/frost/keys/{id}` | `FrostDeleteKey` | `frost.deleteKey` | `(*FrostBackend).DeleteKey` |
| Round 1 (nonces) | `POST /api/v1/frost/keys/{id}/nonces` | `FrostGenerateNonces` | `frost.generateNonces` | `(*FrostBackend).GenerateNonces` |
| Round 2 (sign) | `POST /api/v1/frost/keys/{id}/sign` | `FrostSignRound` | `frost.signRound` | `(*FrostBackend).SignRound` |
| Aggregate | `POST /api/v1/frost/aggregate` | `FrostAggregate` | `frost.aggregate` | `(*FrostBackend).Aggregate` |
| Verify | `POST /api/v1/frost/verify` | `FrostVerify` | `frost.verify` | `(*FrostBackend).Verify` |

**There is no remote/HTTP client wrapper for any of these in `sdk/go/`** — the
"Embedded" column above is the only way `sdk/go/frost.go` reaches FROST; it
is a type-alias re-export of the in-process library
(`pkg/keyprovider/frost`), not a REST/gRPC caller. A Go program that wants to
call the endpoints below over the network constructs its own HTTP/gRPC/MCP
client against the wire types documented here.

Permission: every REST route uses `auth.ResourceKeys` with the action that
matches its verb (`create`/`import`/`list`/`get`/`delete`/`sign`/`verify` —
`pkg/api/rest/routes.go:164-172`), the same resource as every other key
operation — there is no FROST-specific permission.

## REST (`pkg/api/rest/handlers_frost.go`)

Base path: `/api/v1/frost` (the generic `perm(...)` route helper prefixes
`/api/v1`, unlike SSH's `/xkms/v1/ssh` — see `pkg/api/rest/routes.go:104-172`).

| Method | Path |
|---|---|
| `POST` | `/frost/keys` |
| `POST` | `/frost/keys/import` |
| `GET` | `/frost/keys` |
| `GET` | `/frost/keys/{id}` |
| `DELETE` | `/frost/keys/{id}` |
| `POST` | `/frost/keys/{id}/nonces` |
| `POST` | `/frost/keys/{id}/sign` |
| `POST` | `/frost/aggregate` |
| `POST` | `/frost/verify` |

`{id}` is the key's CN (`attrs.CN`). Byte fields (messages, signatures,
shares, nonces, commitments, public keys) are hex-encoded strings in every
request/response body.

### `POST /api/v1/frost/keys` — `FrostGenerateKeyRequest` / `Response`

```jsonc
// request
{"key_id": "demo", "algorithm": "FROST-Ed25519-SHA512", "threshold": 2, "total": 3,
 "participants": ["alice","bob","charlie"], "participant_id": 1, "dealer_mode": false}
// response
{"key_id": "demo", "algorithm": "FROST-Ed25519-SHA512", "threshold": 2, "total": 3,
 "group_public_key": "<hex>", "participant_id": 1,
 "packages": [/* dealer_mode only, one FrostKeyPackage per participant */],
 "created_at": "2026-09-24T00:00:00Z"}
```

### `POST /api/v1/frost/keys/{id}/nonces` — Round 1

Request: `{"key_id": "demo"}`. Response
(`FrostGenerateNoncesResponse`) carries the participant's secret
`hiding_nonce`/`binding_nonce` alongside the public
`hiding_commitment`/`binding_commitment` and a `session_id` — the caller is
responsible for keeping the secret nonces out of anything downstream of this
call.

### `POST /api/v1/frost/keys/{id}/sign` — Round 2

Request (`FrostSignRoundRequest`) carries `message` (hex), `session_id`, this
participant's own nonces/commitments from round 1, and the full
`commitments` array collected from every signer. Response
(`FrostSignRoundResponse`) is this participant's hex `signature_share`.

### `POST /api/v1/frost/aggregate` — `FrostAggregateRequest` / `Response`

Carries `key_id`, hex `message`, the full `commitments` and `shares` arrays,
and a `verify` bool (verify the result before returning it). Response is
`{"signature": "<hex>", "verified": true}`.

### `POST /api/v1/frost/verify` — `FrostVerifyRequest` / `Response`

`{"key_id", "message" (hex), "signature" (hex)}` → `{"valid": bool,
"message": string}`.

## gRPC (`pkg/api/grpc/service_frost.go`, `proto/xkmsv1/xkms.proto`)

Nine RPCs on `KeystoreService`: `FrostGenerateKey`, `FrostImportKey`,
`FrostListKeys`, `FrostGetKey`, `FrostDeleteKey`, `FrostGenerateNonces`,
`FrostSignRound`, `FrostAggregate`, `FrostVerify`. Each has its own
`pb.Frost*Request`/`pb.Frost*Response` message pair (not shared with the REST
JSON DTOs, though the field sets are the same shape). Every handler starts
with `s.getFrostBackend()` (`service_frost.go:600`).

## MCP (`pkg/api/mcp/handlers_frost.go`)

Nine dotted methods, dispatched by a `switch` in `routeFrostMethods`
(`pkg/api/mcp/handlers_frost.go:773-800` — unlike the SSH methods, which are
dispatched through the map in `server.go`): `frost.generateKey`,
`frost.importKey`, `frost.listKeys`, `frost.getKey`, `frost.deleteKey`,
`frost.generateNonces`, `frost.signRound`, `frost.aggregate`,
`frost.verify`.

## Pagination

`GET /api/v1/frost/keys` (`FrostListKeysHandler`) pages through the same
shared `transport.PageRequestFromQuery` implementation every REST list
endpoint uses; see [`../key-management/api.md`](../key-management/api.md)
§"Pagination" for the `page` / `page_size` / `sort_field` / `sort_order`
query parameters and the **400** an invalid one gets. With no `page`
parameter every FROST key on this node is returned.
