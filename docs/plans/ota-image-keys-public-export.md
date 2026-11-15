# ota-image-keys: export the board public key (row #1778, epic #1606)

## Claim

The row issue (trusted-firmware #104, requirement 10) asks for the public
half of a board's ES256 OTA image key in two forms: the raw 64-byte X || Y
and a COSE_Key that carries the key id. Create, rotate and sign already
ship; the export did not exist.

## Slice (this lane)

1. Test commit `26fc69f2c` `test(xkms): export the OTA board public key as
   raw X||Y and COSE_Key`: `TestOTAImageKeys_ExportPublicKey` in
   `pkg/xkms/ota_image_keys_test.go` checks the 64-byte raw key, the COSE_Key
   (kty 2, crv 1, alg -7, x, y, kid = `OTAImageKeyID(board)`, no d), the key
   id, `ErrKeyNotFound` for a board with no key, nil request, and the
   rotated version. It failed to compile before the fix.
2. Fix commit `443a9668e` `feat(xkms): export the OTA board public key as
   raw X||Y and COSE_Key`: `(*XKMSService).ExportOTAImagePublicKey`,
   `transport.OTAImagePublicKeyResponse` with its `sdk/go/transport` alias,
   and `requireES256KeyVersion` behind `requireES256Key`. The COSE_Key uses
   `github.com/fxamacker/cbor/v2`, already in go.mod.
   Follow-up `501d9a5c3` `fix(xkms): encode the OTA public export from
   PublicKey.Bytes` (staticcheck SA1019: ecdsa X/Y deprecated in Go 1.26).
3. Docs commit `4c1cb5e68`: key-management/engineering.md section
   `per-board-ota-image-keys` names the export and the board -> key id
   record (`OTAImageKeyID`); this plan.

## Slice row1778b: REST and MCP

1. `5c81ab950` `test(xkms): assert the OTA permissions are registered in
   go-qrdb` (Codex P1 on row1778a): the grant test also checks
   `qrdbsdk.IsPermissionRegistered`. It passes on the pinned go-qrdb and
   guards a regression.
2. Test commit `23bd9c5ec` `test(api): serve the OTA board public key export
   on REST and MCP`: `TestOTAImageKeyHandlers_ExportPublicKey` and
   `TestOTAImageKeyRoutes_ExportPublicKeyNeedsKeysGet` (REST),
   `TestOTAImageKeyMethods_ExportPublicKey` and the `keys:get` entry in
   `TestOTAImageKeyMethods_Registered` (MCP). They failed to compile first.
3. Fix commit `237b0e44a` `feat(api): serve the OTA board public key export
   on REST and MCP`: `Servicer.ExportOTAImagePublicKey` and its test
   doubles, `GET /api/v1/ota-image-keys/{board}/public-key` and
   `xkms.exportOTAImagePublicKey` under `keys:get`, the REST and MCP authz
   golden tables, and the `sdk/go` alias `OTAImagePublicKeyResponse`.
   Follow-up `66896c62a` `test(api): compare the OTA public export with
   PublicKey.Bytes` (SA1019).
4. Docs commit: key-management/api.md documents the REST route and the MCP
   method; this plan.

## Slice row1778c: gRPC and client transports

1. Test commit `e6c7f7ef9` `test(api): gRPC and client transports export
   the OTA image public key`: `TestService_ExportOTAImagePublicKey` (fields,
   64-byte raw equal to the key's X||Y), `_NotFound` and
   `_PermissionDenied` (gRPC service), and one `ExportPublicKey` test in
   each of the six `transport_ota_image_test.go` files. They failed to
   compile first.
2. Fix commit `c148727c5` `feat(api): ExportOTAImagePublicKey on gRPC and
   every client transport`: `rpc ExportOTAImagePublicKey` with
   `OTAImagePublicKeyResponse` under `keys:get` (`make proto`), the gRPC
   service method, `transport.Client.ExportOTAImagePublicKey` on gRPC, Unix,
   embedded, REST and QUIC (`GET .../{board}/public-key?backend=`) and MCP
   (`xkms.exportOTAImagePublicKey`), the gRPC authz golden table, and the
   `Client` test doubles in cmd/xkmsctl and sdk/go. Follow-up `83b57a9ed`:
   the xkey `Client` doubles, and the raw check via `PublicKey.Bytes`
   (SA1019).
3. Docs commit: key-management/api.md names the gRPC and SDK methods; this
   plan.

## Slice row1778d: xkmsctl export and the integration test

1. Test commit `68d5ef1b4` `test(xkmsctl): export the OTA image public
   key`: `TestKeyOTAImageExportCmd` (key id, board id, version, raw hex),
   `_NotFound` and `_Registered` in cmd/xkmsctl, and
   `TestSDK_Embedded_ExportOTAImagePublicKey` (after a rotate: raw is 64
   bytes and verifies the board's image signature) with `_NotFound` in
   test/integration/sdk/go. They failed first.
2. Fix commit `9233d2981` `feat(xkmsctl): ota-image-key export`:
   `xkmsctl key ota-image export <board-id>` and
   `ErrExportOTAImagePublicKeyFailed`; the integration test service answers
   the export from its stored P-256 key.
3. Docs commit: docs/key-management/cli.md documents the verb; this plan.

## Left for the row

- Nothing in code. The parity suite (`test/integration/api/commands`) has
  no `key ota-image` definitions, the same pre-existing gap as create,
  rotate and sign (cli.md, Parity coverage).

## Out of scope

- go.mod / go.sum changes, docs/SPEC.md, ROADMAP.md, CI files,
  pkg/auth/permissions.go.
