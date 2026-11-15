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
3. Docs commit: key-management/engineering.md section
   `per-board-ota-image-keys` names the export and the board -> key id
   record (`OTAImageKeyID`); this plan.

## Next slice

- Wire the export on gRPC, REST, MCP and the CLI (`xkmsctl key ota-image`),
  with its integration tests, and api.md / cli.md.

## Out of scope

- go.mod / go.sum changes, docs/SPEC.md, ROADMAP.md, CI files,
  pkg/auth/permissions.go.
