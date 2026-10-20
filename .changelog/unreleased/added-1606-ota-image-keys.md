- **One ES256 OTA image-signing key per trusted-firmware board id.**
  `XKMSService.CreateOTAImageKey`, `RotateOTAImageKey` and `SignOTAImage`
  (`pkg/xkms/ota_image_keys.go`) map a board id to the key `ota-image-<board>`
  and create, rotate and sign through the existing key-management path, so a
  rotated board key keeps verifying the images its earlier versions signed. A
  malformed board id is refused with `ErrInvalidBoardID` and any algorithm or
  key other than ECDSA P-256 with `ErrOTAImageAlgorithm` (#1606). REST serves
  them at `POST /api/v1/ota-image-keys/{board}`, `.../rotate` and `.../sign`,
  gRPC as the `CreateOTAImageKey`, `RotateOTAImageKey` and `SignOTAImage`
  RPCs, and MCP as `xkms.createOTAImageKey`, `xkms.rotateOTAImageKey` and
  `xkms.signOTAImage`, under the `keys:create`, `keys:rotate` and `keys:sign`
  permissions; both refusals are a 400, `InvalidArgument` or JSON-RPC -32602.
  xkey reaches them through the SDK as `xkey key ota-image create`, `rotate`
  and `sign`, with the same flags and output as xkmsctl.
