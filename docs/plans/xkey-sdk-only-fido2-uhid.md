# xkey-sdk-only: pkg/fido2 root, uhid and virtualdevice through sdk/go/fido2

Row: xkey-sdk-only (docs/SPEC.md:180), epic #2084, lane sxsdkl.

## Gap

SPEC.md:180: xkey reaches go-xkms through sdk/go only. These xkey test files
still import pkg/fido2, pkg/fido2/uhid or pkg/fido2/virtualdevice:

- xkey/cmd/xkey/cmd/password_vault_passkey_test.go (pkg/fido2 as pkgfido2)
- xkey/pkg/gadget/uhid_transport_test.go (pkg/fido2/uhid)
- xkey/pkg/gui/services/fido2_device_service_test.go (pkg/fido2/virtualdevice)
- xkey/pkg/keyboard/keyboard_test.go (pkg/fido2/uhid)
- xkey/test/integration/uhid/uhid_test.go (pkg/fido2/uhid)

## New aliases

- sdk/go/fido2/uhid: ErrDeviceAlreadyCreated, ErrInvalidPacket,
  MaxReportDescriptorSize, SerializeCreate2Request, SerializeInput2Request
- sdk/go/fido2: ErrNoDeviceFound

## Commits

1. test(sdk): TestReexport_UHIDNames, TestReexport_ErrNoDeviceFound
2. feat(sdk): the six aliases
3. refactor(xkey): imports moved (xkey/pkg; xkey/cmd/xkey/cmd; xkey/test/integration/uhid)

## Checks

- sdk/go: go test -race -run TestReexport_ ./fido2/ ./fido2/uhid/
- sdk/go: go build ./...
- xkey: go build ./... and go vet (codec tags; integration linux for test/integration/uhid)
- xkey: go test -race ./pkg/keyboard/ ./pkg/gadget/
- xkey: go test -race -run 'Passkey|FIDO2Device|VirtualDevice' ./cmd/xkey/cmd/ ./pkg/gui/services/
- make lint

## Results

Results to follow.
