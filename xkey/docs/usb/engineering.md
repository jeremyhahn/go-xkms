# USB — Engineering

> **Status: NORMATIVE** · Feature: `usb` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## Exported surface — virtual CCID device

### `xkey/pkg/ccid`

| Symbol | Kind | Notes |
|---|---|---|
| `ccid.APDUHandler` | interface | `HandleAPDU([]byte) []byte`, `GetATR() []byte` |
| `ccid.CCIDDevice` | type | the event loop / CCID message framing |
| `ccid.NewCCIDDevice(handler, transport gadget.Transport, logger)` | func | — |
| `(*CCIDDevice).Start(ctx)` / `Stop()` / `IsRunning()` | methods | `Start` runs the event loop until `ctx` is cancelled or `Stop` is called |
| `ccid.PKCS11Transport` | interface | `GenerateKey`/`Sign`/`Verify`/`Encrypt`/`Decrypt`, all `(ctx, *transport.XRequest) (*transport.XResponse, error)` — the subset of `sdk/go/transport` the bridge needs |
| `ccid.PKCS11Bridge` | type | implements `APDUHandler` |
| `ccid.NewPKCS11Bridge(t PKCS11Transport, logger)` | func | — |
| `ccid.AppletID` | type | `AppletNone`, `AppletPIV`, `AppletOpenPGP` |
| `ccid.VendorIDCCID`, `ProductIDCCID`, `CCIDDeviceName`, `CCIDDeviceSerial`, `CCIDMaxIFSD` | const | `0xF1D0`, `0x0004`, `"xKey CCID Smartcard Reader"`, `"XKEYCCID001"`, `254` (`descriptor.go`) |
| `ccid.AIDPIV`, `ccid.AIDOpenPGP` | var | applet AID byte slices |

Supported APDU instructions (`bridge.go:164-169`, dispatched by a
`map[byte]handlerFunc`, matching this project's map-dispatch convention):
`INS_SELECT` (`0xA4`), `INS_VERIFY` (`0x20`), `INS_PSO` (`0x2A`),
`INS_READ_BINARY` (`0xB0`), `INS_GENERATE_ASYMMETRIC` (`0x47`),
`INS_GET_DATA` (`0xCA`). PSO sub-operations dispatch further on P1/P2 for
compute/verify signature and encipher/decipher (`bridge.go:240-261` and
surrounding).

### `xkey/pkg/gadget`

| Symbol | Kind | Notes |
|---|---|---|
| `gadget.Transport` | interface | `Read(ctx) ([]byte, error)`, `Write(data) error`, `Close() error` (`transport.go:18-33`) — deliberately small "to accommodate future transports such as NFC" |
| `gadget.TransportType` | type | `TransportUHID`, and the ConfigFS/FunctionFS equivalent |
| `gadget.UHIDTransport` / `NewUHIDTransport(dev *uhid.Device, logger)` | type/func | wraps `xkey/pkg/uhid` |
| `gadget.FunctionFSTransport` / `NewFunctionFSTransport(mountDir, fs, logger)` | type/func | ConfigFS/FunctionFS gadget I/O |
| `gadget.ConfigFS` / `NewConfigFS(config, fs, logger)` | type/func | `Create`, `Bind`, `Unbind`, `Destroy`, `GadgetDir`, `IsBound` — manages the kernel gadget's ConfigFS tree |
| `gadget.GadgetConfig` / `DefaultGadgetConfig()` | type/func | vendor/product IDs, functions to enable |
| `gadget.Gadget` / `gadget.New(config, logger, opts...)` | type/func | top-level orchestrator; `Start`, `Stop`, `CCIDTransport()`, `HIDTransport()`, `IsBound()` |
| `gadget.WithFileSystem(fs)`, `gadget.WithHIDDevicePath(path)` | `Option` funcs | functional options on `New` |
| `gadget.BuildCCIDDescriptors()`, `BuildFunctionFSStrings()` | func | USB descriptor bytes for the CCID class and FunctionFS |

## Errors — CCID (`xkey/pkg/ccid/errors.go`)

| Sentinel | Meaning |
|---|---|
| `ccid.ErrDeviceNotAvailable` / `ErrDeviceAlreadyRunning` / `ErrDeviceNotRunning` | device lifecycle |
| `ccid.ErrAPDUTooLong` / `ErrAPDUMalformed` / `ErrUnsupportedInstruction` | APDU parsing/dispatch |
| `ccid.ErrSessionNotFound` / `ErrAppletNotSelected` | bridge session state — `VERIFY`/PSO before `SELECT` |
| `ccid.ErrNilHandler` / `ErrNilLogger` / `ErrNilService` | construction-time nil checks |
| `ccid.ErrCCIDMessageTooShort` / `ErrCCIDUnsupportedMessage` | CCID framing |
| `ccid.ErrLoginFailed` / `ErrSignFailed` / `ErrVerifyFailed` / `ErrEncryptFailed` / `ErrDecryptFailed` / `ErrKeyGenerationFailed` / `ErrCertificateReadFailed` | PKCS#11 operation failures surfaced back through the bridge |

`gadget` has its own error types (`GadgetError`, `DetailError`,
`SentinelCauseError`, `WrappedError`, `xkey/pkg/gadget/errors.go`) used to
wrap ConfigFS/FunctionFS filesystem failures with the operation and cause.

## Exported surface — portable USB disk images (`xkey/pkg/usb`)

| Symbol | Kind | Notes |
|---|---|---|
| `usb.ImageConfig` | type | `Path string`, `SizeBytes int64`, `Passphrase *secure.Secret`, `Binaries []string` |
| `usb.ImageStatus` | type | `Path`, `IsBlockDevice`, `TotalSize`, `FAT32Size`, `LUKSSize`, `LUKSMounted`, `Binaries` |
| `usb.CreateImage(ctx context.Context, cfg ImageConfig) error` | func | refuses `SizeBytes < MinImageSize` for a file target; ignored for a block device |
| `usb.Status(path) (*ImageStatus, error)` | func | — |
| `usb.UpdateBinaries(path string, binaries []string) error` | func | — |
| `usb.DetectUSBDevices() ([]USBDevice, error)` | func | scans for removable block devices |
| `usb.USBDevice` | type | — |
| `usb.IsBlockDevice(path) bool` / `usb.ValidateBlockDevice(path) error` | func | `ValidateBlockDevice` checks `/proc/mounts` to refuse a device that looks like a system disk |
| `usb.BlockDeviceSize(path) (int64, error)` | func | — |
| `usb.ParseSize(s) (int64, error)` / `usb.FormatSize(bytes) string` | func | units `K`/`M`/`G`/`T`, case-insensitive |
| `usb.GenerateLauncher() string` / `usb.GenerateReadme() string` | func | text written onto the FAT32 partition |
| `usb.MinImageSize`, `usb.FAT32PartitionSize` | const | `1 GB`, `512 MB` |

`ImageConfig.Passphrase` is `*secure.Secret`
(`github.com/jeremyhahn/go-xkms/sdk/go/secure`) — held in protected memory,
**not** a plain `string`; `CreateImage` rejects a `nil` passphrase. It takes
the caller's `context.Context` first and opens the passphrase under it.

## Errors — disk images (`xkey/pkg/usb/errors.go`)

| Sentinel | Meaning |
|---|---|
| `usb.ErrDeviceNotFound` / `ErrImageNotFound` / `ErrImageExists` | path resolution |
| `usb.ErrInvalidSize` | below `MinImageSize`, or an unparseable `--size` |
| `usb.ErrPartitionFailed` / `ErrFormatFailed` / `ErrMountFailed` / `ErrUnmountFailed` | `sgdisk`/`mkfs`/mount pipeline failures |
| `usb.ErrPermissionDenied` | not root |
| `usb.ErrSystemDisk` | `ValidateBlockDevice` refused the target |
| `usb.ErrCopyFailed` / `ErrBinaryNotFound` | binary staging onto the FAT32 partition |
| `usb.ErrLoopSetupFailed` | loop device setup for a file-backed image |
| `usb.ErrDeviceBusy` | device already in use |

## Configuration

No dedicated config file schema for either sub-feature. The CCID device's
backend and transport are pure CLI flags (`cli.md`); the disk-image tools
take all parameters as CLI flags or `ImageConfig` fields — there is no
persisted "USB settings" section in `xkey`'s config.

## Tests

| Layer | File | What it proves |
|---|---|---|
| `pkg/ccid` | `ccid_test.go` | CCID message framing, event loop, `handleIccPowerOn`/`handleXfrBlock`/etc. |
| `pkg/ccid` | `bridge_test.go` | APDU dispatch, applet selection, PSO sub-operations, PKCS#11 delegation and error mapping |
| `pkg/ccid` | `apdu_test.go` | `CommandAPDU`/`ResponseAPDU` wire encode/decode |
| `pkg/gadget` | `*_test.go` (per file: `configfs`, `functionfs`, `gadget`, `hid_gadget`, `uhid_transport`, `descriptor`, `filesystem`, `errors`) | ConfigFS tree construction against a fake `FileSystem`, descriptor byte layout, transport `Read`/`Write`/`Close` |
| `pkg/usb` | `image_test.go` | partition/format/populate pipeline against fake command execution; `Status`/`UpdateBinaries` |
| `pkg/usb` | `device_test.go`, `size_test.go`, `launcher_test.go`, `hooks_test.go`, `errors_test.go` | block-device detection/validation, size parsing/formatting, launcher/README generation, command-hook error wrapping |
| `test/integration/gadget` | `gadget_integration_test.go` | real ConfigFS/FunctionFS gadget bring-up in a privileged container |

`make test-ccid` runs the CCID package unit tests; `make
integration-test-gadget` runs the privileged-Docker gadget integration
suite (`xkey/Makefile:430-431, 609-611`).

## Non-goals

- No REST/gRPC/GUI IPC surface for either sub-feature — see `api.md`.
- No support for USB gadget mode on non-Linux hosts (ConfigFS/FunctionFS
  are Linux kernel interfaces).
- The FAT32 boot partition is deliberately unencrypted — only the LUKS2
  data partition protects data at rest (`xkey/docs/luks/`).
