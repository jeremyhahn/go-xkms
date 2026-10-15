# USB — Architecture

> **Status: NORMATIVE** · Feature: `usb` · Module: `go-xkms/xkey` · Last verified: 2026-09-24

## Scope

This folder covers two unrelated xKey features that both live under
`xkey usb` and the packages a "USB" search turns up:

1. **Virtual CCID smartcard device** (`xkey/pkg/ccid`, `xkey/pkg/gadget`,
   `xkey usb device *`) — xKey presents itself to the OS as a USB CCID
   smartcard reader with a card inserted, translating ISO 7816 APDUs to
   PKCS#11 operations.
2. **Portable USB disk images** (`xkey/pkg/usb`, `xkey usb create` /
   `status` / `update`) — a two-partition disk image (FAT32 launcher +
   LUKS2 data) for carrying xKey and its encrypted state on a physical
   drive.

They share nothing at the code level beyond the `xkey usb` command prefix
and the theme of "acting like a piece of USB hardware." Do not confuse
either of them with the phone-pairing protocol's **USB AOA transport**
(`pkg/pairingproto/usb_transport.go`, build tag `usb` — a different tag
namespace entirely, documented in `xkey/docs/phone-hsm/`): that is a wired
alternative to BLE for reaching a paired phone, not a virtual device or a
disk image.

## 1. Virtual CCID device

### Two transports, one CCID/APDU stack

`CCIDDevice` (`xkey/pkg/ccid/ccid.go`) is transport-agnostic: it depends on
`gadget.Transport` (`Read`/`Write`/`Close`), not directly on `/dev/uhid`.
Two implementations exist (`xkey/pkg/gadget`):

- **`UHIDTransport`** (`uhid_transport.go`) — software HID emulation via
  Linux's `/dev/uhid`. Works on any Linux host, no special hardware. This
  is the default (`xkey usb device start`'s `--transport` defaults to
  `uhid`).
- **`FunctionFSTransport`** / the ConfigFS gadget stack (`configfs.go`,
  `functionfs.go`, `gadget.go`, `descriptor.go`) — a real USB CCID (class
  `0x0B`) and HID composite device built through Linux's ConfigFS/
  FunctionFS gadget framework. This requires OTG-capable hardware with a
  UDC (USB Device Controller) — the CLI help text names a Raspberry Pi
  Zero 2W as an example. Selected with `--transport gadget`, optionally
  `--udc <controller>` to pick a specific UDC when more than one is
  present.

This two-transport design is **not documented in the superseded
`xkey/docs/usb/ccid.md`**, which describes only the UHID path — see this
feature's handoff report for the full disagreement list.

```
+-------------------+    Read/Write/Close    +------------------+     APDU      +----------------+
| Smartcard Client   | <--------------------> | CCIDDevice       | <-----------> | PKCS11Bridge   |
| (OpenSC, GPG,      |  gadget.Transport       | (ccid.go)        |  HandleAPDU   | (bridge.go)    |
|  pcscd, browser)   |  UHID or ConfigFS/      | CCID framing,    |               | AID/session    |
|                     |  FunctionFS             | event loop       |               | state, PSO     |
+-------------------+                         +------------------+               +-------+--------+
                                                                                          |
                                                                                pkcs11 transport
                                                                                          |
                                                                                  +-------v--------+
                                                                                  | xKey backend   |
                                                                                  | (software,     |
                                                                                  |  tpm2, pkcs11) |
                                                                                  +----------------+
```

### APDU bridge

`PKCS11Bridge` (`xkey/pkg/ccid/bridge.go`) implements the handler
`CCIDDevice` calls per `XfrBlock` message, dispatching by APDU instruction
byte (`bridge.go:164-169`): `SELECT` (`0xA4`), `VERIFY` (`0x20`), `PSO`
(`0x2A`), `READ BINARY` (`0xB0`), `GENERATE ASYMMETRIC KEY PAIR` (`0x47`),
`GET DATA` (`0xCA`). `SELECT` recognizes two applet AIDs — PIV
(`A0 00 00 03 08 00 00 10 00 01 00`) and OpenPGP
(`D2 76 00 01 24 01`) — and maps to the corresponding backend PKCS#11
operations underneath.

### Device identity

The virtual reader identifies itself with vendor/product IDs in the
test/prototype range (`xkey/pkg/ccid/descriptor.go:20-37`): vendor
`0xF1D0`, product `0x0004`, name "xKey CCID Smartcard Reader", serial
`XKEYCCID001`, CCID spec version 1.10, max IFSD 254 bytes. The ATR
identifies the emulated card as `xKey CCID v1.0`.

### CLI wiring and the LUKS-exempt group

`cmd/xkey/cmd/usb_device.go` wires `--device-backend` (PKCS#11 backend:
`software`/`tpm2`/`pkcs11`), `--transport` (`uhid`/`gadget`), and `--udc`.
The whole `usb` command group is one of the groups exempt from the LUKS
unlock gate (`xkey/docs/luks/cli.md` "The unlock gate") — `xkey usb device
start` must be runnable before an encrypted home directory is unlocked,
since it can itself be the way an operator reaches the machine.

## 2. Portable USB disk images

### Layout

`CreateImage` (`xkey/pkg/usb/image.go`) partitions a file or block device
with `sgdisk` into two GPT partitions:

| Partition | Filesystem | Size | GPT type | Contents |
|---|---|---|---|---|
| 1 | FAT32, label `XKEY` | fixed 512 MB (`FAT32PartitionSize`) | `EF00` (EFI System) | xkey binaries, `xkey.sh` launcher, README |
| 2 | LUKS2 + ext4, label `xkey-data` | remainder | `8300` (Linux) | encrypted xKey home directory |

Minimum total image size is 1 GB (`MinImageSize`, `xkey/pkg/usb/size.go`) —
the FAT32 partition alone needs 512 MB, plus room for LUKS2 headers and
usable data. For a block device (`--path /dev/sdX`), the full device size
is used and `--size` is ignored.

### Relationship to the LUKS2 feature

The data partition is a standard LUKS2 container — the same format and
the same `xkey/pkg/luks` lifecycle documented in `xkey/docs/luks/`, just
created directly by `xkey/pkg/usb/image.go`'s `formatLUKS` rather than
through `xkey luks2 seal`. Once written to a drive, xKey's ordinary home
resolution (`$XKEY_HOME`, `xkey/pkg/xhome`) treats it identically to any
other LUKS-backed home: the FAT32 partition's `.xkey-home` marker and
`xkey.sh` launcher point `XKEY_HOME` at the script's own directory so the
marker is found, and everything downstream (the Barrier, LUKS unlock gate)
behaves exactly as it does for a fixed installation.

### Portable launcher

`GenerateLauncher()` (`xkey/pkg/usb/launcher.go`) produces a POSIX shell
script written onto the FAT32 partition that detects host architecture
(`x86_64`, `aarch64`, `armv7l`) and execs the matching bundled binary, with
`XKEY_HOME` set to its own directory.

## Rejected/out-of-scope for this folder

- Neither sub-feature has a network (xkmsd) or GUI (Wails) surface — see
  `api.md`.
- The physical/ConfigFS gadget path additionally needs `pkg/fido2/uhid`
  (`uhid_linux.go` / `uhid_stub.go`, split on the `linux` build constraint,
  not a custom tag) only for the UHID transport; the ConfigFS/FunctionFS
  path talks to the kernel gadget subsystem directly and does not use
  `/dev/uhid` at all.
