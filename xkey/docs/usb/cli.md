# USB — CLI

> **Status: NORMATIVE** · Feature: `usb` · Module: `go-xkms/xkey` · Last verified: 2026-10-09

All USB commands live under `xkey usb` and are exempt from the LUKS unlock
gate (`xkey/docs/luks/cli.md` "The unlock gate") — they must be reachable
before (or regardless of) an encrypted home directory being unlocked.

## Portable disk images

### `xkey usb create` — create an image or prepare a device

```bash
sudo xkey usb create <device-or-image> [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--size` | string | `4G` | Total image size (e.g. `1G`, `4G`, `8G`). Ignored for block devices — the full device size is used |
| `--binary` | stringArray | `[]` | Path to an xkey binary to include (repeatable). Defaults to the current binary |

Prompts for a LUKS passphrase with confirmation. Requires root.

```bash
sudo xkey usb create /tmp/xkey.img --size 4G
sudo xkey usb create /tmp/xkey.img --size 4G \
  --binary ./build/xkey-linux-amd64 --binary ./build/xkey-linux-arm64
sudo xkey usb create /dev/sdb                 # writes the whole device; --size ignored
```

### `xkey usb status` — show image or device status

```bash
xkey usb status [device-or-image]
```

Displays partition sizes, LUKS mount status, and binaries detected on the
FAT32 partition. Does not require root.

### `xkey usb update` — refresh binaries and launcher

```bash
sudo xkey usb update <device-or-image> [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--binary` | stringArray | `[]` | Path to an xkey binary to include (repeatable). Defaults to the current binary |

Replaces binaries on the FAT32 partition and regenerates the launcher
script. Requires root.

```bash
sudo xkey usb update /tmp/xkey.img --binary ./build/xkey-linux-amd64
```

### Flashing and testing an image

```bash
sudo dd if=/tmp/xkey.img of=/dev/sdX bs=4M status=progress
qemu-system-x86_64 -drive file=/tmp/xkey.img,format=raw
```

## Virtual CCID device

### `xkey usb device start` — start the virtual smartcard

```bash
sudo xkey usb device start [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--device-backend` | string | `software` | PKCS#11 backend: `software`, `tpm2`, `pkcs11` |
| `--transport` | string | `uhid` | USB transport: `uhid` (software HID emulation, any Linux) or `gadget` (real USB device, requires OTG hardware) |
| `--udc` | string | (auto-detect) | UDC controller name for gadget mode |

Runs in the foreground until `Ctrl+C` or `SIGTERM`. Requires root or access
to `/dev/uhid`.

The keys come from the local app access setting
(`usbDevicePKCS11Transport`, `cmd/xkey/cmd/usb_device.go`). Off (the
default): the device opens the keys in this process. On: it uses the keys of
the open, unlocked xKey over its socket, and fails with
`ErrUSBDeviceGUINotListening` if none answers. It never falls back. Under
`sudo`, both the settings file (`$XDG_CONFIG_HOME/xkey/gui.json`) and the
socket path come from the environment `sudo` passes on, which is usually
root's. Set `XKEY_IPC_SOCKET` to reach your own GUI's socket. See
[../pkcs11/cli.md](../pkcs11/cli.md).

```bash
sudo xkey usb device start                                   # UHID, software backend
sudo xkey usb device start --device-backend tpm2
sudo xkey usb device start --transport gadget
sudo xkey usb device start --transport gadget --udc dummy_udc.0
```

### `xkey usb device status` — show virtual device status

```bash
xkey usb device status
```

Checks UHID availability, device identification, and whether a CCID
device process is currently running.

### `xkey usb device stop` — stop the running device

```bash
xkey usb device stop
```

`stop` does not reach into the other, already-running process (there is no
IPC channel between them) — it only prints the same instructions below.
Stop the running `xkey usb device start` directly:

```bash
kill -TERM $(pgrep -f "xkey usb device start")
```

## Troubleshooting

- **"device not available" / UHID errors** — confirm `/dev/uhid` exists
  and is accessible (root, or membership in whatever group your
  distribution grants `/dev/uhid` access to).
- **"no unlocked xKey is listening"** — local app access is on, so the
  device wants the open xKey's keys. Open and unlock xKey, or run `xkey
  app-access disable` to use in-process keys.
- **`--transport gadget` fails to bind** — needs real OTG hardware with a
  UDC; `--udc` lets you pick one explicitly when auto-detection picks the
  wrong controller or more than one is present.
- **`usb create`/`usb update` fail on a real device** — `ValidateBlockDevice`
  refuses a target that looks like a mounted system disk
  (`ErrSystemDisk`); double-check the device path.
