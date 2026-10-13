# Virtual USB CCID Device

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: background on the virtual CCID device (`xkey/pkg/ccid`); the usb feature folder ([architecture.md](architecture.md), [cli.md](cli.md)) is normative.

xkey can present itself as a virtual CCID (Chip Card Interface Device) smartcard reader with an inserted card. The operating system sees a standard smartcard reader, and ISO 7816 APDU commands are translated into PKCS#11 operations through the xkey backend. This enables VM passthrough, integration with smartcard-aware applications (OpenSC, GnuPG, ssh-agent), and PIV/OpenPGP applet emulation.

## Architecture

```
+-------------------+     UHID      +------------------+     APDU      +----------------+
| Smartcard Client  | <-----------> | CCIDDevice       | <-----------> | PKCS11Bridge   |
| (OpenSC, GPG,     |   /dev/uhid   | (ccid.go)        |  HandleAPDU   | (bridge.go)    |
|  pcscd, browser)  |               | Event loop,      |               | APDU dispatch, |
+-------------------+               | CCID framing     |               | session mgmt   |
                                    +------------------+               +-------+--------+
                                                                               |
                                                                     PKCS11Transport
                                                                               |
                                                                       +-------v--------+
                                                                       | xKey Backend   |
                                                                       | (software,     |
                                                                       |  tpm2, pkcs11) |
                                                                       +----------------+
```

The stack has three layers:

1. **CCIDDevice** (`xkey/pkg/ccid/ccid.go`) -- Runs the event loop over a USB transport: a virtual HID device on `/dev/uhid` (`--transport uhid`, the default) or a real USB gadget through ConfigFS/FunctionFS (`--transport gadget`). `xkey/cmd/xkey/cmd/usb_device.go` opens the transport. Receives PC_to_RDR messages, extracts APDU payloads from XfrBlock messages, and sends RDR_to_PC responses back.

2. **PKCS11Bridge** (`bridge.go`) -- Implements the `APDUHandler` interface. Routes ISO 7816 instructions (SELECT, VERIFY, PSO, GENERATE ASYMMETRIC, GET DATA, READ BINARY) to the corresponding PKCS#11 transport operations. Manages card sessions and applet selection state.

3. **PKCS11Transport** (`xkey/pkg/ccid/bridge.go`) -- The backend abstraction. When local app access is off it is the in-process transport; when it is on, the running xKey's socket (`usbDevicePKCS11Transport`, `xkey/cmd/xkey/cmd/usb_device.go:256`). `--device-backend` selects `software`, `tpm2` or `pkcs11`.

## APDU Command Handling

The bridge supports the following ISO 7816-4 instructions:

| INS | Name | PKCS#11 Mapping |
|-----|------|-----------------|
| `0xA4` | SELECT | Select PIV or OpenPGP applet by AID |
| `0x20` | VERIFY | C_Login (PIN authentication, creates session) |
| `0x2A` | PSO (Perform Security Operation) | See sub-operations below |
| `0x47` | GENERATE ASYMMETRIC KEY PAIR | C_GenerateKeyPair |
| `0xB0` | READ BINARY | Certificate/object retrieval |
| `0xCA` | GET DATA | Data object retrieval by tag |

### PSO Sub-Operations

| P1 | P2 | Operation | PKCS#11 Mapping |
|----|----|-----------|-----------------|
| `0x9E` | `0x9A` | Compute Digital Signature | C_Sign (SHA-256) |
| `0x00` | `0xA8` | Verify Digital Signature | C_Verify |
| `0x86` | `0x80` | Encipher | C_Encrypt |
| `0x80` | `0x86` | Decipher | C_Decrypt |

### Supported Applets

| Applet | AID | Description |
|--------|-----|-------------|
| PIV | `A000000308000010000100` | Personal Identity Verification |
| OpenPGP | `D27600012401` | OpenPGP card |

## CCID Message Protocol

The device implements the USB CCID 1.10 specification. Messages use a 10-byte header:

```
Offset  Field           Size    Description
0       bMessageType    1       Message type identifier
1-4     dwLength        4       Data length (little-endian)
5       bSlot           1       Slot number (always 0)
6       bSeq            1       Sequence number
7-9     (varies)        3       Message-specific fields
```

Supported PC_to_RDR (host to reader) messages: IccPowerOn, IccPowerOff, GetSlotStatus, XfrBlock, GetParameters, Escape, Abort.

## CLI Commands

Virtual device commands are under `xkey usb device`.

### start - Start the Virtual CCID Device

Creates the virtual device and runs the event loop in the foreground. Requires root, or access to `/dev/uhid` in UHID mode.

```bash
sudo xkey usb device start [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--device-backend` | PKCS#11 backend: software, tpm2, pkcs11 | software |
| `--transport` | USB transport: `uhid` or `gadget` (OTG hardware) | uhid |
| `--udc` | UDC controller name for gadget mode | auto-detect |

Stop the device with Ctrl+C or SIGTERM.

### stop - Print Stop Instructions

Prints how to stop the running device; it does not signal it.

### status - Show Device Status

Displays UHID and USB gadget availability, the UDC controller if one is found, whether a CCID device process is running, and the device identification.

```bash
xkey usb device status
```

## Usage Examples

### Start with Default Software Backend

```bash
sudo xkey usb device start
```

### Start with TPM2 Backend

```bash
sudo xkey usb device start --device-backend tpm2
```

### Check Device Status

```bash
xkey usb device status
```

### Stop a Running Device

```bash
# From another terminal:
kill -TERM $(pgrep -f "xkey usb device start")
```

## Device Identification

| Property | Value |
|----------|-------|
| Device Name | xKey CCID Smartcard Reader |
| Vendor ID | `0xF1D0` (test/prototype range) |
| Product ID | `0x0004` |
| Serial | `XKEYCCID001` |
| CCID Version | 1.10 |
| Protocols | T=0, T=1 |
| Max IFSD | 254 bytes |

The ATR (Answer To Reset) identifies the card as `xKey CCID v1.0` using direct convention with T=1 protocol.

## Requirements

- UHID mode: Linux kernel with UHID support (`CONFIG_UHID`) and access to `/dev/uhid`
- Gadget mode: OTG-capable hardware with a UDC
- With local app access on, an open and unlocked xKey; otherwise the start fails with `ErrUSBDeviceGUINotListening`

## See Also

- [USB CLI](cli.md) - every `xkey usb` verb and flag
- [USB Architecture](architecture.md) - feature design
- [USB Disk Images](images.md) - Portable USB image creation
- [PKCS#11 CLI](../pkcs11/cli.md) - local app access and the PKCS#11 transports
