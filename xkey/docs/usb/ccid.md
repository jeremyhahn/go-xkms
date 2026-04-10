# Virtual USB CCID Device

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

1. **CCIDDevice** (`ccid.go`) -- Opens `/dev/uhid`, creates a virtual USB HID device with CCID-class report descriptors, and runs the event loop. Receives PC_to_RDR messages, extracts APDU payloads from XfrBlock messages, and sends RDR_to_PC responses back.

2. **PKCS11Bridge** (`bridge.go`) -- Implements the `APDUHandler` interface. Routes ISO 7816 instructions (SELECT, VERIFY, PSO, GENERATE ASYMMETRIC, GET DATA, READ BINARY) to the corresponding PKCS#11 transport operations. Manages card sessions and applet selection state.

3. **PKCS11Transport** -- The backend abstraction. Supports `software`, `tpm2`, and `pkcs11` backends for key generation, signing, verification, encryption, and decryption.

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

Creates the virtual device and runs the event loop in the foreground. Requires root or access to `/dev/uhid`.

```bash
sudo xkey usb device start [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--device-backend` | PKCS#11 backend: software, tpm2, pkcs11 | software |

Stop the device with Ctrl+C or SIGTERM.

### status - Show Device Status

Displays UHID availability, device identification, and whether a CCID device process is running.

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

- Linux kernel with UHID support (`CONFIG_UHID`)
- Access to `/dev/uhid` (root or `uinput` group membership)
- The xkey PKCS#11 subsystem must be initialized before starting

## See Also

- [PKCS#11 IPC](pkcs11-ipc.md) - PKCS#11 module integration
- [PIV Support](piv.md) - PIV applet and certificate management
- [USB Disk Images](usb-images.md) - Portable USB image creation
- [Architecture](architecture.md) - System design overview
