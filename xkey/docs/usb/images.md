# USB Disk Image Support

xkey can create bootable USB disk images for portable deployments. Images work with both physical USB flash drives and QEMU virtual machines, allowing you to carry xkey and all its encrypted data on a single USB device.

## Overview

A USB image contains two partitions:

```
+---------------------------+-----------------------------------+
| Partition 1: FAT32 (512MB)| Partition 2: LUKS2 (remainder)    |
| Label: XKEY               | Label: xkey-data                  |
| Type:  EFI System (EF00)  | Type:  Linux (8300)               |
|                            |                                   |
| - xkey binaries            | - Encrypted data partition        |
| - xkey.sh launcher         | - AES-256-XTS via dm-crypt        |
| - .xkey-home marker        | - ext4 filesystem inside          |
| - README.txt               |                                   |
+---------------------------+-----------------------------------+
```

The FAT32 partition is readable on any OS and contains multi-architecture xkey binaries with a launcher script that auto-detects the host CPU. The LUKS2 partition stores all credentials, keys, and configuration encrypted at rest.

## Partition Layout

| Partition | Filesystem | Size | GPT Type | Contents |
|-----------|-----------|------|----------|----------|
| 1 | FAT32 | 512 MB (fixed) | EF00 (EFI System) | Binaries, launcher, marker |
| 2 | LUKS2 + ext4 | Remaining space | 8300 (Linux) | Encrypted data |

Minimum image size is 1 GB. The GPT partition table is created with `sgdisk`.

## CLI Commands

All USB image commands are under `xkey usb`.

### create - Create a New Image

Creates a two-partition disk image file or prepares a physical USB device. Requires root.

```bash
sudo xkey usb create <path> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--size` | Total image size (e.g., 1G, 4G, 8G). Ignored for block devices. | 4G |
| `--binary` | Path to xkey binary to include (repeatable). | Current binary |

Prompts for a LUKS passphrase with confirmation.

### status - Show Image Status

Displays partition sizes, LUKS mount status, and detected binaries.

```bash
xkey usb status <path>
```

### update - Update Binaries

Replaces xkey binaries on the FAT32 partition and refreshes the launcher script. Requires root.

```bash
sudo xkey usb update <path> [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--binary` | Path to xkey binary to include (repeatable). | Current binary |

## Usage Examples

### Create a 4 GB Image File

```bash
sudo xkey usb create /tmp/xkey.img --size 4G
```

### Create with Multi-Architecture Binaries

```bash
sudo xkey usb create /tmp/xkey.img --size 4G \
  --binary ./build/xkey-linux-amd64 \
  --binary ./build/xkey-linux-arm64
```

### Write Directly to a USB Device

```bash
# The full device size is used; --size is ignored.
sudo xkey usb create /dev/sdb
```

### Flash an Image to USB

```bash
sudo dd if=/tmp/xkey.img of=/dev/sdX bs=4M status=progress
```

### Test with QEMU

```bash
qemu-system-x86_64 -drive file=/tmp/xkey.img,format=raw
```

### Update Binaries on an Existing Image

```bash
sudo xkey usb update /tmp/xkey.img --binary ./build/xkey-linux-amd64
```

## Portable Launcher

The FAT32 partition includes `xkey.sh`, a POSIX shell script that detects the host architecture (x86_64, aarch64, armv7l) and runs the matching binary. It sets `XKEY_HOME` to the script directory so that xkey's home resolution picks up the `.xkey-home` marker on the FAT32 partition.

```bash
# From the mounted USB drive:
./xkey.sh
```

## API Reference

The `xkey/pkg/usb` package provides the programmatic interface.

| Function | Description |
|----------|-------------|
| `CreateImage(cfg ImageConfig)` | Create a partitioned image or prepare a block device |
| `Status(path string)` | Query the status of an existing image or device |
| `UpdateBinaries(path string, binaries []string)` | Replace binaries on the FAT32 partition |
| `DetectUSBDevices()` | Scan for removable USB mass storage devices |
| `IsBlockDevice(path string)` | Check if a path is a block device |
| `ValidateBlockDevice(path string)` | Verify a device is safe to write (not a system disk) |
| `ParseSize(s string)` | Parse human-readable size strings (e.g., "4G") |
| `FormatSize(bytes int64)` | Format byte counts for display |

### ImageConfig

```go
type ImageConfig struct {
    Path       string   // Output path (file or block device)
    SizeBytes  int64    // Total size (ignored for block devices)
    Passphrase string   // LUKS passphrase for the data partition
    Binaries   []string // Paths to xkey binaries for the FAT32 partition
}
```

## Security Notes

- The FAT32 partition is **not encrypted**. Do not store secrets on it.
- The LUKS2 data partition uses AES-256-XTS via the kernel dm-crypt subsystem.
- Always safely eject the USB drive before removing it.
- Keep a secure backup of your passphrase; it is not recoverable.
- `ValidateBlockDevice` prevents accidental writes to system disks by checking `/proc/mounts`.

## See Also

- [LUKS2 Encrypted Storage](luks.md) - LUKS container management
- [Auto-Unseal](auto-unseal.md) - TPM-based auto-unseal for LUKS and barrier
- [Architecture](architecture.md) - System design overview
