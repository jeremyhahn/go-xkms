// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package usb

// GenerateLauncher returns a POSIX shell script that detects the host
// architecture, sets XKEY_HOME to the directory containing the script,
// and executes the appropriate xkey binary.
//
// The launcher supports amd64 (x86_64), arm64 (aarch64), and armv7l
// architectures. It sets XKEY_HOME so that the xhome resolution picks
// up the .xkey-home marker file on the FAT32 partition.
func GenerateLauncher() string {
	return launcherScript
}

const launcherScript = `#!/bin/sh
# xKey Portable Launcher
# Auto-generated - do not edit
#
# This script detects the host architecture, sets XKEY_HOME to the
# directory containing the script (the USB drive's FAT32 partition),
# and launches the appropriate xkey binary.

set -e

# Resolve the directory this script lives in, following symlinks.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"

# Set XKEY_HOME to the script's directory so that xhome resolution
# finds the .xkey-home marker and uses this directory as the root.
export XKEY_HOME="${SCRIPT_DIR}"

# Detect architecture.
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)
        BINARY="xkey-linux-amd64"
        ;;
    aarch64|arm64)
        BINARY="xkey-linux-arm64"
        ;;
    armv7l|armv6l)
        BINARY="xkey-linux-arm"
        ;;
    *)
        echo "Error: unsupported architecture: ${ARCH}" >&2
        exit 1
        ;;
esac

BINARY_PATH="${SCRIPT_DIR}/${BINARY}"

if [ ! -f "${BINARY_PATH}" ]; then
    echo "Error: binary not found: ${BINARY_PATH}" >&2
    echo "Available binaries:" >&2
    ls -1 "${SCRIPT_DIR}"/xkey-* 2>/dev/null || echo "  (none)" >&2
    exit 1
fi

if [ ! -x "${BINARY_PATH}" ]; then
    chmod +x "${BINARY_PATH}"
fi

exec "${BINARY_PATH}" "$@"
`

// GenerateReadme returns a README.txt suitable for the FAT32 partition
// root directory explaining the USB drive's contents and usage.
func GenerateReadme() string {
	return readmeText
}

const readmeText = `xKey Portable USB Drive
======================

This USB drive contains the xKey security key application configured
for portable use. The drive has two partitions:

  Partition 1 (XKEY):      FAT32 - Contains xKey binaries and launcher
  Partition 2 (xkey-data):  LUKS2 - Encrypted data partition

Quick Start
-----------
On Linux, run the launcher script from this partition:

    ./xkey.sh

The launcher automatically detects your CPU architecture and runs the
correct binary. Your XKEY_HOME is set to this directory.

To unlock the encrypted data partition:

    sudo ./xkey.sh luks2 unseal

Files on this Partition
-----------------------
  xkey.sh          - Portable launcher script (start here)
  xkey-linux-amd64 - Binary for x86_64 systems
  xkey-linux-arm64 - Binary for ARM64 systems
  xkey-linux-arm   - Binary for ARMv7 systems
  .xkey-home       - Marker file for xKey home detection
  README.txt       - This file

Security Notes
--------------
  - The encrypted data partition uses LUKS2 with AES-256-XTS
  - Always safely eject the USB drive before removing it
  - Keep a backup of your passphrase in a secure location
  - The FAT32 partition is NOT encrypted; do not store secrets on it
`
