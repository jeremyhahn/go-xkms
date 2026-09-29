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

package cmd

import (
	"github.com/spf13/cobra"
)

// registerDeviceScanFlags registers the flags for `xkey device scan`. It is
// called by both the ble and !ble implementations of the command
// (device_scan.go and device_scan_stub.go) so the two flag sets cannot drift
// out of parity (go-xkms#1318).
//
// --timeout is shared with `device pair` and resolves through
// resolveDeviceScanTimeout (device.go): the flag when explicitly set, else
// device.scan_timeout from the unified config, else this registered default
// (go-xkms#1071).
func registerDeviceScanFlags(cmd *cobra.Command) {
	cmd.Flags().Duration("timeout", defaultDeviceScanTimeout,
		"Scan timeout duration (default: device.scan_timeout, 30s)")
}
