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

// registerDevicePairFlags registers the flags for `xkey device pair`. It is
// called by both the ble and !ble implementations of the command
// (device_pair.go and device_pair_stub.go) so the two flag sets cannot drift
// out of parity (go-xkms#1318).
//
// --device and --force are per-invocation choices with no config-file
// meaning and are read directly off the flag; --timeout is shared with
// `device scan` and resolves through resolveDeviceScanTimeout (device.go),
// so device.scan_timeout applies here too (go-xkms#1071).
func registerDevicePairFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Specific device name or address to pair")
	cmd.Flags().Duration("timeout", defaultDeviceScanTimeout,
		"Scan timeout duration (default: device.scan_timeout, 30s)")
	cmd.Flags().Bool("force", false, "Force re-pairing even if already paired")
	addSOPINFlags(cmd)
	addBarrierPasswordFlags(cmd)
}
