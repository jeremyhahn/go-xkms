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

// registerDeviceListenFlags registers the flags for `xkey device listen`
// and, since go-xkms#1306, `xkey device relay`. It is called by the ble and
// !ble implementations of "listen" (device_listen.go and
// device_listen_stub.go) and by "relay" (device_relay.go) so their flag sets
// cannot drift out of parity (go-xkms#1318).
func registerDeviceListenFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Specific paired device to accept connections from")
	cmd.Flags().String("name", "", "Advertised device name (default: hostname)")
	cmd.Flags().Duration("timeout", 0, "Listen timeout (0 for indefinite)")
	cmd.Flags().String("attestation-mode", "auto", "Attestation mode: auto, tpm2, software")
	cmd.Flags().String("tpm-device", "", "TPM2 device path (default: /dev/tpmrm0)")
	cmd.Flags().Bool("tpm-enrollment", false, "Serve TCG-CSR-IDEVID device enrollment from this host's TPM")
	cmd.Flags().String("tpm-pcr-bank", "", "PCR bank for the platform policy digest (default: SHA-256); set only if this TPM's SHA-256 bank is not allocated")
	// --allow-sync opts THIS session in to serving remote.syncPasswords,
	// remote.syncOATH and remote.syncAll -- the bridge methods that export
	// the password vault or OATH secrets to the phone. Without it those
	// three methods are refused (ErrSyncApprovalRequired) regardless of
	// what else is configured: exporting secrets is never the default
	// (go-xkms#1306). An enterprise policy sealed under the SO PIN can lock
	// this decision either way; see resolvePairingPolicy and
	// allowPhoneSyncExport.
	cmd.Flags().Bool("allow-sync", false, "Allow this session to export the password vault and OATH secrets to the phone via remote.sync*")
	addSOPINFlags(cmd)
	addBarrierPasswordFlags(cmd)
}
