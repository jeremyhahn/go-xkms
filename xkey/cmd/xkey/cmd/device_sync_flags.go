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
	"time"

	"github.com/spf13/cobra"
)

// registerDeviceSyncFlags registers the flags for `xkey device sync`. It is
// called by both the ble and !ble implementations of the command
// (device_sync.go and device_sync_stub.go) so the two flag sets cannot drift
// out of parity (go-xkms#1318).
func registerDeviceSyncFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("trust-store", false, "Sync trust store certificates")
	cmd.Flags().Bool("oath", false, "Sync OATH credentials")
	cmd.Flags().Bool("passwords", false, "Sync password entries")
	cmd.Flags().Bool("all", true, "Sync all stores (default)")
	cmd.Flags().String("device", "", "Paired device name")
	cmd.Flags().Bool("dry-run", false, "Show what would be synced without applying")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	addBarrierPasswordFlags(cmd)
}

// registerDeviceSyncStatusFlags registers the flags for `xkey device
// sync-status`. It is called by both the ble and !ble implementations of the
// command so the two flag sets cannot drift out of parity (go-xkms#1318).
func registerDeviceSyncStatusFlags(cmd *cobra.Command) {
	cmd.Flags().String("device", "", "Paired device name")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	addBarrierPasswordFlags(cmd)
}

// registerDeviceSyncPushFlags registers the flags for `xkey device
// sync-push`. It is called by both the ble and !ble implementations of the
// command so the two flag sets cannot drift out of parity (go-xkms#1318).
func registerDeviceSyncPushFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("trust-store", false, "Push trust store certificates")
	cmd.Flags().Bool("oath", false, "Push OATH credentials")
	cmd.Flags().Bool("passwords", false, "Push password entries")
	cmd.Flags().Bool("all", true, "Push all stores (default)")
	cmd.Flags().String("device", "", "Paired device name")
	cmd.Flags().Bool("dry-run", false, "Show what would be pushed without applying")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	addBarrierPasswordFlags(cmd)
}

// registerDeviceSyncPullFlags registers the flags for `xkey device
// sync-pull`. It is called by both the ble and !ble implementations of the
// command so the two flag sets cannot drift out of parity (go-xkms#1318).
func registerDeviceSyncPullFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("trust-store", false, "Pull trust store certificates")
	cmd.Flags().Bool("oath", false, "Pull OATH credentials")
	cmd.Flags().Bool("passwords", false, "Pull password entries")
	cmd.Flags().Bool("all", true, "Pull all stores (default)")
	cmd.Flags().String("device", "", "Paired device name")
	cmd.Flags().Bool("dry-run", false, "Show what would be pulled without applying")
	cmd.Flags().Duration("timeout", 60*time.Second, "Operation timeout")
	addBarrierPasswordFlags(cmd)
}
