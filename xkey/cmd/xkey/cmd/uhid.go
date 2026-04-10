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
	"errors"

	"github.com/spf13/cobra"
)

// UHID command errors.
var (
	// ErrUHIDNotLinux indicates that UHID is only available on Linux.
	ErrUHIDNotLinux = errors.New("uhid: only available on Linux")
)

// uhidCmd is the parent command for UHID device management.
var uhidCmd = &cobra.Command{
	Use:   "uhid",
	Short: "UHID virtual USB HID device management",
	Long: `Manage the Linux UHID (User-space HID) kernel interface used by
the FIDO2 virtual authenticator.

Commands:
  setup     Configure /dev/uhid permissions (requires root)`,
}

func init() {
	RootCmd.AddCommand(uhidCmd)
}
