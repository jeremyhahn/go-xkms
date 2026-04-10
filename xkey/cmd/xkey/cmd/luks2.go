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

// luks2Cmd is the parent command for LUKS2 encrypted storage operations.
var luks2Cmd = &cobra.Command{
	Use:   "luks2",
	Short: "LUKS2 encrypted storage management",
	Long: `Manage LUKS2 encrypted storage for xKey credentials.

xKey supports LUKS2 encrypted storage to protect credentials at rest.
All credential data is stored inside an encrypted container that must be
unlocked before use.

Features:
  - AES-256-XTS encryption with Argon2id key derivation
  - Automatic migration of existing unencrypted data
  - Auto-detection and unlock prompting on startup
  - Secure container destruction with multi-pass wiping

Default Paths:
  Data directory:  ~/.xkey (mount point when using LUKS)
  LUKS container:  ~/.xkey.luks

Commands:
  seal         Create a new encrypted container
  unseal       Unlock an existing container
  lock         Lock an open container
  import-data  Import existing data into a LUKS volume
  migrate      Migrate to a new/larger container
  wipe         Securely destroy an encrypted container

Examples:
  # Create encrypted storage (migrates existing data)
  sudo xkey luks2 seal

  # Unlock encrypted storage
  sudo xkey luks2 unseal

  # Lock encrypted storage
  sudo xkey luks2 lock

  # Migrate to larger container (doubles size by default)
  sudo xkey luks2 migrate

  # Securely destroy the container
  sudo xkey luks2 wipe --passes 3`,
}

func init() {
	RootCmd.AddCommand(luks2Cmd)
}
