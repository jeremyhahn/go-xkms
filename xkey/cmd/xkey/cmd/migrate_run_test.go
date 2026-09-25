// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
)

// TestRunMigrate_RequiresRoot exercises the real, unprivileged code path:
// the test process is never root in CI, so runMigrate must refuse before
// touching any LUKS container, kernel keyring, or device mapper state.
func TestRunMigrate_RequiresRoot(t *testing.T) {
	require.NotEqual(t, 0, os.Geteuid(), "this test must not run as root")

	cmd := &cobra.Command{}
	err := runMigrate(cmd, nil)
	require.ErrorIs(t, err, luks.ErrPermissionDenied)
}
