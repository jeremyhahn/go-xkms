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
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

func TestSoftwarePIV_UnusableHomeRequiresTheEncryptedKeyStore(t *testing.T) {
	isolatedBackupHome(t)
	// An xKey home below a regular file has no data directory to hold the
	// encrypted key store.
	blocker := filepath.Join(t.TempDir(), "regular-file")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	t.Setenv(xhome.EnvHome, filepath.Join(blocker, "home"))
	xhome.ResetRoot()
	t.Cleanup(xhome.ResetRoot)
	newPIVProcess()
	t.Cleanup(newPIVProcess)

	err := ensureSoftwarePIVKeyStore(newPIVGenerateCmd(t), slog.Default())
	require.ErrorIs(t, err, ErrPIVSoftwareKeyStoreRequiresBarrier)
}
