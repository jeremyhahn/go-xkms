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

//go:build tpm_simulator

package cmd

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// openStorageFDs counts this process's open file descriptors on a path
// under dir: the TPM key store's lock file and data files.
func openStorageFDs(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && strings.HasPrefix(target, dir+string(filepath.Separator)) {
			count++
		}
	}
	return count
}

// tpmStorageDir isolates the data dir like the other simulator tests and
// returns the TPM key store's directory under it, with the garbage
// collector off so no finalizer closes a leaked descriptor mid-test.
func tpmStorageDir(t *testing.T) string {
	t.Helper()
	withSimulatorTPMCfg(t)
	dataDir, err := resolveDataDir("")
	require.NoError(t, err)
	resolved, err := filepath.EvalSymlinks(dataDir)
	require.NoError(t, err)
	previous := debug.SetGCPercent(-1)
	t.Cleanup(func() { debug.SetGCPercent(previous) })
	return filepath.Join(resolved, "tpm")
}

// TestOpenTPM_CloseReleasesKeyStore is Codex P1 on #2305: closing a TPM the
// `tpm` commands opened also closes its key-store factory, so its lock file
// is not held until garbage collection or process exit.
func TestOpenTPM_CloseReleasesKeyStore(t *testing.T) {
	dir := tpmStorageDir(t)

	tpm, err := openTPMForProvisioning()
	require.NoError(t, err)
	require.Positive(t, openStorageFDs(t, dir), "the open TPM holds its key store")
	require.NoError(t, tpm.Close())

	require.Zero(t, openStorageFDs(t, dir), "key store still open after TPM Close")
}

// TestOpenTPM_FailureReleasesKeyStore is the error path of the same P1: an
// open that fails (an unprovisioned TPM) leaves no key store open.
func TestOpenTPM_FailureReleasesKeyStore(t *testing.T) {
	dir := tpmStorageDir(t)

	tpm, err := openConfiguredTPM()
	require.ErrorIs(t, err, ErrTPMNotInitialized)
	require.Nil(t, tpm)

	require.Zero(t, openStorageFDs(t, dir), "key store still open after a failed open")
}
