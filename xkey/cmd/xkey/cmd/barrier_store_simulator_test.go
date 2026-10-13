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

// These tests drive the tpm2 barrier strategy against a fresh TPM simulator.
// Production code never auto-provisions the Platform SRK, so a fresh
// simulator is exactly the "TPM present but not enrolled" host: every tpm2
// operation must fail as a typed error, never as success, and must release
// the TPM it opened.
package cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateTPM2Barrier isolates the barrier flags and data directory and
// selects the tpm2 strategy on the simulator.
func isolateTPM2Barrier(t *testing.T) string {
	t.Helper()
	dir := isolateBarrier(t)
	withSimulatorTPMFlag(t)
	barrierStrategy = "tpm2"
	return dir
}

// plantTPM2RootKey writes a root key whose envelope names the tpm2 strategy
// but whose sealed blob no TPM can open.
func plantTPM2RootKey(t *testing.T, dir string) {
	t.Helper()
	writeBarrierRootKey(t, dir, []byte(`{"strategy":"tpm2","sealed":"AAAA"}`))
}

func TestRunBarrierInit_TPM2WithoutPlatformSRKFails(t *testing.T) {
	dir := isolateTPM2Barrier(t)

	pipeBarrier(t, "correct-horse", "correct-horse")
	out, err := runBarrierCmd(t, runBarrierInit)
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "initialize", barrierErr.Operation)
	assert.Contains(t, err.Error(), "Platform SRK")
	assert.NotContains(t, out, "Barrier initialized successfully.")
	assert.False(t, barrierRootKeyExists(dir), "a failed init must not leave a root key behind")
}

func TestRunBarrierSeal_TPM2StrategyReleasesTheTPM(t *testing.T) {
	dir := isolateTPM2Barrier(t)
	plantTPM2RootKey(t, dir)

	// Sealing an already-sealed barrier is a no-op; the TPM the strategy
	// opened is closed on the way out.
	out, err := runBarrierCmd(t, runBarrierSeal)
	require.NoError(t, err)
	assert.Contains(t, out, "Barrier sealed successfully.")
}

func TestRunBarrierUnseal_TPM2UnopenableRootKeyFails(t *testing.T) {
	dir := isolateTPM2Barrier(t)
	plantTPM2RootKey(t, dir)

	pipeBarrier(t, "correct-horse")
	out, err := runBarrierCmd(t, runBarrierUnseal)
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "unseal", barrierErr.Operation)
	assert.NotContains(t, out, "Barrier unsealed successfully.")
}

func TestOpenBarrierBackend_TPM2WithoutDeviceIsTPMUnavailable(t *testing.T) {
	dir := isolateTPM2Barrier(t)
	plantTPM2RootKey(t, dir)

	missing := filepath.Join(t.TempDir(), "tpmrm0")
	backend, err := openBarrierBackend("", dir, missing, false)
	require.ErrorIs(t, err, ErrBarrierStoreTPMUnavailable)
	assert.Nil(t, backend)
}
