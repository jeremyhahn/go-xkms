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

// These tests exercise runBarrierUnsealAuto (barrier_unseal.go) -- the
// CLI-level wrapper around tryBarrierPolicyAutoUnseal, which
// barrier_auto_unseal_test.go already covers directly. What is untested
// below the CLI layer is the wrapper itself: strategy gating and BarrierError
// translation.
//
// The success path (a policy match that actually unseals the barrier) is
// deliberately not exercised here through runBarrierUnsealAuto: it opens its
// own TPM connection via tryBarrierPolicyAutoUnseal, and a fresh in-process
// simulator instance has no SRK resident at its persistent handle (see
// initSimulatorTPM2Barrier's doc comment in barrier_auto_unseal_test.go).
// TestTryBarrierPolicyAutoUnseal_Success works around that by driving
// services.BarrierAutoUnsealService directly against a single already-open,
// already-provisioned simulator; runBarrierUnsealAuto has no such seam, and
// production code correctly never auto-provisions a TPM's owner hierarchy as
// a side effect of an unseal attempt, so there is no way to make its own
// internal TPM open succeed here without doing exactly that.
package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// withSimulatorTPMFlag sets barrierTPMSimulator for the duration of a test
// and restores it, and points xhome.Resolve at a private, already-created
// root so runBarrierUnsealAuto's unused xhome.Resolve() call cannot touch
// the real user home.
func withSimulatorTPMFlag(t *testing.T) {
	t.Helper()

	previous := barrierTPMSimulator
	barrierTPMSimulator = true
	t.Cleanup(func() { barrierTPMSimulator = previous })

	xhome.SetRoot(t.TempDir())
	t.Cleanup(xhome.ResetRoot)
}

func TestRunBarrierUnsealAuto_RejectsNonTPM2Strategy(t *testing.T) {
	dir := isolateBarrier(t)
	withSimulatorTPMFlag(t)

	pipeBarrier(t, "correct-horse", "correct-horse")
	_, err := runBarrierCmd(t, runBarrierInit)
	require.NoError(t, err, "the software-strategy barrier this test needs must initialize")

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err = runBarrierUnsealAuto(cmd, dir)
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "auto_unseal", barrierErr.Operation)
	assert.Contains(t, err.Error(), "requires the tpm2 strategy")
	assert.Contains(t, err.Error(), "software")
	assert.Empty(t, buf.String(), "a rejected strategy must not print a success line")
}

func TestRunBarrierUnsealAuto_NoPolicyConfiguredIsReported(t *testing.T) {
	withSimulatorTPMFlag(t)
	dataDir := t.TempDir()

	// A tpm2-strategy barrier exists but no auto-unseal policy was ever
	// designated: the CLI wrapper must translate that into a typed,
	// actionable BarrierError rather than silently reporting success.
	initSimulatorTPM2Barrier(t, dataDir)

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	err := runBarrierUnsealAuto(cmd, dataDir)
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "auto_unseal", barrierErr.Operation)
	assert.Contains(t, err.Error(), "no auto-unseal policy configured")
	assert.Empty(t, buf.String(), "a failed auto-unseal must not print a success line")
}

// TestRunBarrierUnseal_AutoFlagDispatches proves the `--auto` flag on
// `xkey barrier unseal` actually reaches runBarrierUnsealAuto (rather than
// falling through to the password prompt), using the same non-TPM2 rejection
// as its observable signature: a software-strategy barrier can never satisfy
// auto-unseal, so seeing that specific, typed failure -- and not a password
// prompt hanging on stdin -- is proof the flag dispatched correctly.
func TestRunBarrierUnseal_AutoFlagDispatches(t *testing.T) {
	isolateBarrier(t)
	withSimulatorTPMFlag(t)

	pipeBarrier(t, "correct-horse", "correct-horse")
	_, err := runBarrierCmd(t, runBarrierInit)
	require.NoError(t, err)

	require.NoError(t, barrierUnsealCmd.Flags().Set("auto", "true"))
	t.Cleanup(func() { _ = barrierUnsealCmd.Flags().Set("auto", "false") })

	var buf bytes.Buffer
	barrierUnsealCmd.SetOut(&buf)

	err = runBarrierUnseal(barrierUnsealCmd, nil)
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "auto_unseal", barrierErr.Operation, "the --auto flag must dispatch to runBarrierUnsealAuto")
}
