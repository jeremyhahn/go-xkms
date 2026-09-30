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

// These tests exercise runBarrierUnsealAuto (barrier_unseal.go), the
// CLI-level wrapper around tryBarrierPolicyAutoUnseal, which
// tpm_policy_simulator_test.go covers directly: the wrapper's BarrierError
// translation and the --auto dispatch. The unseal itself -- the barrier
// password sealed under the scope's auto-unseal policy and unsealed
// through the TPM -- is proven by the services package's
// BarrierAutoUnsealService tests on the simulator.
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

// TestRunBarrierUnsealAuto_UnenrolledTPMIsATypedFailure proves auto-unseal
// on a TPM whose Platform SRK was never enrolled -- a fresh simulator, which
// production code never auto-provisions -- fails as a typed BarrierError
// that keeps the TPM's reason, never as success, for any password strategy
// (auto-unseal is a TPM policy attribute, not a barrier strategy). The
// "no auto-unseal policy configured" outcome needs a provisioned TPM and is
// covered by test/integration/tpm_policy_test.go on swtpm.
func TestRunBarrierUnsealAuto_UnenrolledTPMIsATypedFailure(t *testing.T) {
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
	assert.Contains(t, err.Error(), "Platform SRK unavailable", "the TPM's reason must survive the wrapping")
	assert.Empty(t, buf.String(), "a failed auto-unseal must not print a success line")
}

// TestRunBarrierUnseal_AutoFlagDispatches proves --auto routes `barrier
// unseal` to runBarrierUnsealAuto rather than the password prompt.
func TestRunBarrierUnseal_AutoFlagDispatches(t *testing.T) {
	isolateBarrier(t)
	withSimulatorTPMFlag(t)

	pipeBarrier(t, "correct-horse", "correct-horse")
	_, err := runBarrierCmd(t, runBarrierInit)
	require.NoError(t, err)

	require.NoError(t, barrierUnsealCmd.Flags().Set("auto", "true"))
	t.Cleanup(func() { require.NoError(t, barrierUnsealCmd.Flags().Set("auto", "false")) })

	var buf bytes.Buffer
	barrierUnsealCmd.SetOut(&buf)

	err = runBarrierUnseal(barrierUnsealCmd, nil)
	require.Error(t, err)

	var barrierErr *BarrierError
	require.ErrorAs(t, err, &barrierErr)
	assert.Equal(t, "auto_unseal", barrierErr.Operation, "the --auto flag must dispatch to runBarrierUnsealAuto")
}
