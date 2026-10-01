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

// These tests run the tpm policy commands in local mode against the
// in-process TPM 2.0 simulator. The simulator is in memory; the data
// directory is a test temporary directory.
package cmd

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/localtpm"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// localSimTPMPolicies points the tpm policy commands at the local TPM
// policy service over a provisioned simulator, with its data directory in
// dataDir, and returns the service. The simulator stays open for the test.
func localSimTPMPolicies(t *testing.T, dataDir string) (*localtpm.Host, *slog.Logger) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	opened, err := openTPMWithKeyStore(logger, dataDir, "", true)
	require.NoError(t, err)
	require.NoError(t, opened.TPM().Provision(nil))
	cfg := xkms.DefaultTPMConfig
	require.NoError(t, xkms.EnrollSimulatorPlatformSRK(opened.TPM(), &cfg))

	local, err := localtpm.Open(localtpm.Params{
		TPM:       opened.TPM(),
		Keys:      opened.Keys(),
		DataDir:   dataDir,
		OpenStore: openEngineStore,
		Logger:    logger,
	})
	require.NoError(t, err)
	session := &localtpm.Host{Policies: local, Device: opened}
	t.Cleanup(func() { assert.NoError(t, session.Close()) })

	previous := tpmPolicySessionFactory
	tpmPolicySessionFactory = func(*cobra.Command) (*tpmPolicySession, error) {
		svc := services.NewTPMPolicyService()
		svc.SetLocal(local)
		// The session is closed by the test cleanup, not by each command.
		return &tpmPolicySession{svc: svc, local: local}, nil
	}
	t.Cleanup(func() { tpmPolicySessionFactory = previous })
	return session, logger
}

func TestTPMPolicyCommands_LocalModeLifecycle(t *testing.T) {
	localSimTPMPolicies(t, t.TempDir())
	withTPMPolicyFlags(t, "23", "sha256", false, false)

	out, err := runTPMPolicyCommand(t, runTPMPolicyCreate, "boot")
	require.NoError(t, err)
	assert.Contains(t, out, "Branch 0:     pcr=sha256:23 (approved: yes)")

	out, err = runTPMPolicyCommand(t, runTPMPolicyList)
	require.NoError(t, err)
	assert.Contains(t, out, "Source: local TPM (system scope)")
	assert.Contains(t, out, "boot")

	_, err = runTPMPolicyCommand(t, runTPMPolicyVerify, "boot")
	require.NoError(t, err)

	out, err = runTPMPolicyCommand(t, runTPMAuthorityRotate)
	require.NoError(t, err)
	assert.Contains(t, out, "Generation: 2")

	_, err = runTPMPolicyCommand(t, runTPMPolicyDelete, "boot")
	require.NoError(t, err)
}

func TestTPMPolicyAutoUnseal_LocalSealsTheBarrierCredential(t *testing.T) {
	dataDir := t.TempDir()
	session, logger := localSimTPMPolicies(t, dataDir)
	withTPMPolicyFlags(t, "23", "sha256", true, false)

	// create --auto-unseal reads the barrier password and seals it under the
	// new policy.
	pipeBarrier(t, "barrier password")
	out, err := runTPMPolicyCommand(t, runTPMPolicyCreate, "boot")
	require.NoError(t, err)
	assert.Contains(t, out, "Auto-unseal:  yes")

	// The TPM releases it to a barrier sealed with that password.
	barrier := services.NewBarrierService(dataDir, logger)
	barrier.SetDataDir(dataDir)
	require.NoError(t, barrier.Initialize("barrier password", string(xkms.StrategyPassphrase)))
	require.NoError(t, barrier.Seal())
	auto := services.NewBarrierAutoUnsealService(services.WithBarrierAutoUnsealLocal(session.Policies),
		services.WithBarrierAutoUnsealBarrier(barrier), services.WithBarrierAutoUnsealLogger(logger))
	ok, err := auto.TryAutoUnseal(context.Background(), string(xkms.StrategyPassphrase))
	require.NoError(t, err)
	assert.True(t, ok)

	// --off clears the mark and the credential.
	withTPMPolicyFlags(t, "", "", false, true)
	out, err = runTPMPolicyCommand(t, runTPMPolicyAutoUnseal)
	require.NoError(t, err)
	assert.Contains(t, out, "Barrier auto-unseal disabled")
	status, err := auto.GetAutoUnsealStatus()
	require.NoError(t, err)
	assert.False(t, status.PolicyConfigured)

	// Enabling again needs the password; an empty one is refused.
	withTPMPolicyFlags(t, "", "", false, false)
	pipeBarrier(t, "")
	_, err = runTPMPolicyCommand(t, runTPMPolicyAutoUnseal, "boot")
	assert.ErrorIs(t, err, ErrBarrierPasswordEmpty)
	pipeBarrier(t, "barrier password")
	out, err = runTPMPolicyCommand(t, runTPMPolicyAutoUnseal, "boot")
	require.NoError(t, err)
	assert.Contains(t, out, `enabled under TPM policy "boot"`)
}

func TestTryBarrierPolicyAutoUnseal_UnprovisionedTPMCannotOpen(t *testing.T) {
	// A fresh simulator has no Platform SRK, so the local service cannot be
	// built over it and the caller is told why.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	barrierSvc := services.NewBarrierService(t.TempDir(), logger)
	unsealed, closer, err := tryBarrierPolicyAutoUnseal(context.Background(), logger, barrierSvc, t.TempDir(),
		xkms.StrategyTPM2, "", true)
	assert.False(t, unsealed)
	assert.Nil(t, closer)
	assert.ErrorIs(t, err, ErrLocalTPMPoliciesOpenFailed)
}
