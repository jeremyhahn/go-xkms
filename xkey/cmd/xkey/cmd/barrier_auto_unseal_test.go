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

// These tests exercise tryBarrierPolicyAutoUnseal (barrier_auto_unseal.go)
// against the in-process TPM 2.0 simulator so the full headless auto-unseal
// path -- the one `xkey extension serve`, `xkey fido2`, and
// `xkey barrier unseal --auto` all now drive -- runs without real hardware
// and without a password. The simulator is entirely in-memory; it never
// touches the host filesystem or a physical device.
package cmd

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// initSimulatorTPM2Barrier initializes and seals a tpm2-strategy barrier in
// dataDir using the in-process TPM simulator, and returns the PCR values
// (bank "SHA256", indices 0-7) captured from that same simulator instance
// so a test can pin them into an auto-unseal policy. It closes its TPM
// connection before returning rather than deferring to t.Cleanup: the
// go-tpm-tools in-process simulator serializes on a process-wide lock
// (simulator.Get), so a second simulator opened anywhere else in the same
// test process -- exactly what tryBarrierPolicyAutoUnseal's own TPM open
// does -- would block forever waiting for this one to close. The SRK is
// re-derived deterministically from the simulator's fixed seed
// (pkg/tpm2/tpm_simulator.go), so a policy pinned to the PCR values read
// here, and a barrier sealed here, remain valid once Provision runs again
// in the next simulator instance.
func initSimulatorTPM2Barrier(t *testing.T, dataDir string) map[uint][]byte {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(testWriter{t}, nil))

	tpm, closer, err := openTPMModule(logger, dataDir, "", true)
	require.NoError(t, err)

	// A fresh simulator has no SRK resident at its persistent handle yet
	// (unlike real hardware, which is provisioned once via `xkey tpm
	// provision`/`install` and keeps the SRK resident forever): Provision
	// creates and evicts it so sealing has a usable parent key.
	require.NoError(t, tpm.Provision(nil), "provisioning the TPM simulator's SRK must succeed")

	barrierSvc := services.NewBarrierService(dataDir, logger)
	barrierSvc.SetDataDir(dataDir)
	barrierSvc.SetTPMSealerFunc(func() xkms.Sealer { return tpm })
	require.NoError(t, barrierSvc.Initialize("", string(xkms.StrategyTPM2)))
	require.NoError(t, barrierSvc.Seal())

	accessor := services.NewTPMAccessor(func() xkms.TrustedPlatformModule { return tpm })
	probe := services.NewBarrierAutoUnsealService(nil, services.WithBarrierAutoUnsealTPMAccessor(accessor))
	pcrs, err := probe.CaptureCurrentPCRs(context.Background(), "sha256", []uint{0, 1, 2, 3, 4, 5, 6, 7})
	require.NoError(t, err)

	require.NoError(t, closer.Close())

	return pcrs
}

// createAndDesignateAutoUnsealPolicy creates a policy named "boot-policy"
// pinning pcrs and marks it as the auto-unseal policy, using the exact
// store path (and therefore location) tryBarrierPolicyAutoUnseal reads --
// the same one `xkey policy create` / `xkey policy set-auto-unseal` write
// to by default.
func createAndDesignateAutoUnsealPolicy(t *testing.T, dataDir string, pcrs map[uint][]byte) {
	t.Helper()

	store, err := openPolicyStore(filepath.Join(dataDir, pcrPolicyStoreSubdir))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	_, err = store.Create(ctx, "boot-policy", "SHA256", pcrs)
	require.NoError(t, err)
	require.NoError(t, store.SetAutoUnseal(ctx, "boot-policy"))
}

// testWriter adapts *testing.T to io.Writer so a *slog.Logger can write
// into the test log instead of stderr.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

// TestTryBarrierPolicyAutoUnseal_Success exercises a full, real PCR-policy
// auto-unseal -- policy verification and the barrier's TPM2 Unseal both run
// against genuine simulator crypto, and no password appears anywhere in
// this test -- but against a single already-open, already-provisioned TPM
// rather than through tryBarrierPolicyAutoUnseal's own TPM open.
//
// tryBarrierPolicyAutoUnseal deliberately opens its own TPM connection,
// matching every production caller (extension serve, fido2, `barrier
// unseal --auto`), each of which is a separate process reconnecting to a
// real chip that was already provisioned once, out of band, via `xkey tpm
// provision`/`install`. The in-process go-tpm-tools simulator cannot stand
// in for that: it allows only one simulator open per process at a time
// (simulator.Get's package-wide lock -- a second concurrent open deadlocks
// waiting for the first to close) and starts every fresh instance
// unprovisioned (no SRK resident at its persistent handle), so a second,
// independently-opened simulator instance can verify PCRs -- and this test
// does exercise that read through tryBarrierPolicyAutoUnseal in the other
// three tests below -- but cannot Unseal without Provisioning itself
// first, which production code correctly never does on the caller's
// behalf (auto-provisioning a TPM's owner hierarchy as a side effect of an
// unseal attempt would be a security-relevant behaviour change of its
// own). This test therefore drives the same
// services.BarrierAutoUnsealService.TryAutoUnseal call
// tryBarrierPolicyAutoUnseal makes, against one real TPM, to prove the
// underlying mechanism it composes actually works end-to-end.
func TestTryBarrierPolicyAutoUnseal_Success(t *testing.T) {
	dataDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(testWriter{t}, nil))

	tpm, closer, err := openTPMModule(logger, dataDir, "", true)
	require.NoError(t, err)
	defer func() { _ = closer.Close() }()
	require.NoError(t, tpm.Provision(nil), "provisioning the TPM simulator's SRK must succeed")

	barrierSvc := services.NewBarrierService(dataDir, logger)
	barrierSvc.SetDataDir(dataDir)
	barrierSvc.SetTPMSealerFunc(func() xkms.Sealer { return tpm })
	require.NoError(t, barrierSvc.Initialize("", string(xkms.StrategyTPM2)))
	require.NoError(t, barrierSvc.Seal())
	require.False(t, barrierSvc.IsUnsealed())

	accessor := services.NewTPMAccessor(func() xkms.TrustedPlatformModule { return tpm })
	pcrProbe := services.NewBarrierAutoUnsealService(nil, services.WithBarrierAutoUnsealTPMAccessor(accessor))
	pcrs, err := pcrProbe.CaptureCurrentPCRs(context.Background(), "sha256", []uint{0, 1, 2, 3, 4, 5, 6, 7})
	require.NoError(t, err)

	store, err := openPolicyStore(filepath.Join(dataDir, pcrPolicyStoreSubdir))
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	_, err = store.Create(ctx, "boot-policy", "SHA256", pcrs)
	require.NoError(t, err)
	require.NoError(t, store.SetAutoUnseal(ctx, "boot-policy"))

	autoSvc := services.NewBarrierAutoUnsealService(store,
		services.WithBarrierAutoUnsealTPMAccessor(accessor),
		services.WithBarrierAutoUnsealBarrier(barrierSvc),
		services.WithBarrierAutoUnsealLogger(logger),
	)

	unsealed, err := autoSvc.TryAutoUnseal(ctx)
	require.NoError(t, err)
	assert.True(t, unsealed)
	assert.True(t, barrierSvc.IsUnsealed())
}

func TestTryBarrierPolicyAutoUnseal_NoPolicyConfigured(t *testing.T) {
	dataDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(testWriter{t}, nil))

	// Barrier exists and is tpm2-strategy, but no policy was ever created
	// or designated: the caller must fall back silently.
	initSimulatorTPM2Barrier(t, dataDir)

	barrierSvc := services.NewBarrierService(dataDir, logger)
	barrierSvc.SetDataDir(dataDir)

	unsealed, closer, err := tryBarrierPolicyAutoUnseal(context.Background(), logger, barrierSvc, dataDir, "", true)
	require.NoError(t, err)
	assert.False(t, unsealed)
	assert.Nil(t, closer)
	assert.False(t, barrierSvc.IsUnsealed())
}

func TestTryBarrierPolicyAutoUnseal_PCRMismatch(t *testing.T) {
	dataDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(testWriter{t}, nil))

	pcrs := initSimulatorTPM2Barrier(t, dataDir)

	// Corrupt one PCR digest so it can never match the simulator's actual
	// (freshly booted, unextended) value.
	for idx := range pcrs {
		bad := make([]byte, len(pcrs[idx]))
		copy(bad, pcrs[idx])
		bad[0] ^= 0xFF
		pcrs[idx] = bad
		break
	}
	createAndDesignateAutoUnsealPolicy(t, dataDir, pcrs)

	barrierSvc := services.NewBarrierService(dataDir, logger)
	barrierSvc.SetDataDir(dataDir)

	unsealed, closer, err := tryBarrierPolicyAutoUnseal(context.Background(), logger, barrierSvc, dataDir, "", true)
	assert.False(t, unsealed)
	assert.Nil(t, closer)
	require.Error(t, err)
	assert.ErrorIs(t, err, services.ErrBarrierAutoUnsealPCRMismatch)
	assert.False(t, barrierSvc.IsUnsealed())
}

func TestTryBarrierPolicyAutoUnseal_PolicyStoreOpenFailedIsTyped(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(testWriter{t}, nil))
	barrierSvc := services.NewBarrierService(t.TempDir(), logger)

	// dataDir is a file, not a directory: opening the policy store beneath
	// it must fail, and the failure must be the typed sentinel, not a bare
	// filesystem error, so callers can distinguish it from a PCR mismatch.
	dataDir := filepath.Join(t.TempDir(), "not-a-directory")
	f, err := os.Create(dataDir)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	unsealed, closer, err := tryBarrierPolicyAutoUnseal(context.Background(), logger, barrierSvc, dataDir, "", true)
	assert.False(t, unsealed)
	assert.Nil(t, closer)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBarrierAutoUnsealPolicyStoreFailed)
}
