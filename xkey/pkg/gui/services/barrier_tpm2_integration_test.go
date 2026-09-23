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

//go:build integration && tpm_simulator

// Barrier/TPM2 integration test. Run: `go test -tags "integration linux
// tpm_simulator ble codec_json" ./pkg/gui/services/... -run TPM2Reunseal`.
package services

import (
	"context"
	"log/slog"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/stretchr/testify/require"
)

// TestIntegration_BarrierService_TPM2ReunsealAfterAutoLock is #510 verified
// against the in-process TPM 2.0 reference simulator rather than a mock
// Sealer, on the exact sequence the reported burn-in host ran: a barrier
// sealed with the tpm2 strategy, an inactivity auto-lock that seals it, and
// the unlock that reopens it in the same process (what "xkey unlock
// --pin-stdin" drives over IPC). Before the in-place reopen existed in
// BarrierService.Unseal, this second unseal discarded the live barrier and
// rebuilt one from scratch through assembleStrategy every time, and any
// mismatch between the freshly resolved strategy and the one recorded in the
// persisted root key surfaced as the reported qrdb/seal: requested strategy
// not registered. Real TPM sealing exercises the actual Seal/Unseal round
// trip through the hardware object, not a canned response, so a regression in
// how TPM2Strategy is captured or reused across the lock/unlock boundary
// would fail here even if it passed against the mock.
func TestIntegration_BarrierService_TPM2ReunsealAfterAutoLock(t *testing.T) {
	tpm := setupSimulatedTPM(t)

	svc := NewBarrierService(t.TempDir(), slog.Default())
	svc.SetTPMSealerFunc(func() xkms.Sealer { return tpm })

	ctx := context.Background()
	require.NoError(t, svc.Initialize("", string(xkms.StrategyTPM2)),
		"initializing the barrier against the simulator's TPM2 strategy")
	require.True(t, svc.IsUnsealed())

	backend := svc.GetBackend()
	require.NotNil(t, backend)
	require.NoError(t, backend.Put(ctx, "secrets/entry", []byte("sealed before the lock")))

	// The inactivity auto-lock.
	require.NoError(t, svc.Seal())
	require.False(t, svc.IsUnsealed())

	// The re-unlock: must reopen the same barrier in place, not rebuild one
	// and re-resolve the strategy against the simulator.
	err := svc.Unseal("", string(xkms.StrategyTPM2))
	require.NoError(t, err,
		"re-unseal after lock must reopen the TPM2 barrier in place against the simulator, got %v", err)
	require.True(t, svc.IsUnsealed())

	got, err := backend.Get(ctx, "secrets/entry")
	require.NoError(t, err, "the backend handed out before the lock must still read after the unlock")
	require.Equal(t, []byte("sealed before the lock"), got)
}
