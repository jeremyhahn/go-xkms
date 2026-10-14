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

package seal

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// fakeTPMSealer stands in for a probed *tpm2backend.Backend so the autodetect
// policy can be tested without hardware. It records whether Close was called
// and can be scripted to fail Close so go-xkms#876's "log, don't fail" close
// contract is testable without hardware.
type fakeTPMSealer struct {
	canSeal  bool
	closeErr error
	closed   atomic.Bool
}

func (f *fakeTPMSealer) CanSeal() bool { return f.canSeal }
func (f *fakeTPMSealer) Close() error {
	f.closed.Store(true)
	return f.closeErr
}
func (f *fakeTPMSealer) Seal(context.Context, []byte, *types.SealOptions) (*types.SealedData, error) {
	return &types.SealedData{}, nil
}
func (f *fakeTPMSealer) Unseal(context.Context, *types.SealedData, *types.UnsealOptions) ([]byte, error) {
	return nil, nil
}

// recordingHandler is a minimal slog.Handler that records every record
// passed to Handle, so a test can assert a specific message/level was
// logged without parsing formatted output.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) hasRecordContaining(level slog.Level, substr string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Level == level && strings.Contains(r.Message, substr) {
			return true
		}
	}
	return false
}

// withStubbedOpen swaps the package open seam for the duration of a test.
func withStubbedOpen(t *testing.T, fn func(*TPM2ProbeConfig) (tpm2Sealer, error)) {
	t.Helper()
	orig := openTPM2Backend
	openTPM2Backend = fn
	t.Cleanup(func() { openTPM2Backend = orig })
}

func probeCfg() AutodetectOptions {
	return AutodetectOptions{TPM2: &TPM2ProbeConfig{UseSimulator: true}}
}

func TestBuildBestStrategy_NoTPMConfig(t *testing.T) {
	res := BuildBestStrategy(AutodetectOptions{})
	assert.False(t, res.HardwareAvailable())
	assert.Nil(t, res.Strategy)
	require.NoError(t, res.Close())
}

func TestBuildBestStrategy_SealCapableTPMSelected(t *testing.T) {
	sealer := &fakeTPMSealer{canSeal: true}
	withStubbedOpen(t, func(*TPM2ProbeConfig) (tpm2Sealer, error) { return sealer, nil })

	res := BuildBestStrategy(probeCfg())
	require.True(t, res.HardwareAvailable())
	assert.Equal(t, StrategyTPM2, res.ID)
	require.NotNil(t, res.Strategy)
	require.NotNil(t, res.Sealer)

	// Closing the result releases the single TPM open.
	require.NoError(t, res.Close())
	assert.True(t, sealer.closed.Load())
}

func TestBuildBestStrategy_UnprovisionedFallsBack(t *testing.T) {
	withStubbedOpen(t, func(*TPM2ProbeConfig) (tpm2Sealer, error) {
		return nil, errTPM2NotInitialized
	})
	res := BuildBestStrategy(probeCfg())
	assert.False(t, res.HardwareAvailable())
}

func TestBuildBestStrategy_OpenErrorFallsBack(t *testing.T) {
	withStubbedOpen(t, func(*TPM2ProbeConfig) (tpm2Sealer, error) {
		return nil, errors.New("device busy")
	})
	res := BuildBestStrategy(probeCfg())
	assert.False(t, res.HardwareAvailable())
}

func TestBuildBestStrategy_NotSealCapableClosesAndFallsBack(t *testing.T) {
	sealer := &fakeTPMSealer{canSeal: false}
	withStubbedOpen(t, func(*TPM2ProbeConfig) (tpm2Sealer, error) { return sealer, nil })

	res := BuildBestStrategy(probeCfg())
	assert.False(t, res.HardwareAvailable())
	// A non-seal-capable open must be closed so the session does not leak.
	assert.True(t, sealer.closed.Load())
}

// TestBuildBestStrategy_NotSealCapableCloseFailure_LoggedNotFatal proves
// go-xkms#876's "log, don't fail" contract for the not-seal-capable close
// path: a Close failure on the discarded backend must not stop autodetect
// from falling back to software, and must be logged at debug rather than
// silently dropped.
func TestBuildBestStrategy_NotSealCapableCloseFailure_LoggedNotFatal(t *testing.T) {
	sealer := &fakeTPMSealer{canSeal: false, closeErr: errors.New("simulated close failure")}
	withStubbedOpen(t, func(*TPM2ProbeConfig) (tpm2Sealer, error) { return sealer, nil })

	handler := &recordingHandler{}
	opts := probeCfg()
	opts.Logger = slog.New(handler)

	res := BuildBestStrategy(opts)
	assert.False(t, res.HardwareAvailable())
	assert.True(t, sealer.closed.Load())
	assert.True(t, handler.hasRecordContaining(slog.LevelDebug, "failed to close a non-seal-capable TPM backend"))
}

func TestBuildBestStrategy_TimeoutFallsBack(t *testing.T) {
	release := make(chan struct{})
	sealer := &fakeTPMSealer{canSeal: true}
	withStubbedOpen(t, func(*TPM2ProbeConfig) (tpm2Sealer, error) {
		<-release // block past the probe timeout
		return sealer, nil
	})

	opts := probeCfg()
	opts.ProbeTimeout = 20 * time.Millisecond
	res := BuildBestStrategy(opts)
	assert.False(t, res.HardwareAvailable())

	// Releasing the late open lets the drain goroutine close it (no leak).
	close(release)
	assert.Eventually(t, func() bool { return sealer.closed.Load() }, time.Second, 5*time.Millisecond)
}

// TestBuildBestStrategy_TimeoutCloseFailure_LoggedNotFatal proves go-xkms#876's
// "log, don't fail" contract for the late-arriving-open drain path: a Close
// failure there must be logged at debug, and must not panic or block the
// drain goroutine.
func TestBuildBestStrategy_TimeoutCloseFailure_LoggedNotFatal(t *testing.T) {
	release := make(chan struct{})
	sealer := &fakeTPMSealer{canSeal: true, closeErr: errors.New("simulated close failure")}
	withStubbedOpen(t, func(*TPM2ProbeConfig) (tpm2Sealer, error) {
		<-release // block past the probe timeout
		return sealer, nil
	})

	handler := &recordingHandler{}
	opts := probeCfg()
	opts.ProbeTimeout = 20 * time.Millisecond
	opts.Logger = slog.New(handler)

	res := BuildBestStrategy(opts)
	assert.False(t, res.HardwareAvailable())

	close(release)
	assert.Eventually(t, func() bool { return sealer.closed.Load() }, time.Second, 5*time.Millisecond)
	assert.Eventually(t, func() bool {
		return handler.hasRecordContaining(slog.LevelDebug, "failed to close a late-arriving TPM open")
	}, time.Second, 5*time.Millisecond)
}

func TestOpenTPM2Strategy_SealCapableTPMSelected(t *testing.T) {
	sealer := &fakeTPMSealer{canSeal: true}
	withStubbedOpen(t, func(*TPM2ProbeConfig) (tpm2Sealer, error) { return sealer, nil })

	res, err := OpenTPM2Strategy(probeCfg())
	require.NoError(t, err)
	require.True(t, res.HardwareAvailable())
	assert.Equal(t, StrategyTPM2, res.ID)
	require.NoError(t, res.Close())
	assert.True(t, sealer.closed.Load())
}

func TestOpenTPM2Strategy_ReportsWhyNoTPMWasSelected(t *testing.T) {
	openErr := errors.New("device busy")
	tests := []struct {
		name    string
		sealer  tpm2Sealer
		openErr error
		want    error
	}{
		{name: "open error", openErr: openErr, want: openErr},
		{name: "unprovisioned", openErr: errTPM2NotInitialized, want: errTPM2NotInitialized},
		{name: "not seal-capable", sealer: &fakeTPMSealer{canSeal: false}, want: ErrTPM2NotSealCapable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withStubbedOpen(t, func(*TPM2ProbeConfig) (tpm2Sealer, error) { return tt.sealer, tt.openErr })

			res, err := OpenTPM2Strategy(probeCfg())
			assert.Nil(t, res)
			var probeErr *TPM2ProbeError
			require.ErrorAs(t, err, &probeErr)
			assert.ErrorIs(t, err, tt.want)
			assert.NotErrorIs(t, err, ErrTPM2ProbeTimeout)
		})
	}
}

// TestOpenTPM2Strategy_TimeoutIsDistinctFromAbsent pins go-xkms#1528: a TPM
// that is slow to open is reported as timed out, not as missing, and the
// late open is still released.
func TestOpenTPM2Strategy_TimeoutIsDistinctFromAbsent(t *testing.T) {
	release := make(chan struct{})
	sealer := &fakeTPMSealer{canSeal: true}
	withStubbedOpen(t, func(*TPM2ProbeConfig) (tpm2Sealer, error) {
		<-release // block past the probe timeout
		return sealer, nil
	})

	opts := probeCfg()
	opts.ProbeTimeout = 20 * time.Millisecond
	res, err := OpenTPM2Strategy(opts)
	assert.Nil(t, res)
	var probeErr *TPM2ProbeError
	require.ErrorAs(t, err, &probeErr)
	assert.ErrorIs(t, err, ErrTPM2ProbeTimeout)
	assert.Equal(t, "seal: tpm2 probe: seal: TPM open timed out", err.Error())

	close(release)
	assert.Eventually(t, func() bool { return sealer.closed.Load() }, time.Second, 5*time.Millisecond)
}

func TestProbeStrategies_ListsAvailable(t *testing.T) {
	// No TPM: software + none only.
	avail, res := ProbeStrategies(AutodetectOptions{})
	assert.Equal(t, []StrategyID{StrategyPassphrase, StrategyNone}, avail)
	require.NoError(t, res.Close())

	// TPM present: tpm2 leads the list.
	sealer := &fakeTPMSealer{canSeal: true}
	withStubbedOpen(t, func(*TPM2ProbeConfig) (tpm2Sealer, error) { return sealer, nil })
	avail, res = ProbeStrategies(probeCfg())
	require.NoError(t, res.Close())
	assert.Equal(t, []StrategyID{StrategyTPM2, StrategyPassphrase, StrategyNone}, avail)
}
