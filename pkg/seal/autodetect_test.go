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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// fakeTPMSealer stands in for a probed *tpm2backend.Backend so the autodetect
// policy can be tested without hardware. It records whether Close was called.
type fakeTPMSealer struct {
	canSeal bool
	closed  atomic.Bool
	block   chan struct{} // when non-nil, the open blocks until closed (timeout test)
}

func (f *fakeTPMSealer) CanSeal() bool { return f.canSeal }
func (f *fakeTPMSealer) Close() error  { f.closed.Store(true); return nil }
func (f *fakeTPMSealer) Seal(context.Context, []byte, *types.SealOptions) (*types.SealedData, error) {
	return &types.SealedData{}, nil
}
func (f *fakeTPMSealer) Unseal(context.Context, *types.SealedData, *types.UnsealOptions) ([]byte, error) {
	return nil, nil
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
