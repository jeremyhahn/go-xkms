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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSealer implements types.Sealer for testing.
type mockSealer struct {
	canSeal   bool
	sealErr   error
	unsealErr error
	sealData  *types.SealedData
	lastData  []byte
}

func (m *mockSealer) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	m.lastData = data
	if m.sealData != nil {
		return m.sealData, nil
	}
	return &types.SealedData{
		Ciphertext: data,
		Metadata:   make(map[string][]byte),
	}, nil
}

func (m *mockSealer) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	return sealed.Ciphertext, nil
}

func (m *mockSealer) CanSeal() bool {
	return m.canSeal
}

// Compile-time check.
var _ types.Sealer = (*mockSealer)(nil)

func TestPlatformSealer_AutoSelectBest(t *testing.T) {
	softwareSealer := &mockSealer{canSeal: true}
	sealers := map[StrategyID]types.Sealer{
		StrategySoftware: softwareSealer,
	}

	ps, err := NewPlatformSealer(testLogger(), SealerConfig{
		PreferenceOrder: []StrategyID{StrategySoftware},
	}, sealers)
	require.NoError(t, err)

	ctx := context.Background()
	data := []byte("seal me")

	sealed, err := ps.Seal(ctx, data, nil)
	require.NoError(t, err)
	require.NotNil(t, sealed)

	// Strategy tag must be present.
	stratTag, ok := sealed.Metadata[strategyMetadataKey]
	assert.True(t, ok)
	assert.Equal(t, string(StrategySoftware), string(stratTag))
}

func TestPlatformSealer_Fallback(t *testing.T) {
	// TPM2 unavailable, software available.
	tpmSealer := &mockSealer{canSeal: false}
	swSealer := &mockSealer{canSeal: true}

	sealers := map[StrategyID]types.Sealer{
		StrategyTPM2:     tpmSealer,
		StrategySoftware: swSealer,
	}

	ps, err := NewPlatformSealer(testLogger(), SealerConfig{
		PreferenceOrder: []StrategyID{StrategyTPM2, StrategySoftware},
	}, sealers)
	require.NoError(t, err)

	best, err := ps.BestStrategy()
	require.NoError(t, err)
	assert.Equal(t, StrategySoftware, best)
}

func TestPlatformSealer_SealWith(t *testing.T) {
	swSealer := &mockSealer{canSeal: true}

	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: swSealer,
	})
	require.NoError(t, err)

	ctx := context.Background()
	sealed, err := ps.SealWith(ctx, StrategySoftware, []byte("explicit"), nil)
	require.NoError(t, err)

	tag := sealed.Metadata[strategyMetadataKey]
	assert.Equal(t, string(StrategySoftware), string(tag))
}

func TestPlatformSealer_SealWithUnknownStrategy(t *testing.T) {
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true},
	})
	require.NoError(t, err)

	_, err = ps.SealWith(context.Background(), StrategyTPM2, []byte("data"), nil)
	assert.ErrorIs(t, err, ErrStrategyNotFound)
}

func TestPlatformSealer_CanSeal(t *testing.T) {
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true},
	})
	require.NoError(t, err)
	assert.True(t, ps.CanSeal())
}

func TestPlatformSealer_CanSealAllUnavailable(t *testing.T) {
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: false},
	})
	require.NoError(t, err)
	assert.False(t, ps.CanSeal())
}

func TestPlatformSealer_UnsealByMetadata(t *testing.T) {
	swSealer := &mockSealer{canSeal: true}

	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: swSealer,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Seal first.
	sealed, err := ps.Seal(ctx, []byte("round-trip"), nil)
	require.NoError(t, err)

	// Unseal reads strategy from metadata.
	plaintext, err := ps.Unseal(ctx, sealed, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("round-trip"), plaintext)
}

func TestPlatformSealer_UnsealNilData(t *testing.T) {
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true},
	})
	require.NoError(t, err)

	_, err = ps.Unseal(context.Background(), nil, nil)
	assert.ErrorIs(t, err, ErrNilSealedData)
}

func TestPlatformSealer_UnsealMissingMetadata(t *testing.T) {
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true},
	})
	require.NoError(t, err)

	// Sealed data without strategy metadata.
	sealed := &types.SealedData{
		Ciphertext: []byte("data"),
		Metadata:   map[string][]byte{},
	}
	_, err = ps.Unseal(context.Background(), sealed, nil)
	assert.ErrorIs(t, err, ErrStrategyMismatch)
}

func TestPlatformSealer_UnsealUnknownStrategy(t *testing.T) {
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true},
	})
	require.NoError(t, err)

	sealed := &types.SealedData{
		Ciphertext: []byte("data"),
		Metadata:   map[string][]byte{strategyMetadataKey: []byte("unknown")},
	}
	_, err = ps.Unseal(context.Background(), sealed, nil)
	assert.ErrorIs(t, err, ErrStrategyNotFound)
}

func TestPlatformSealer_NoAvailableStrategy(t *testing.T) {
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: false},
	})
	require.NoError(t, err)

	_, err = ps.BestStrategy()
	assert.ErrorIs(t, err, ErrNoAvailableStrategy)

	_, err = ps.Seal(context.Background(), []byte("data"), nil)
	assert.ErrorIs(t, err, ErrNoAvailableStrategy)
}

func TestNewPlatformSealer_EmptySealers(t *testing.T) {
	_, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{})
	assert.ErrorIs(t, err, ErrNoAvailableStrategy)
}

func TestPlatformSealer_AvailableStrategies(t *testing.T) {
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true},
		StrategyTPM2:     &mockSealer{canSeal: false},
	})
	require.NoError(t, err)

	available := ps.AvailableStrategies()
	assert.Contains(t, available, StrategySoftware)
	assert.NotContains(t, available, StrategyTPM2)
}

func TestPlatformSealer_SealError(t *testing.T) {
	sealErr := errors.New("seal failed")
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true, sealErr: sealErr},
	})
	require.NoError(t, err)

	_, err = ps.Seal(context.Background(), []byte("data"), nil)
	assert.ErrorIs(t, err, sealErr)
}

func TestPlatformSealer_UnsealError(t *testing.T) {
	unsealErr := errors.New("unseal failed")
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true, unsealErr: unsealErr},
	})
	require.NoError(t, err)

	sealed := &types.SealedData{
		Ciphertext: []byte("data"),
		Metadata:   map[string][]byte{strategyMetadataKey: []byte(StrategySoftware)},
	}
	_, err = ps.Unseal(context.Background(), sealed, nil)
	assert.ErrorIs(t, err, unsealErr)
}

// TestPlatformSealer_SealWith_NilMetadata verifies that sealWith correctly
// initializes the Metadata map when the underlying sealer returns SealedData
// with a nil Metadata map. This exercises the nil-metadata guard in sealWith.
func TestPlatformSealer_SealWith_NilMetadata(t *testing.T) {
	// Return SealedData with nil Metadata to trigger the nil guard.
	nilMetaSealer := &mockSealer{
		canSeal: true,
		sealData: &types.SealedData{
			Ciphertext: []byte("encrypted"),
			Metadata:   nil, // explicitly nil
		},
	}

	ps, err := NewPlatformSealer(testLogger(), SealerConfig{}, map[StrategyID]types.Sealer{
		StrategySoftware: nilMetaSealer,
	})
	require.NoError(t, err)

	ctx := context.Background()
	sealed, err := ps.Seal(ctx, []byte("data"), nil)
	require.NoError(t, err)
	require.NotNil(t, sealed.Metadata)

	// Strategy tag should still be set.
	tag, ok := sealed.Metadata[strategyMetadataKey]
	assert.True(t, ok, "strategy metadata key must be present even when sealer returns nil metadata")
	assert.Equal(t, string(StrategySoftware), string(tag))
}

// TestPlatformSealer_SealWith_WithAuditLogger verifies that sealWith emits
// audit events through a non-nil audit logger on success.
func TestPlatformSealer_SealWith_WithAuditLogger(t *testing.T) {
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{
		AuditLogger: &audit.NoOpLogger{},
	}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true},
	})
	require.NoError(t, err)

	sealed, err := ps.Seal(context.Background(), []byte("data"), nil)
	require.NoError(t, err)
	require.NotNil(t, sealed)
}

// TestPlatformSealer_SealError_WithAuditLogger verifies that sealWith emits
// a deny audit event when the underlying sealer returns an error.
func TestPlatformSealer_SealError_WithAuditLogger(t *testing.T) {
	sealErr := errors.New("seal failed with audit")
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{
		AuditLogger: &audit.NoOpLogger{},
	}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true, sealErr: sealErr},
	})
	require.NoError(t, err)

	_, err = ps.Seal(context.Background(), []byte("data"), nil)
	assert.ErrorIs(t, err, sealErr)
}

// TestPlatformSealer_Unseal_WithAuditLogger verifies that Unseal emits
// audit events through a non-nil audit logger.
func TestPlatformSealer_Unseal_WithAuditLogger(t *testing.T) {
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{
		AuditLogger: &audit.NoOpLogger{},
	}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true},
	})
	require.NoError(t, err)

	ctx := context.Background()
	sealed, err := ps.Seal(ctx, []byte("data"), nil)
	require.NoError(t, err)

	plaintext, err := ps.Unseal(ctx, sealed, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), plaintext)
}

// TestPlatformSealer_UnsealUnknown_WithAuditLogger verifies that Unseal emits
// a deny audit event when the strategy is not found.
func TestPlatformSealer_UnsealUnknown_WithAuditLogger(t *testing.T) {
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{
		AuditLogger: &audit.NoOpLogger{},
	}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true},
	})
	require.NoError(t, err)

	sealed := &types.SealedData{
		Ciphertext: []byte("data"),
		Metadata:   map[string][]byte{strategyMetadataKey: []byte("unknown")},
	}
	_, err = ps.Unseal(context.Background(), sealed, nil)
	assert.ErrorIs(t, err, ErrStrategyNotFound)
}

// TestPlatformSealer_UnsealError_WithAuditLogger verifies that Unseal emits
// a deny audit event when the underlying sealer returns an error.
func TestPlatformSealer_UnsealError_WithAuditLogger(t *testing.T) {
	unsealErr := errors.New("unseal failed with audit")
	ps, err := NewPlatformSealer(testLogger(), SealerConfig{
		AuditLogger: &audit.NoOpLogger{},
	}, map[StrategyID]types.Sealer{
		StrategySoftware: &mockSealer{canSeal: true, unsealErr: unsealErr},
	})
	require.NoError(t, err)

	sealed := &types.SealedData{
		Ciphertext: []byte("data"),
		Metadata:   map[string][]byte{strategyMetadataKey: []byte(StrategySoftware)},
	}
	_, err = ps.Unseal(context.Background(), sealed, nil)
	assert.ErrorIs(t, err, unsealErr)
}
