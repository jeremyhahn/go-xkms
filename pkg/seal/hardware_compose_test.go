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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStrategy is a minimal SealingStrategy used to exercise the
// hardware-composition helpers without real hardware. hardwareBacked controls
// whether NewHardwareStrategyRegistry registers it.
type fakeStrategy struct {
	id             StrategyID
	hardwareBacked bool
}

func (f *fakeStrategy) ID() StrategyID       { return f.id }
func (f *fakeStrategy) Available() bool      { return true }
func (f *fakeStrategy) HardwareBacked() bool { return f.hardwareBacked }

func (f *fakeStrategy) SealRootKey(context.Context, []byte, Credentials) (*SealedRootKey, error) {
	return &SealedRootKey{Strategy: f.id}, nil
}

func (f *fakeStrategy) UnsealRootKey(context.Context, *SealedRootKey, Credentials) ([]byte, error) {
	return []byte("root"), nil
}

func (f *fakeStrategy) BarrierEncryptor(context.Context, []byte) (SymmetricEncrypter, error) {
	return nil, nil
}

func (f *fakeStrategy) Close() error { return nil }

func TestNewHardwareStrategyRegistry_RegistersHardwareSkipsSoftware(t *testing.T) {
	hw := &fakeStrategy{id: StrategyTPM2, hardwareBacked: true}
	sw := &fakeStrategy{id: StrategyID("custom-software"), hardwareBacked: false}

	reg, err := NewHardwareStrategyRegistry(hw, sw, nil)
	require.NoError(t, err)
	require.NotNil(t, reg)

	// The hardware strategy is resolvable by ID.
	factory, err := reg.LookupFactory(StrategyTPM2)
	require.NoError(t, err)
	require.NotNil(t, factory)
	got, err := factory()
	require.NoError(t, err)
	assert.Equal(t, StrategyTPM2, got.ID())

	// The software strategy was skipped (only hardware-backed strategies are
	// registered; software/none come from the default registry).
	_, err = reg.LookupFactory(StrategyID("custom-software"))
	assert.Error(t, err)

	// The default registry still provides the built-in software strategies.
	assert.Contains(t, reg.ListAvailable(), StrategyTPM2)
}

func TestNewHardwareStrategyRegistry_DuplicateIDError(t *testing.T) {
	first := &fakeStrategy{id: StrategyTPM2, hardwareBacked: true}
	second := &fakeStrategy{id: StrategyTPM2, hardwareBacked: true}

	_, err := NewHardwareStrategyRegistry(first, second)
	assert.Error(t, err, "registering two strategies with the same ID must fail")
}

func TestNewHardwareTenantService_Success(t *testing.T) {
	store := newMemoryBackend()
	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, NewSoftwareStrategy())
	require.NoError(t, err)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	hw := &fakeStrategy{id: StrategyTPM2, hardwareBacked: true}
	svc, err := NewHardwareTenantService(barrier, registry, testLogger(), []SealingStrategy{hw})
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestNewHardwareTenantService_DuplicateStrategyError(t *testing.T) {
	store := newMemoryBackend()
	barrier, err := NewBarrier(testLogger(), store, BarrierConfig{
		RootKeyPath: "test/root-key",
	}, NewSoftwareStrategy())
	require.NoError(t, err)

	registry, err := NewBarrierRegistry(barrier)
	require.NoError(t, err)

	dup := []SealingStrategy{
		&fakeStrategy{id: StrategyTPM2, hardwareBacked: true},
		&fakeStrategy{id: StrategyTPM2, hardwareBacked: true},
	}
	_, err = NewHardwareTenantService(barrier, registry, testLogger(), dup)
	assert.Error(t, err, "duplicate hardware strategy IDs must propagate the registry error")
}
