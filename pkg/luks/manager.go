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

package luks

import (
	"context"
	"fmt"
	"sync/atomic"
)

// Executor performs the actual LUKS volume operations. Production
// implementations call cryptsetup, dmsetup, and mount; test code supplies
// lightweight mocks.
type Executor interface {
	// Create formats a new LUKS container at the path in config with the
	// given size and passphrase.
	Create(ctx context.Context, config *VolumeConfig, sizeBytes int64, passphrase string) error

	// Unlock opens an existing LUKS container with the given passphrase
	// and maps it to the device mapper name in config.
	Unlock(ctx context.Context, config *VolumeConfig, passphrase string) error

	// Lock closes the mapped LUKS device.
	Lock(ctx context.Context, config *VolumeConfig) error

	// IsMounted reports whether the volume is currently mounted at the
	// configured mount point.
	IsMounted(config *VolumeConfig) bool

	// IsUnlocked reports whether the LUKS device mapper entry exists.
	IsUnlocked(config *VolumeConfig) bool
}

// Manager coordinates the lifecycle of a single LUKS encrypted volume,
// tracking mount and unlock state with lock-free atomics.
type Manager struct {
	config   *VolumeConfig
	executor Executor
	mounted  atomic.Bool
	unlocked atomic.Bool
}

// NewManager creates a Manager after applying defaults and validating the
// configuration. It returns ErrNilExecutor when executor is nil and
// propagates any validation error from VolumeConfig.Validate.
func NewManager(config *VolumeConfig, executor Executor) (*Manager, error) {
	if executor == nil {
		return nil, ErrNilExecutor
	}
	config.SetDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Manager{
		config:   config,
		executor: executor,
	}, nil
}

// NewFIPSAwareManager is a convenience constructor that builds a
// VolumeConfig from the given paths and delegates to NewManager. The KDF
// is automatically chosen based on the runtime FIPS policy.
func NewFIPSAwareManager(luksPath, mountPoint, mapperName string, executor Executor) (*Manager, error) {
	cfg := &VolumeConfig{
		LUKSPath:   luksPath,
		MountPoint: mountPoint,
		MapperName: mapperName,
	}
	return NewManager(cfg, executor)
}

// Create formats a new LUKS container with the given size and passphrase.
// It validates sizeBytes and passphrase before delegating to the Executor.
func (m *Manager) Create(ctx context.Context, sizeBytes int64, passphrase string) error {
	if sizeBytes <= 0 {
		return ErrInvalidSize
	}
	if passphrase == "" {
		return ErrEmptyPassphrase
	}
	if err := m.executor.Create(ctx, m.config, sizeBytes, passphrase); err != nil {
		return fmt.Errorf("%w: %w", ErrOperationFailed, err)
	}
	return nil
}

// Unlock opens the LUKS container with the given passphrase and updates
// internal state. It validates the passphrase before delegating.
func (m *Manager) Unlock(ctx context.Context, passphrase string) error {
	if passphrase == "" {
		return ErrEmptyPassphrase
	}
	if err := m.executor.Unlock(ctx, m.config, passphrase); err != nil {
		return fmt.Errorf("%w: %w", ErrOperationFailed, err)
	}
	m.unlocked.Store(true)
	return nil
}

// Lock closes the LUKS device mapper entry and updates internal state.
func (m *Manager) Lock(ctx context.Context) error {
	if err := m.executor.Lock(ctx, m.config); err != nil {
		return fmt.Errorf("%w: %w", ErrOperationFailed, err)
	}
	m.unlocked.Store(false)
	m.mounted.Store(false)
	return nil
}

// IsMounted reports whether the volume is currently mounted according to
// internal state tracking.
func (m *Manager) IsMounted() bool {
	return m.mounted.Load()
}

// IsUnlocked reports whether the volume is currently unlocked according to
// internal state tracking.
func (m *Manager) IsUnlocked() bool {
	return m.unlocked.Load()
}

// Config returns a copy of the volume configuration.
func (m *Manager) Config() VolumeConfig {
	return *m.config
}
