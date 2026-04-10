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
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

// State constants for the atomic state field.
const (
	stateLocked   int32 = 0
	stateUnlocked int32 = 1
)

// Compile-time interface check.
var _ storage.Backend = (*Backend)(nil)

// Backend is a storage.Backend implementation backed by a LUKS encrypted
// volume. When the volume is unlocked, all operations are delegated to an
// underlying file-based storage backend whose root directory is the LUKS
// mount point. When the volume is locked, every storage operation returns
// ErrVolumeLocked.
//
// The state field uses sync/atomic for lock-free fast-path checks. The
// mutex protects only the delegate pointer assignment during Unlock/Lock
// transitions.
type Backend struct {
	volume   VolumeOperator
	delegate storage.Backend
	state    atomic.Int32
	mu       sync.Mutex
}

// NewBackend creates a new LUKS storage backend wrapping the given volume.
// The backend starts in the locked state; call Unlock or Initialize before
// performing storage operations.
func NewBackend(volume VolumeOperator) *Backend {
	return &Backend{
		volume: volume,
	}
}

// Initialize creates a new LUKS volume, unlocks it, and prepares the
// delegate file storage backend on the mount point.
func (b *Backend) Initialize(sizeBytes int64, passphrase string) error {
	if passphrase == "" {
		return ErrInitializeRequiresPassphrase
	}

	if err := b.volume.Create(sizeBytes, passphrase); err != nil {
		return err
	}

	return b.Unlock(passphrase)
}

// Unlock opens the LUKS volume and creates a file storage delegate on
// the mount point. Returns ErrVolumeAlreadyUnlocked if the backend is
// already in the unlocked state.
func (b *Backend) Unlock(passphrase string) error {
	if b.state.Load() == stateUnlocked {
		return ErrVolumeAlreadyUnlocked
	}

	if !b.volume.Exists() {
		return ErrVolumeNotInitialized
	}

	if err := b.volume.Unlock(passphrase); err != nil {
		return err
	}

	delegate, err := filestorage.New(b.volume.GetMountPoint())
	if err != nil {
		// Best-effort rollback: lock the volume again since we cannot
		// create the delegate storage.
		b.volume.Lock() //nolint:errcheck
		return ErrDelegateCreateFailed
	}

	b.mu.Lock()
	b.delegate = delegate
	b.mu.Unlock()

	b.state.Store(stateUnlocked)
	return nil
}

// Lock closes the delegate backend and locks the LUKS volume.
// Returns ErrVolumeLocked if the backend is already locked.
func (b *Backend) Lock() error {
	if b.state.Load() == stateLocked {
		return ErrVolumeLocked
	}

	b.state.Store(stateLocked)

	b.mu.Lock()
	delegate := b.delegate
	b.delegate = nil
	b.mu.Unlock()

	if delegate != nil {
		delegate.Close() //nolint:errcheck
	}

	if err := b.volume.Lock(); err != nil {
		return ErrVolumeLockFailed
	}

	return nil
}

// IsUnlocked reports whether the backend is in the unlocked state.
func (b *Backend) IsUnlocked() bool {
	return b.state.Load() == stateUnlocked
}

// Get retrieves the value for the given key from the delegate backend.
// Returns ErrVolumeLocked if the volume is not unlocked.
func (b *Backend) Get(ctx context.Context, key string) ([]byte, error) {
	delegate, err := b.getDelegate()
	if err != nil {
		return nil, err
	}
	return delegate.Get(ctx, key)
}

// Put stores the value for the given key in the delegate backend.
// Returns ErrVolumeLocked if the volume is not unlocked.
func (b *Backend) Put(ctx context.Context, key string, value []byte) error {
	delegate, err := b.getDelegate()
	if err != nil {
		return err
	}
	return delegate.Put(ctx, key, value)
}

// Delete removes the key from the delegate backend.
// Returns ErrVolumeLocked if the volume is not unlocked.
func (b *Backend) Delete(ctx context.Context, key string) error {
	delegate, err := b.getDelegate()
	if err != nil {
		return err
	}
	return delegate.Delete(ctx, key)
}

// List returns all keys matching the prefix from the delegate backend.
// Returns ErrVolumeLocked if the volume is not unlocked.
func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	delegate, err := b.getDelegate()
	if err != nil {
		return nil, err
	}
	return delegate.List(ctx, prefix)
}

// Scan iterates over all key-value pairs matching the prefix from the delegate backend.
// Returns ErrVolumeLocked if the volume is not unlocked.
func (b *Backend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	delegate, err := b.getDelegate()
	if err != nil {
		return err
	}
	return delegate.Scan(ctx, prefix, fn)
}

// Exists checks whether the key exists in the delegate backend.
// Returns ErrVolumeLocked if the volume is not unlocked.
func (b *Backend) Exists(ctx context.Context, key string) (bool, error) {
	delegate, err := b.getDelegate()
	if err != nil {
		return false, err
	}
	return delegate.Exists(ctx, key)
}

// Close locks the volume if it is currently unlocked, releasing all
// resources. If the volume is already locked this is a no-op.
func (b *Backend) Close() error {
	if b.state.Load() == stateLocked {
		return nil
	}
	return b.Lock()
}

// getDelegate returns the current delegate backend, or ErrVolumeLocked
// if the backend is in the locked state.
func (b *Backend) getDelegate() (storage.Backend, error) {
	if b.state.Load() == stateLocked {
		return nil, ErrVolumeLocked
	}

	b.mu.Lock()
	delegate := b.delegate
	b.mu.Unlock()

	if delegate == nil {
		return nil, ErrVolumeLocked
	}

	return delegate, nil
}
