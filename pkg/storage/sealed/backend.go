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

// Package sealed provides a storage backend decorator that transparently
// encrypts and decrypts values using a types.Sealer before delegating
// to an underlying storage.Backend. Keys (paths) are stored in the clear;
// only values are sealed.
package sealed

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Backend wraps a storage.Backend and encrypts all values using a types.Sealer.
// Keys (paths) are stored as-is; values are sealed before Put and unsealed on Get.
type Backend struct {
	inner    storage.Backend
	sealer   types.Sealer
	sealOpts *types.SealOptions
}

// New creates a new sealed storage Backend.
// The inner backend is used for actual persistence, while the sealer handles
// encryption and decryption of values. The sealOpts parameter may be nil to
// use the sealer's default options.
func New(inner storage.Backend, sealer types.Sealer, sealOpts *types.SealOptions) (*Backend, error) {
	if inner == nil {
		return nil, fmt.Errorf("%w: inner backend is nil", ErrSealerNotAvailable)
	}
	if sealer == nil {
		return nil, fmt.Errorf("%w: sealer is nil", ErrSealerNotAvailable)
	}
	if !sealer.CanSeal() {
		return nil, ErrSealerNotAvailable
	}
	return &Backend{
		inner:    inner,
		sealer:   sealer,
		sealOpts: sealOpts,
	}, nil
}

// Get retrieves a value from the inner backend, deserializes the sealed
// envelope, and returns the unsealed plaintext.
func (b *Backend) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := b.inner.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	var sealed types.SealedData
	if err := json.Unmarshal(data, &sealed); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnmarshalFailed, err)
	}

	plaintext, err := b.sealer.Unseal(ctx, &sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsealFailed, err)
	}

	return plaintext, nil
}

// Put seals the value and stores the resulting sealed data envelope
// (serialized as JSON) in the inner backend.
func (b *Backend) Put(ctx context.Context, key string, value []byte) error {
	sealed, err := b.sealer.Seal(ctx, value, b.sealOpts)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSealFailed, err)
	}

	data, err := json.Marshal(sealed)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMarshalFailed, err)
	}

	return b.inner.Put(ctx, key, data)
}

// Delete delegates to the inner backend.
func (b *Backend) Delete(ctx context.Context, key string) error {
	return b.inner.Delete(ctx, key)
}

// List delegates to the inner backend. Keys are not encrypted.
func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	return b.inner.List(ctx, prefix)
}

// Scan iterates over all key-value pairs matching the given prefix,
// unsealing each value before passing it to fn. Return a non-nil error
// from fn to stop iteration early.
func (b *Backend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	return b.inner.Scan(ctx, prefix, func(key string, data []byte) error {
		var sealed types.SealedData
		if err := json.Unmarshal(data, &sealed); err != nil {
			return fmt.Errorf("%w: %w", ErrUnmarshalFailed, err)
		}

		plaintext, err := b.sealer.Unseal(ctx, &sealed, nil)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUnsealFailed, err)
		}

		return fn(key, plaintext)
	})
}

// Exists delegates to the inner backend.
func (b *Backend) Exists(ctx context.Context, key string) (bool, error) {
	return b.inner.Exists(ctx, key)
}

// Close delegates to the inner backend.
func (b *Backend) Close() error {
	return b.inner.Close()
}

// Verify compile-time interface compliance.
var _ storage.Backend = (*Backend)(nil)
