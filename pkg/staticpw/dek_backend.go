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

package staticpw

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/aesgcm"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// dekAADPrefix binds a personal entry's ciphertext to its storage key, so a
// value moved to another key (another user's, another entry's) does not
// decrypt.
const dekAADPrefix = "xkms/staticpw/personal/v1|"

// dekBackend is the storage.Backend a user's personal store writes through
// while the user's session is open: every value is sealed with the user's
// DEK (AES-256-GCM, the storage key as associated data) before it reaches the
// tenant barrier, and opened on the way back. Keys pass through unchanged.
//
// It does not own inner, which is the tenant barrier shared with the tenant's
// shared store: Close releases nothing but the DEK reference.
type dekBackend struct {
	inner storage.Backend
	dek   []byte
}

var _ storage.Backend = (*dekBackend)(nil)

// newDEKBackend returns inner sealed with dek. dek is borrowed, not copied:
// the session that owns it zeroes it when the session ends.
func newDEKBackend(inner storage.Backend, dek []byte) *dekBackend {
	return &dekBackend{inner: inner, dek: dek}
}

func (b *dekBackend) seal(key string, value []byte) ([]byte, error) {
	ct, err := aesgcm.EncryptWithAAD(b.dek, value, []byte(dekAADPrefix+key))
	if err != nil {
		return nil, &VaultCryptoError{Op: "seal entry", Err: err}
	}
	return ct, nil
}

func (b *dekBackend) open(key string, value []byte) ([]byte, error) {
	pt, err := aesgcm.DecryptWithAAD(b.dek, value, []byte(dekAADPrefix+key))
	if err != nil {
		return nil, &PersonalEntryDecryptError{Key: key, Err: err}
	}
	return pt, nil
}

// Get implements storage.Backend.
func (b *dekBackend) Get(ctx context.Context, key string) ([]byte, error) {
	value, err := b.inner.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	return b.open(key, value)
}

// Put implements storage.Backend.
func (b *dekBackend) Put(ctx context.Context, key string, value []byte) error {
	ct, err := b.seal(key, value)
	if err != nil {
		return err
	}
	return b.inner.Put(ctx, key, ct)
}

// PutIfAbsent implements storage.Backend.
func (b *dekBackend) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	ct, err := b.seal(key, value)
	if err != nil {
		return false, err
	}
	return b.inner.PutIfAbsent(ctx, key, ct)
}

// Delete implements storage.Backend.
func (b *dekBackend) Delete(ctx context.Context, key string) error {
	return b.inner.Delete(ctx, key)
}

// List implements storage.Backend.
func (b *dekBackend) List(ctx context.Context, prefix string) ([]string, error) {
	return b.inner.List(ctx, prefix)
}

// Scan implements storage.Backend, opening each value before fn sees it.
func (b *dekBackend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	return b.inner.Scan(ctx, prefix, func(key string, value []byte) error {
		pt, err := b.open(key, value)
		if err != nil {
			return err
		}
		return fn(key, pt)
	})
}

// Exists implements storage.Backend.
func (b *dekBackend) Exists(ctx context.Context, key string) (bool, error) {
	return b.inner.Exists(ctx, key)
}

// Close implements storage.Backend. The tenant barrier belongs to the
// tenant's shared store, so it is not closed here.
func (b *dekBackend) Close() error { return nil }

// PersonalEntryDecryptError reports a personal entry the user's DEK does not
// open: it was written under another key, or tampered with.
type PersonalEntryDecryptError struct {
	Key string
	Err error
}

// Error implements the error interface.
func (e *PersonalEntryDecryptError) Error() string {
	return "staticpw: personal entry " + e.Key + " does not open with the user's key: " + e.Err.Error()
}

// Unwrap returns the underlying failure.
func (e *PersonalEntryDecryptError) Unwrap() error { return e.Err }
