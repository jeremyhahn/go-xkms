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

package storage

import (
	"context"
	"errors"
	"strings"
)

// ErrEmptyPrefix is returned when a PrefixBackend is created with an empty prefix.
var ErrEmptyPrefix = errors.New("storage: prefix must not be empty")

// PrefixBackend wraps a storage.Backend and transparently prepends a prefix
// to all keys. This provides namespace isolation so that multiple consumers
// can share a single underlying backend without key collisions.
//
// List and Scan results have the prefix stripped so callers see keys exactly
// as they stored them. Close is a no-op; the underlying backend's lifecycle
// is managed by the owner that created it.
type PrefixBackend struct {
	inner  Backend
	prefix string
}

// Compile-time interface compliance check.
var _ Backend = (*PrefixBackend)(nil)

// NewPrefixBackend creates a PrefixBackend that prepends prefix to every key.
// The prefix should include a trailing separator (e.g. "backends/tpm2/") so
// that keys are stored in a clean namespace.
//
// Returns ErrEmptyPrefix if prefix is empty or ErrInvalidData if inner is nil.
func NewPrefixBackend(inner Backend, prefix string) (*PrefixBackend, error) {
	if inner == nil {
		return nil, ErrInvalidData
	}
	if prefix == "" {
		return nil, ErrEmptyPrefix
	}
	return &PrefixBackend{
		inner:  inner,
		prefix: prefix,
	}, nil
}

// Get retrieves the value for the prefixed key.
func (p *PrefixBackend) Get(ctx context.Context, key string) ([]byte, error) {
	return p.inner.Get(ctx, p.prefix+key)
}

// Put stores the value under the prefixed key.
func (p *PrefixBackend) Put(ctx context.Context, key string, value []byte) error {
	return p.inner.Put(ctx, p.prefix+key, value)
}

// Delete removes the prefixed key.
func (p *PrefixBackend) Delete(ctx context.Context, key string) error {
	return p.inner.Delete(ctx, p.prefix+key)
}

// List returns keys matching the prefixed version of prefix, with the
// PrefixBackend's own prefix stripped from each result.
func (p *PrefixBackend) List(ctx context.Context, prefix string) ([]string, error) {
	keys, err := p.inner.List(ctx, p.prefix+prefix)
	if err != nil {
		return nil, err
	}
	stripped := make([]string, 0, len(keys))
	for _, k := range keys {
		stripped = append(stripped, strings.TrimPrefix(k, p.prefix))
	}
	return stripped, nil
}

// Scan iterates over key-value pairs matching the prefixed version of prefix,
// with the PrefixBackend's own prefix stripped from each key passed to fn.
func (p *PrefixBackend) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	return p.inner.Scan(ctx, p.prefix+prefix, func(key string, value []byte) error {
		return fn(strings.TrimPrefix(key, p.prefix), value)
	})
}

// Exists checks if the prefixed key exists.
func (p *PrefixBackend) Exists(ctx context.Context, key string) (bool, error) {
	return p.inner.Exists(ctx, p.prefix+key)
}

// Close is a no-op. The underlying backend's lifecycle is managed by its owner.
func (p *PrefixBackend) Close() error {
	return nil
}

// Prefix returns the prefix used by this backend.
func (p *PrefixBackend) Prefix() string {
	return p.prefix
}
