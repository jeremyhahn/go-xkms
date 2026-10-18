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

package server

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// sharedStorageView is the shared datastore resolved at call time rather
// than at construction. A hardware backend opened before the qrdb node
// (the node transport key's PKCS#11 token) keeps its metadata behind the
// barrier like every other backend: its store is this view, which serves
// from the shared datastore once initializeQRDBStorage opens it and
// refuses with ErrSharedStorageUnbound before then.
type sharedStorageView struct {
	s *Server
}

var _ storage.Backend = sharedStorageView{}

func (v sharedStorageView) backend() (storage.Backend, error) {
	backend := v.s.sharedStorage()
	if backend == nil {
		return nil, ErrSharedStorageUnbound
	}
	return backend, nil
}

func (v sharedStorageView) Get(ctx context.Context, key string) ([]byte, error) {
	backend, err := v.backend()
	if err != nil {
		return nil, err
	}
	return backend.Get(ctx, key)
}

func (v sharedStorageView) Put(ctx context.Context, key string, value []byte) error {
	backend, err := v.backend()
	if err != nil {
		return err
	}
	return backend.Put(ctx, key, value)
}

func (v sharedStorageView) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	backend, err := v.backend()
	if err != nil {
		return false, err
	}
	return backend.PutIfAbsent(ctx, key, value)
}

func (v sharedStorageView) Delete(ctx context.Context, key string) error {
	backend, err := v.backend()
	if err != nil {
		return err
	}
	return backend.Delete(ctx, key)
}

func (v sharedStorageView) List(ctx context.Context, prefix string) ([]string, error) {
	backend, err := v.backend()
	if err != nil {
		return nil, err
	}
	return backend.List(ctx, prefix)
}

func (v sharedStorageView) Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error {
	backend, err := v.backend()
	if err != nil {
		return err
	}
	return backend.Scan(ctx, prefix, fn)
}

func (v sharedStorageView) Exists(ctx context.Context, key string) (bool, error) {
	backend, err := v.backend()
	if err != nil {
		return false, err
	}
	return backend.Exists(ctx, key)
}

// Close is a no-op: the shared datastore's lifecycle belongs to the server.
func (v sharedStorageView) Close() error {
	return nil
}
