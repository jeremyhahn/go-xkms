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

package qrdb

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// Provider is a thin wrapper around Service that provides convenient
// access to KV operations and the underlying KVStore for DAO access.
type Provider interface {
	// KV returns a KVClient for data-plane key-value operations.
	KV() db.KVClient

	// KVStore returns a KVStore for DAO access. In embedded mode this
	// returns the direct KVStore; in remote mode it returns a KVClient
	// adapter that implements the KVStore interface.
	KVStore() qrdbsdk.KVStore

	// Close shuts down the underlying service.
	Close() error

	// Healthy reports whether the service is healthy.
	Healthy(ctx context.Context) bool
}

// provider implements Provider by wrapping a Service.
type provider struct {
	svc     Service
	kvStore qrdbsdk.KVStore
}

// NewProvider creates a Provider from a Service. If kvStore is nil,
// a KVStoreAdapter is created from the service's KVClient.
func NewProvider(svc Service, kvStore qrdbsdk.KVStore) Provider {
	if kvStore == nil {
		kvStore = NewKVStoreAdapter(svc.KV())
	}
	return &provider{
		svc:     svc,
		kvStore: kvStore,
	}
}

// KV returns a KVClient for data-plane key-value operations.
func (p *provider) KV() db.KVClient {
	return p.svc.KV()
}

// KVStore returns the KVStore for DAO access.
func (p *provider) KVStore() qrdbsdk.KVStore {
	return p.kvStore
}

// Close shuts down the underlying service.
func (p *provider) Close() error {
	return p.svc.Close()
}

// Healthy reports whether the service is healthy.
func (p *provider) Healthy(ctx context.Context) bool {
	return p.svc.Healthy(ctx)
}
