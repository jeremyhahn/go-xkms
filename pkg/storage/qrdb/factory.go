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

	sdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/embedded"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// NewMemory creates an embedded in-memory backend. The entire QRDB stack
// (storage, state machine, services, transport, and SDK client) is
// initialized in-process. Close() tears down all resources.
func NewMemory() (*Backend, error) {
	store := qrdbsdk.NewMemoryStorage()
	return newEmbedded(store, "memory")
}

// NewFile creates an embedded file-based backend at the given path. Each
// key-value pair is stored as a separate file under the directory. The
// entire QRDB stack is initialized in-process. Close() tears down all
// resources.
func NewFile(path string) (*Backend, error) {
	store, err := qrdbsdk.NewFileStorage(path)
	if err != nil {
		return nil, &FactoryError{Engine: "file", Err: err}
	}
	return newEmbedded(store, "file")
}

// NewPebble creates an embedded PebbleDB backend at the given path. Uses
// a test-optimized PebbleDB configuration suitable for lightweight embedded
// usage. The entire QRDB stack is initialized in-process. Close() tears
// down all resources.
func NewPebble(path string) (*Backend, error) {
	cfg := qrdbsdk.TestPebbleConfig(path)
	store, err := qrdbsdk.NewPebbleStorage(cfg)
	if err != nil {
		return nil, &FactoryError{Engine: "pebble", Err: err}
	}
	return newEmbedded(store, "pebble")
}

// newEmbedded builds the full QRDB embedded stack from a storage engine:
//
//	Storage -> FastStateMachine -> LocalBackend -> KVService + AdminService
//	-> embedded.Transport -> sdk.Client -> Backend
//
// FastStateMachine is used instead of SimpleStateMachine because it
// supports PrefixQuery lookups required by the Scan operation.
//
// The returned Backend owns the SDK client lifecycle; Close() tears down
// the client, which in turn closes the transport.
func newEmbedded(store qrdbsdk.Storage, engine string) (*Backend, error) {
	fsm := qrdbsdk.NewFastStateMachine(1, 1, store)
	host := qrdbsdk.NewLocalBackend(fsm)
	kvSvc := qrdbsdk.NewKVService(host, 1)
	adminSvc := qrdbsdk.NewAdminService(host)

	t, err := embedded.New(kvSvc, adminSvc)
	if err != nil {
		return nil, &FactoryError{Engine: engine, Err: err}
	}

	client, err := sdk.NewClient(t)
	if err != nil {
		return nil, &FactoryError{Engine: engine, Err: err}
	}

	if err := client.Connect(context.Background()); err != nil {
		return nil, &FactoryError{Engine: engine, Err: err}
	}

	return newOwnedBackend(client.KV(), client), nil
}
