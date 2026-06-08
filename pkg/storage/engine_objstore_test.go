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
	"testing"
)

// TestOpenEngineObjstoreLocal verifies object storage is a first-class engine:
// a storage.Backend over the objstore "local" provider round-trips Put/Get/List,
// so the same DAOs persist to object storage as they do to file/pebble.
func TestOpenEngineObjstoreLocal(t *testing.T) {
	ctx := context.Background()
	b, err := OpenEngine(EngineConfig{Kind: EngineObjstore, Provider: "local", Options: map[string]string{"path": t.TempDir()}})
	if err != nil {
		t.Fatalf("OpenEngine(objstore/local): %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Put(ctx, "acme/accounts/1", []byte("acct")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got, err := b.Get(ctx, "acme/accounts/1"); err != nil || string(got) != "acct" {
		t.Fatalf("Get = %q, %v; want acct", got, err)
	}
	if keys, err := b.List(ctx, "acme/accounts/"); err != nil || len(keys) != 1 {
		t.Fatalf("List = %v, %v; want 1 key", keys, err)
	}
}

// TestOpenEngineObjstoreDefaultsProviderLocal verifies an empty provider
// defaults to the always-available "local" provider.
func TestOpenEngineObjstoreDefaultsProviderLocal(t *testing.T) {
	b, err := OpenEngine(EngineConfig{Kind: EngineObjstore, Options: map[string]string{"path": t.TempDir()}})
	if err != nil {
		t.Fatalf("OpenEngine(objstore, empty provider): %v", err)
	}
	_ = b.Close()
}
