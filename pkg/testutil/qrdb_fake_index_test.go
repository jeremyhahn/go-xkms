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

package testutil

import (
	"bytes"
	"context"
	"errors"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// TestQRDBFakeClientKVStoreServesKeyedCRUD proves Client.KVStore() works over
// the fake: the SDK's KVStore needs the transport's index capability to be
// present, and keyed reads and writes go through to the fake's KV map.
func TestQRDBFakeClientKVStoreServesKeyedCRUD(t *testing.T) {
	ctx := context.Background()
	client, ft, err := NewQRDBFakeClient()
	if err != nil {
		t.Fatalf("NewQRDBFakeClient: %v", err)
	}

	store := client.KVStore()
	if err := store.Put(ctx, "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	raw, err := ft.Get(ctx, "k")
	if err != nil {
		t.Fatalf("fake Get: %v", err)
	}
	if !bytes.Equal(raw, []byte("v")) {
		t.Fatalf("fake holds %q, want %q", raw, "v")
	}
}

// TestQRDBFakeRefusesIndexes proves every index verb reports the capability
// as unsupported -- the error the SDK's KVStore turns into
// ErrIndexUnsupported -- rather than answering a lookup with an empty result.
func TestQRDBFakeRefusesIndexes(t *testing.T) {
	ctx := context.Background()
	ft := NewQRDBFakeTransport()

	_, queryErr := ft.IndexQuery(ctx, "notes.title", "x")
	_, scanErr := ft.IndexScan(ctx, "notes.title", nil, nil)
	_, listErr := ft.IndexList(ctx)
	verbs := map[string]error{
		"IndexCreate": ft.IndexCreate(ctx, "notes.title", "title", qrdbtransport.IndexConfig{}),
		"IndexDrop":   ft.IndexDrop(ctx, "notes.title"),
		"IndexQuery":  queryErr,
		"IndexScan":   scanErr,
		"IndexList":   listErr,
	}
	for verb, err := range verbs {
		var unsupported *qrdbtransport.CapabilityUnsupportedError
		if !errors.As(err, &unsupported) {
			t.Errorf("%s error = %v, want CapabilityUnsupportedError", verb, err)
		}
	}
}
