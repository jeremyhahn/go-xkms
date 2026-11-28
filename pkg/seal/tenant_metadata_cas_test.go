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

package seal

import (
	"bytes"
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// casBackend is a tenant metadata store that offers go-qrdb's
// compare-and-swap; the rest of StorageBackend is never called.
type casBackend struct {
	qrdbsdk.StorageBackend
	value []byte
}

func (c *casBackend) CompareAndSwap(_ context.Context, _ string, expected, next []byte) (bool, error) {
	if !bytes.Equal(c.value, expected) {
		return false, nil
	}
	c.value = next
	return true, nil
}

// TestTenantMetadataStore_CompareAndSwap: go-qrdb v0.58.5's UpdateTenant
// refuses a metadata store without compare-and-swap
// (ErrTenantUpdateNotAtomic), so the wrapper must pass the barrier's
// through.
func TestTenantMetadataStore_CompareAndSwap(t *testing.T) {
	inner := &casBackend{value: []byte("v1")}
	var store any = tenantMetadataStore{inner}
	cas, ok := store.(interface {
		CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error)
	})
	if !ok {
		t.Fatal("tenantMetadataStore does not offer CompareAndSwap")
	}
	swapped, err := cas.CompareAndSwap(t.Context(), "tenant/a", []byte("stale"), []byte("v2"))
	if err != nil || swapped {
		t.Fatalf("swap against a stale read: swapped=%v err=%v, want false, nil", swapped, err)
	}
	swapped, err = cas.CompareAndSwap(t.Context(), "tenant/a", []byte("v1"), []byte("v2"))
	if err != nil || !swapped {
		t.Fatalf("swap against the current record: swapped=%v err=%v, want true, nil", swapped, err)
	}
	if string(inner.value) != "v2" {
		t.Fatalf("stored value %q, want v2", inner.value)
	}
}
