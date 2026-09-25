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

package symmetric

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// wrappedNotFoundStorage is a storage.Backend double whose Delete wraps
// storage.ErrNotFound with call-site context (fmt.Errorf's %w), the shape
// a real backend produces when it adds detail to the sentinel.
type wrappedNotFoundStorage struct {
	storage.Backend
}

func (w *wrappedNotFoundStorage) Delete(_ context.Context, key string) error {
	return fmt.Errorf("delete %s: %w", key, storage.ErrNotFound)
}

// TestDeleteKey_NotFound_Wrapped is go-xkms#894's regression case: DeleteKey
// compares the storage error with errors.Is, so a storage backend that
// wraps storage.ErrNotFound must still classify as backend.ErrKeyNotFound,
// not the generic "failed to delete key" a bare == comparison would take.
func TestDeleteKey_NotFound_Wrapped(t *testing.T) {
	config := &Config{KeyStorage: &wrappedNotFoundStorage{Backend: storage.New()}}
	b, err := NewBackend(config)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "test-deletekey-wrapped-notfound.com",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_SW,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	err = b.(*Backend).DeleteKey(context.Background(), attrs)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("expected backend.ErrKeyNotFound, got %v", err)
	}
}
