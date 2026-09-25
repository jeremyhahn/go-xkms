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

package quantum

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// wrappedNotFoundStorage is a storage.Backend double whose Get wraps
// storage.ErrNotFound with call-site context (fmt.Errorf's %w), the shape
// a real backend produces when it adds detail to the sentinel.
type wrappedNotFoundStorage struct {
	storage.Backend
}

func (w *wrappedNotFoundStorage) Get(_ context.Context, key string) ([]byte, error) {
	return nil, fmt.Errorf("get %s: %w", key, storage.ErrNotFound)
}

// TestGetKey_NotFound_Wrapped is go-xkms#894's regression case: GetKey
// compares the storage error with errors.Is, so a storage backend that
// wraps storage.ErrNotFound must still classify as backend.ErrKeyNotFound,
// not the generic "failed to retrieve key" a bare == comparison would take.
func TestGetKey_NotFound_Wrapped(t *testing.T) {
	store, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	qb, err := New(&wrappedNotFoundStorage{Backend: store})
	require.NoError(t, err)

	attrs := mldsaAttrs("test-getkey-wrapped-notfound.com", types.QuantumAlgorithmMLDSA65)

	_, err = qb.GetKey(context.Background(), attrs)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Fatalf("expected backend.ErrKeyNotFound, got %v", err)
	}
}
