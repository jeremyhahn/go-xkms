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

package xkms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Pointer-to-interface conversions compile only when the two types are
// identical, so these prove the sdk/go names are aliases, not copies.
var (
	_ *storage.CompareAndSwapper = (*StorageCompareAndSwapper)(nil)
	_ *storage.CompareAndDeleter = (*StorageCompareAndDeleter)(nil)
)

func TestStorageCompareCapabilities_MemoryBackend(t *testing.T) {
	b := NewStorageMemory()

	_, ok := b.(StorageCompareAndSwapper)
	require.True(t, ok, "memory backend must implement StorageCompareAndSwapper")

	cad, ok := b.(StorageCompareAndDeleter)
	require.True(t, ok, "memory backend must implement StorageCompareAndDeleter")

	deleted, err := cad.CompareAndDelete(context.Background(), "absent", []byte("x"))
	require.NoError(t, err)
	require.False(t, deleted)
}
