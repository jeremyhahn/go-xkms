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

package seal

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestGuardedStorageBackend_GetAbsentKeyMatchesBothNotFoundSentinels proves
// the registry's "no record yet" test works over an xkms backend: go-qrdb's
// BarrierRegistry reads the tenant-root record through the system barrier and
// matches ErrSecretNotFound, while xkms callers match storage.ErrNotFound.
func TestGuardedStorageBackend_GetAbsentKeyMatchesBothNotFoundSentinels(t *testing.T) {
	g := guardedStorageBackend{Backend: storage.NewMemory()}

	_, err := g.Get(context.Background(), "absent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, qrdbsdk.ErrSecretNotFound), "go-qrdb's sentinel must match")
	assert.True(t, errors.Is(err, storage.ErrNotFound), "xkms's sentinel must still match")

	var missing *MissingKeyError
	require.True(t, errors.As(err, &missing))
	assert.Equal(t, "absent", missing.Key)
}

// TestGuardedStorageBackend_GetPresentKeyAndOtherErrorsPassThrough proves the
// translation is confined to absence: a stored value is returned as is, and
// a failing backend's error is not recast as "not found".
func TestGuardedStorageBackend_GetPresentKeyAndOtherErrorsPassThrough(t *testing.T) {
	mem := storage.NewMemory()
	require.NoError(t, mem.Put(context.Background(), "present", []byte("v")))
	got, err := guardedStorageBackend{Backend: mem}.Get(context.Background(), "present")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)

	require.NoError(t, mem.Close())
	_, err = guardedStorageBackend{Backend: mem}.Get(context.Background(), "present")
	require.Error(t, err)
	assert.False(t, errors.Is(err, qrdbsdk.ErrSecretNotFound), "a closed backend is a failure, not an absent key")
}
