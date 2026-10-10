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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A host without a go-qrdb node keeps its feature data in the storage backend
// it already has: a password written through the factory lands in that
// backend and reads back through a second store over the same backend.
func TestNewBackendDAOFactory_PersistsThroughTheBackend(t *testing.T) {
	backend := NewStorageMemory()
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })

	daos, err := NewBackendDAOFactory(backend)
	require.NoError(t, err)
	store, err := NewStaticPasswordStore(daos)
	require.NoError(t, err)
	require.NoError(t, store.Add(&StaticPassword{Name: "db", Password: "s3cret"}))

	keys, err := backend.List(t.Context(), "")
	require.NoError(t, err)
	assert.NotEmpty(t, keys, "the record must be written to the backend")

	reopened, err := NewBackendDAOFactory(backend)
	require.NoError(t, err)
	again, err := NewStaticPasswordStore(reopened)
	require.NoError(t, err)
	got, err := again.Get("db")
	require.NoError(t, err)
	assert.Equal(t, "s3cret", got.Password)
}

// A missing backend is refused rather than deferred to the first write.
func TestNewBackendDAOFactory_NilBackend(t *testing.T) {
	daos, err := NewBackendDAOFactory(nil)
	require.Error(t, err)
	assert.Nil(t, daos)
}
