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

package staticpw

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// The store xkey opens over its barrier or file backend round-trips an entry.
func TestNewBackendStore_RoundTrip(t *testing.T) {
	backend := xkms.NewStorageMemory()
	t.Cleanup(func() { assert.NoError(t, backend.Close()) })

	store, err := NewBackendStore(backend)
	require.NoError(t, err)
	require.NoError(t, store.Add(&StaticPassword{Name: "mail", Password: "pw"}))

	got, err := store.Get("mail")
	require.NoError(t, err)
	assert.Equal(t, "pw", got.Password)

	_, err = store.Get("absent")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

// Without a backend there is no store.
func TestNewBackendStore_NilBackend(t *testing.T) {
	store, err := NewBackendStore(nil)
	require.Error(t, err)
	assert.Nil(t, store)
}
