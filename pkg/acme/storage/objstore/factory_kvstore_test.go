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

package objstore

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewFactoryFromKVStore verifies the datastore path: a Factory built over a
// kvadapter-wrapped storage.Backend (no go-objstore) yields working ACME DAOs.
func TestNewFactoryFromKVStore(t *testing.T) {
	kv, err := kvadapter.New(storage.NewMemory())
	require.NoError(t, err)

	factory, err := NewFactoryFromKVStore(kv)
	require.NoError(t, err)

	accountDAO, err := factory.AccountDAO()
	assert.NoError(t, err)
	assert.NotNil(t, accountDAO)

	orderDAO, err := factory.OrderDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, orderDAO)

	certDAO, err := factory.CertificateDAO()
	assert.NoError(t, err)
	assert.NotNil(t, certDAO)
}

func TestNewFactoryFromKVStore_NilKV(t *testing.T) {
	_, err := NewFactoryFromKVStore(nil)
	assert.Error(t, err)
}
