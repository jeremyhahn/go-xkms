//go:build codec_json

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package objstore

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-objstore/pkg/local"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFactory_AccountDAO(t *testing.T) {
	tmpDir, cleanup := setupTestStore(t)
	defer cleanup()

	store := local.New()
	err := store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.AccountDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_OrderDAO(t *testing.T) {
	tmpDir, cleanup := setupTestStore(t)
	defer cleanup()

	store := local.New()
	err := store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.OrderDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_OrderDAO_InvalidAccountID(t *testing.T) {
	tmpDir, cleanup := setupTestStore(t)
	defer cleanup()

	store := local.New()
	err := store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	factory, err := NewFactory(store)
	require.NoError(t, err)

	_, err = factory.OrderDAO(0)
	var idErr qrdbsdk.DAOInvalidEntityIDError
	assert.True(t, errors.As(err, &idErr))
}

func TestFactory_AuthorizationDAO(t *testing.T) {
	tmpDir, cleanup := setupTestStore(t)
	defer cleanup()

	store := local.New()
	err := store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.AuthorizationDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_AuthorizationDAO_InvalidAccountID(t *testing.T) {
	tmpDir, cleanup := setupTestStore(t)
	defer cleanup()

	store := local.New()
	err := store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	factory, err := NewFactory(store)
	require.NoError(t, err)

	_, err = factory.AuthorizationDAO(0)
	var idErr qrdbsdk.DAOInvalidEntityIDError
	assert.True(t, errors.As(err, &idErr))
}

func TestFactory_ChallengeDAO(t *testing.T) {
	tmpDir, cleanup := setupTestStore(t)
	defer cleanup()

	store := local.New()
	err := store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.ChallengeDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_ChallengeDAO_InvalidAccountID(t *testing.T) {
	tmpDir, cleanup := setupTestStore(t)
	defer cleanup()

	store := local.New()
	err := store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	factory, err := NewFactory(store)
	require.NoError(t, err)

	_, err = factory.ChallengeDAO(0)
	var idErr qrdbsdk.DAOInvalidEntityIDError
	assert.True(t, errors.As(err, &idErr))
}

func TestFactory_CertificateDAO(t *testing.T) {
	tmpDir, cleanup := setupTestStore(t)
	defer cleanup()

	store := local.New()
	err := store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.CertificateDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_NonceDAO(t *testing.T) {
	tmpDir, cleanup := setupTestStore(t)
	defer cleanup()

	store := local.New()
	err := store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.NonceDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_ExternalAccountBindingDAO(t *testing.T) {
	tmpDir, cleanup := setupTestStore(t)
	defer cleanup()

	store := local.New()
	err := store.Configure(map[string]string{"path": tmpDir})
	require.NoError(t, err)

	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.ExternalAccountBindingDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestNewFactory_NilStore(t *testing.T) {
	_, err := NewFactory(nil)
	var cfgErr qrdbsdk.DAOInvalidConfigError
	assert.True(t, errors.As(err, &cfgErr))
}

// Mock storage tests for Factory

func TestFactory_MockStorage_AccountDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.AccountDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_MockStorage_OrderDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.OrderDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_MockStorage_OrderDAO_InvalidAccountID(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	_, err = factory.OrderDAO(0)
	var idErr qrdbsdk.DAOInvalidEntityIDError
	assert.True(t, errors.As(err, &idErr))
}

func TestFactory_MockStorage_AuthorizationDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.AuthorizationDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_MockStorage_ChallengeDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.ChallengeDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_MockStorage_CertificateDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.CertificateDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_MockStorage_NonceDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.NonceDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_MockStorage_ExternalAccountBindingDAO(t *testing.T) {
	store := newMockStorage()
	factory, err := NewFactory(store)
	require.NoError(t, err)

	d, err := factory.ExternalAccountBindingDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}
