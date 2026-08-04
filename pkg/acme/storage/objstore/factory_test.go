//go:build codec_json

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
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestFactory builds a Factory over an in-memory storage.Backend wrapped by
// the kvadapter datastore path (no go-objstore). Each call yields an isolated
// store so tests do not share state.
func newTestFactory(t *testing.T) *Factory {
	t.Helper()
	kv, err := kvadapter.New(xkmsstorage.NewMemory())
	require.NoError(t, err)
	f, err := NewFactoryFromKVStore(kv)
	require.NoError(t, err)
	return f.(*Factory)
}

func TestFactory_AccountDAO(t *testing.T) {
	factory := newTestFactory(t)

	d, err := factory.AccountDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_OrderDAO(t *testing.T) {
	factory := newTestFactory(t)

	d, err := factory.OrderDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_OrderDAO_InvalidAccountID(t *testing.T) {
	factory := newTestFactory(t)

	_, err := factory.OrderDAO(0)
	var idErr qrdbsdk.DAOInvalidEntityIDError
	assert.True(t, errors.As(err, &idErr))
}

func TestFactory_AuthorizationDAO(t *testing.T) {
	factory := newTestFactory(t)

	d, err := factory.AuthorizationDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_AuthorizationDAO_InvalidAccountID(t *testing.T) {
	factory := newTestFactory(t)

	_, err := factory.AuthorizationDAO(0)
	var idErr qrdbsdk.DAOInvalidEntityIDError
	assert.True(t, errors.As(err, &idErr))
}

func TestFactory_ChallengeDAO(t *testing.T) {
	factory := newTestFactory(t)

	d, err := factory.ChallengeDAO(1)
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_ChallengeDAO_InvalidAccountID(t *testing.T) {
	factory := newTestFactory(t)

	_, err := factory.ChallengeDAO(0)
	var idErr qrdbsdk.DAOInvalidEntityIDError
	assert.True(t, errors.As(err, &idErr))
}

func TestFactory_CertificateDAO(t *testing.T) {
	factory := newTestFactory(t)

	d, err := factory.CertificateDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_NonceDAO(t *testing.T) {
	factory := newTestFactory(t)

	d, err := factory.NonceDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestFactory_ExternalAccountBindingDAO(t *testing.T) {
	factory := newTestFactory(t)

	d, err := factory.ExternalAccountBindingDAO()
	assert.NoError(t, err)
	assert.NotNil(t, d)
}

func TestNewFactory_NilKVStore(t *testing.T) {
	_, err := NewFactoryFromKVStore(nil)
	var cfgErr qrdbsdk.DAOInvalidConfigError
	assert.True(t, errors.As(err, &cfgErr))
}
