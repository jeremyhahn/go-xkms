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

package qrdb

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProvider(t *testing.T) {
	t.Run("creates provider with explicit kvstore", func(t *testing.T) {
		svc := &mockProviderService{
			kvClient: NewMemoryKVClient(),
		}
		adapter := NewKVStoreAdapter(svc.KV())
		p := NewProvider(svc, adapter)

		require.NotNil(t, p)
		assert.NotNil(t, p.KVStore())
		assert.NotNil(t, p.KV())
	})

	t.Run("creates provider with nil kvstore auto-wraps", func(t *testing.T) {
		memKV := NewMemoryKVClient()
		svc := &mockProviderService{
			kvClient: memKV,
		}
		p := NewProvider(svc, nil)

		require.NotNil(t, p)
		assert.NotNil(t, p.KVStore())
	})
}

func TestProviderKVStore(t *testing.T) {
	t.Run("put and get through kvstore", func(t *testing.T) {
		svc := &mockProviderService{
			kvClient: NewMemoryKVClient(),
		}
		p := NewProvider(svc, nil)
		ctx := context.Background()

		err := p.KVStore().Put(ctx, "key1", []byte("value1"))
		require.NoError(t, err)

		got, err := p.KVStore().Get(ctx, "key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), got)
	})

	t.Run("returns database ErrNotFound for missing key", func(t *testing.T) {
		svc := &mockProviderService{
			kvClient: NewMemoryKVClient(),
		}
		p := NewProvider(svc, nil)
		ctx := context.Background()

		got, err := p.KVStore().Get(ctx, "nonexistent")
		require.Error(t, err)
		assert.Nil(t, got)

		var de *qrdbsdk.DatabaseError
		require.ErrorAs(t, err, &de)
		assert.Equal(t, qrdbsdk.ErrNotFound, de.Code)
	})
}

func TestProviderHealthy(t *testing.T) {
	t.Run("delegates to service", func(t *testing.T) {
		svc := &mockProviderService{
			kvClient: NewMemoryKVClient(),
			healthy:  true,
		}
		p := NewProvider(svc, nil)
		assert.True(t, p.Healthy(context.Background()))
	})

	t.Run("unhealthy service", func(t *testing.T) {
		svc := &mockProviderService{
			kvClient: NewMemoryKVClient(),
			healthy:  false,
		}
		p := NewProvider(svc, nil)
		assert.False(t, p.Healthy(context.Background()))
	})
}

func TestProviderClose(t *testing.T) {
	t.Run("delegates close to service", func(t *testing.T) {
		svc := &mockProviderService{
			kvClient: NewMemoryKVClient(),
			healthy:  true,
		}
		p := NewProvider(svc, nil)

		err := p.Close()
		assert.NoError(t, err)
		assert.True(t, svc.closed)
	})

	t.Run("propagates close error", func(t *testing.T) {
		closeErr := NewError(ErrorCodeInternal, "close failed")
		svc := &mockProviderService{
			kvClient: NewMemoryKVClient(),
			closeErr: closeErr,
		}
		p := NewProvider(svc, nil)

		err := p.Close()
		require.Error(t, err)
		assert.True(t, IsInternal(err))
	})
}

// mockProviderService implements Service for provider testing.
type mockProviderService struct {
	kvClient db.KVClient
	healthy  bool
	closed   bool
	closeErr error
}

func (m *mockProviderService) KV() db.KVClient       { return m.kvClient }
func (m *mockProviderService) Watch() db.WatchClient { return nil }
func (m *mockProviderService) Lease() db.LeaseClient { return nil }
func (m *mockProviderService) Batch() db.BatchClient { return nil }
func (m *mockProviderService) Transaction() db.TransactionClient {
	return nil
}
func (m *mockProviderService) Index() db.IndexClient            { return nil }
func (m *mockProviderService) Users() db.UserClient             { return nil }
func (m *mockProviderService) Roles() db.RoleClient             { return nil }
func (m *mockProviderService) Certs() db.CertClient             { return nil }
func (m *mockProviderService) Barrier() db.BarrierClient        { return nil }
func (m *mockProviderService) Ceremony() db.CeremonyClient      { return nil }
func (m *mockProviderService) Credentials() db.CredentialClient { return nil }
func (m *mockProviderService) Config() *Config                  { return DefaultConfig() }
func (m *mockProviderService) Healthy(_ context.Context) bool {
	return m.healthy
}
func (m *mockProviderService) Close() error {
	m.closed = true
	return m.closeErr
}
func (m *mockProviderService) Admin() db.AdminClient { return nil }
