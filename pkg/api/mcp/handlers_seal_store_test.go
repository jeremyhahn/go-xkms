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

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// fakeSealStore implements seal.PlatformStore over an in-memory map, with a
// settable err that every method returns unconditionally, so tests can drive
// each of apierrors.SealStoreSentinelClasses' sentinels through a real
// XKMSService.SealStore* call instead of only through the transport-level
// "not configured" nil check.
type fakeSealStore struct {
	secrets map[string][]byte
	err     error
}

func newFakeSealStore() *fakeSealStore {
	return &fakeSealStore{secrets: make(map[string][]byte)}
}

func (f *fakeSealStore) Put(_ context.Context, name string, secret []byte) error {
	if f.err != nil {
		return f.err
	}
	f.secrets[name] = secret
	return nil
}

func (f *fakeSealStore) Get(_ context.Context, name string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	s, ok := f.secrets[name]
	if !ok {
		return nil, seal.ErrSecretNotFound
	}
	return s, nil
}

func (f *fakeSealStore) Delete(_ context.Context, name string) error {
	if f.err != nil {
		return f.err
	}
	if _, ok := f.secrets[name]; !ok {
		return seal.ErrSecretNotFound
	}
	delete(f.secrets, name)
	return nil
}

func (f *fakeSealStore) Exists(_ context.Context, name string) (bool, error) {
	_, ok := f.secrets[name]
	return ok, nil
}

func (f *fakeSealStore) List(_ context.Context) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	names := make([]string, 0, len(f.secrets))
	for name := range f.secrets {
		names = append(names, name)
	}
	return names, nil
}

func (f *fakeSealStore) Reseal(_ context.Context, _ string) error {
	if f.err != nil {
		return f.err
	}
	return nil
}

// compile-time guard: fakeSealStore must satisfy seal.PlatformStore.
var _ seal.PlatformStore = (*fakeSealStore)(nil)

// sealStoreMethods lists every sealStore.* JSON-RPC method and the params
// body InvokeMethod needs to reach its handler, so the "not configured"
// classification test below covers the whole family in one table instead of
// six near-duplicate test functions.
var sealStoreMethods = []struct {
	method string
	params string
}{
	{"sealStore.put", `{"name":"k","secret":"c2VjcmV0"}`},
	{"sealStore.get", `{"name":"k"}`},
	{"sealStore.delete", `{"name":"k"}`},
	{"sealStore.list", `{}`},
	{"sealStore.reseal", `{"name":"k"}`},
	{"sealStore.status", `{}`},
}

// TestInvokeMethod_SealStore_NotConfigured proves every sealStore.* handler
// reaches the caller as Service unavailable, through the real InvokeMethod
// dispatch, when no platform-sealed store is wired -- matching
// pkg/api/grpc/service_seal_store.go's mapSealStoreError for the identical
// xkms.ErrNotConfigured condition (go-xkms#921). Before this change every one
// of these six methods reported wire.CodeInternal instead, because the
// handlers returned the bare sentinel.
func TestInvokeMethod_SealStore_NotConfigured(t *testing.T) {
	for _, tc := range sealStoreMethods {
		t.Run(tc.method, func(t *testing.T) {
			server := createTestServer(t)
			defer cleanupXKMS()

			_, err := server.InvokeMethod(context.Background(), tc.method, json.RawMessage(tc.params))
			require.Error(t, err)

			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
			assert.ErrorIs(t, err, xkms.ErrNotConfigured)
		})
	}
}

// TestInvokeMethod_SealStore_XKMSServiceNil proves every sealStore.* handler
// reports Service unavailable, matching the platform-store-not-configured
// case above, when the transport itself has no xkms service wired at all
// (the earlier of the two "not configured" checks each handler makes).
// Called directly, like TestHandlePasswordSetAccessMode's "fails when xkms
// service not configured" case, since a zero-value *Server cannot run
// InvokeMethod's logger and RBAC gates.
func TestInvokeMethod_SealStore_XKMSServiceNil(t *testing.T) {
	bare := &Server{}
	ctx := context.Background()

	t.Run("put", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "sealStore.put", ID: 1}
		_, err := bare.handleSealStorePut(ctx, req)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
		assert.ErrorIs(t, err, ErrSealStoreNotConfigured)
	})

	t.Run("get", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "sealStore.get", ID: 1}
		_, err := bare.handleSealStoreGet(ctx, req)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
	})

	t.Run("delete", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "sealStore.delete", ID: 1}
		_, err := bare.handleSealStoreDelete(ctx, req)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
	})

	t.Run("list", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "sealStore.list", ID: 1}
		_, err := bare.handleSealStoreList(ctx, req)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
	})

	t.Run("reseal", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "sealStore.reseal", ID: 1}
		_, err := bare.handleSealStoreReseal(ctx, req)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
	})

	t.Run("status", func(t *testing.T) {
		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "sealStore.status", ID: 1}
		_, err := bare.handleSealStoreStatus(ctx, req)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
	})
}

// TestInvokeMethod_SealStore_SecretNotFound proves sealStore.get and
// sealStore.delete report Not found (sdkssh.JSONRPCCodeNotFound) for an
// unknown secret name, matching pkg/api/grpc/service_seal_store.go's
// codes.NotFound for seal.ErrSecretNotFound.
func TestInvokeMethod_SealStore_SecretNotFound(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()
	server.xkmsService.SetPlatformStore(newFakeSealStore())

	t.Run("get", func(t *testing.T) {
		_, err := server.InvokeMethod(context.Background(), "sealStore.get", json.RawMessage(`{"name":"missing"}`))
		require.Error(t, err)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyErr.Code)
		assert.ErrorIs(t, err, seal.ErrSecretNotFound)
	})

	t.Run("delete", func(t *testing.T) {
		_, err := server.InvokeMethod(context.Background(), "sealStore.delete", json.RawMessage(`{"name":"missing"}`))
		require.Error(t, err)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyErr.Code)
		assert.ErrorIs(t, err, seal.ErrSecretNotFound)
	})
}

func TestInvokeMethod_SealStore_CredentialNamespace(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()
	store := newFakeSealStore()
	store.secrets["credentials/db-password"] = []byte("hunter2")
	store.secrets["vault-token"] = []byte("token")
	server.xkmsService.SetPlatformStore(store)

	t.Run("credential refused", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "sealStore.get", json.RawMessage(`{"name":"credentials/db-password"}`))
		assert.Nil(t, result)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, ErrCodeForbidden, keyErr.Code)
		assert.ErrorIs(t, err, xkms.ErrReservedSecretName)
	})

	t.Run("platform secret readable", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "sealStore.get", json.RawMessage(`{"name":"vault-token"}`))
		require.NoError(t, err)
		resp, ok := result.(*transport.SealStoreGetResponse)
		require.True(t, ok, "unexpected result type %T", result)
		assert.Equal(t, []byte("token"), resp.Secret)
	})
}

// TestInvokeMethod_SealStore_ResealFailed proves sealStore.reseal reports
// Internal (apierrors.ClassInternal, matching gRPC's codes.Internal) for
// seal.ErrResealFailed, and that the failure still reaches the caller as a
// classified *KeyOpError rather than the dispatcher's opaque fallback.
func TestInvokeMethod_SealStore_ResealFailed(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()

	store := newFakeSealStore()
	store.err = seal.ErrResealFailed
	server.xkmsService.SetPlatformStore(store)

	_, err := server.InvokeMethod(context.Background(), "sealStore.reseal", json.RawMessage(`{"name":"k"}`))
	require.Error(t, err)

	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeInternalError, keyErr.Code)
	assert.ErrorIs(t, err, seal.ErrResealFailed)
}

// TestInvokeMethod_SealStore_Success proves each sealStore.* handler's happy
// path reaches the xkms service and returns a usable result through the
// real InvokeMethod dispatch, using a working fakeSealStore.
func TestInvokeMethod_SealStore_Success(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()
	server.xkmsService.SetPlatformStore(newFakeSealStore())

	t.Run("put", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "sealStore.put", json.RawMessage(`{"name":"k","secret":"c2VjcmV0"}`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("get", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "sealStore.get", json.RawMessage(`{"name":"k"}`))
		require.NoError(t, err)
		resp, ok := result.(*transport.SealStoreGetResponse)
		require.True(t, ok)
		assert.Equal(t, "k", resp.Name)
	})

	t.Run("list", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "sealStore.list", json.RawMessage(`{}`))
		require.NoError(t, err)
		resp, ok := result.(*transport.SealStoreListResponse)
		require.True(t, ok)
		assert.Contains(t, resp.Names, "k")
	})

	t.Run("status", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "sealStore.status", json.RawMessage(`{}`))
		require.NoError(t, err)
		resp, ok := result.(*transport.SealStoreStatusResponse)
		require.True(t, ok)
		assert.True(t, resp.Available)
	})

	t.Run("reseal", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "sealStore.reseal", json.RawMessage(`{"name":"k"}`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("delete", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "sealStore.delete", json.RawMessage(`{"name":"k"}`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})
}
