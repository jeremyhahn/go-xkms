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

package module

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePKCS11StateClient is an in-memory stand-in for the transport, so the
// remoteBackend's translation of storage.Backend calls to state RPCs can be
// tested without a live xkmsd. It keys by "tenant/token/key" to prove the
// backend forwards the namespace fields.
type fakePKCS11StateClient struct {
	data map[string][]byte
}

func newFakePKCS11StateClient() *fakePKCS11StateClient {
	return &fakePKCS11StateClient{data: make(map[string][]byte)}
}

func (f *fakePKCS11StateClient) k(tenant, token, key string) string {
	return tenant + "\x00" + token + "\x00" + key
}

func (f *fakePKCS11StateClient) PKCS11StatePut(_ context.Context, req *transport.PKCS11StatePutRequest) (*transport.PKCS11StatePutResponse, error) {
	f.data[f.k(req.TenantID, req.Token, req.Key)] = append([]byte(nil), req.Value...)
	return &transport.PKCS11StatePutResponse{}, nil
}

func (f *fakePKCS11StateClient) PKCS11StatePutIfAbsent(_ context.Context, req *transport.PKCS11StatePutIfAbsentRequest) (*transport.PKCS11StatePutIfAbsentResponse, error) {
	key := f.k(req.TenantID, req.Token, req.Key)
	if _, ok := f.data[key]; ok {
		return &transport.PKCS11StatePutIfAbsentResponse{Stored: false}, nil
	}
	f.data[key] = append([]byte(nil), req.Value...)
	return &transport.PKCS11StatePutIfAbsentResponse{Stored: true}, nil
}

func (f *fakePKCS11StateClient) PKCS11StateCAS(_ context.Context, req *transport.PKCS11StateCASRequest) (*transport.PKCS11StateCASResponse, error) {
	key := f.k(req.TenantID, req.Token, req.Key)
	current, present := f.data[key]
	if req.ExpectAbsent {
		if present {
			return &transport.PKCS11StateCASResponse{Swapped: false, Current: current}, nil
		}
	} else if !present || !bytes.Equal(current, req.Expected) {
		return &transport.PKCS11StateCASResponse{Swapped: false, Current: current}, nil
	}
	f.data[key] = append([]byte(nil), req.New...)
	return &transport.PKCS11StateCASResponse{Swapped: true}, nil
}

func (f *fakePKCS11StateClient) PKCS11StateGet(_ context.Context, req *transport.PKCS11StateGetRequest) (*transport.PKCS11StateGetResponse, error) {
	v, ok := f.data[f.k(req.TenantID, req.Token, req.Key)]
	if !ok {
		return &transport.PKCS11StateGetResponse{Found: false}, nil
	}
	return &transport.PKCS11StateGetResponse{Value: v, Found: true}, nil
}

func (f *fakePKCS11StateClient) PKCS11StateDelete(_ context.Context, req *transport.PKCS11StateDeleteRequest) (*transport.PKCS11StateDeleteResponse, error) {
	delete(f.data, f.k(req.TenantID, req.Token, req.Key))
	return &transport.PKCS11StateDeleteResponse{}, nil
}

func (f *fakePKCS11StateClient) PKCS11StateList(_ context.Context, req *transport.PKCS11StateListRequest) (*transport.PKCS11StateListResponse, error) {
	scope := f.k(req.TenantID, req.Token, req.Prefix)
	var keys []string
	tokenScope := f.k(req.TenantID, req.Token, "")
	for k := range f.data {
		if strings.HasPrefix(k, scope) {
			keys = append(keys, strings.TrimPrefix(k, tokenScope))
		}
	}
	return &transport.PKCS11StateListResponse{Keys: keys}, nil
}

func newRemoteBackendForTest(t *testing.T) (storage.Backend, *fakePKCS11StateClient) {
	t.Helper()
	client := newFakePKCS11StateClient()
	b, err := newRemoteBackend(client, "tenant-x", "tok0")
	require.NoError(t, err)
	return b, client
}

func TestNewRemoteBackend_Validation(t *testing.T) {
	_, err := newRemoteBackend(nil, "t", "tok0")
	require.ErrorIs(t, err, ErrRemoteClientRequired)

	_, err = newRemoteBackend(newFakePKCS11StateClient(), "t", "")
	require.ErrorIs(t, err, ErrRemoteTokenRequired)
}

func TestRemoteBackend_PutGetDelete(t *testing.T) {
	b, _ := newRemoteBackendForTest(t)
	ctx := context.Background()

	require.NoError(t, b.Put(ctx, "pkcs11/tokens/0", []byte("state")))

	got, err := b.Get(ctx, "pkcs11/tokens/0")
	require.NoError(t, err)
	assert.Equal(t, []byte("state"), got)

	require.NoError(t, b.Delete(ctx, "pkcs11/tokens/0"))
	_, err = b.Get(ctx, "pkcs11/tokens/0")
	assert.ErrorIs(t, err, storage.ErrNotFound, "a deleted key must translate to storage.ErrNotFound")
}

func TestRemoteBackend_Get_AbsentMapsToErrNotFound(t *testing.T) {
	b, _ := newRemoteBackendForTest(t)
	_, err := b.Get(context.Background(), "missing")
	assert.ErrorIs(t, err, storage.ErrNotFound,
		"the module's ModuleStorage relies on storage.ErrNotFound to tell absent from empty")
}

func TestRemoteBackend_PutIfAbsent_And_Exists(t *testing.T) {
	b, _ := newRemoteBackendForTest(t)
	ctx := context.Background()

	stored, err := b.PutIfAbsent(ctx, "marker", []byte("first"))
	require.NoError(t, err)
	assert.True(t, stored)

	stored, err = b.PutIfAbsent(ctx, "marker", []byte("second"))
	require.NoError(t, err)
	assert.False(t, stored, "PutIfAbsent must forward the server's not-stored result")

	exists, err := b.Exists(ctx, "marker")
	require.NoError(t, err)
	assert.True(t, exists)

	exists, err = b.Exists(ctx, "absent")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestRemoteBackend_ListAndScan(t *testing.T) {
	b, _ := newRemoteBackendForTest(t)
	ctx := context.Background()
	require.NoError(t, b.Put(ctx, "pkcs11/objects/1", []byte("a")))
	require.NoError(t, b.Put(ctx, "pkcs11/objects/2", []byte("b")))
	require.NoError(t, b.Put(ctx, "pkcs11/tokens/0", []byte("c")))

	keys, err := b.List(ctx, "pkcs11/objects/")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"pkcs11/objects/1", "pkcs11/objects/2"}, keys)

	seen := map[string][]byte{}
	require.NoError(t, b.Scan(ctx, "pkcs11/objects/", func(k string, v []byte) error {
		seen[k] = v
		return nil
	}))
	assert.Equal(t, map[string][]byte{
		"pkcs11/objects/1": []byte("a"),
		"pkcs11/objects/2": []byte("b"),
	}, seen)
}

func TestRemoteBackend_NamespaceIsForwarded(t *testing.T) {
	b, client := newRemoteBackendForTest(t)
	require.NoError(t, b.Put(context.Background(), "k", []byte("v")))
	// The fake keys by tenant/token/key; the value must be filed under the
	// backend's configured (tenant-x, tok0) namespace, proving the backend
	// forwards them rather than dropping them.
	_, ok := client.data["tenant-x\x00tok0\x00k"]
	assert.True(t, ok, "the backend must forward its tenant and token to the RPC")
}

// TestRemoteBackend_CompareAndSwap verifies the remote backend translates the
// storage.CompareAndSwapper contract onto the CAS RPC: a nil expected creates
// only when absent, a matching expected swaps, and a stale expected is rejected
// with the current value returned so the caller can retry.
func TestRemoteBackend_CompareAndSwap(t *testing.T) {
	b, _ := newRemoteBackendForTest(t)
	ctx := context.Background()
	cas, ok := b.(storage.CompareAndSwapper)
	require.True(t, ok, "remote backend must satisfy storage.CompareAndSwapper")

	const key = "pkcs11/counters/lockout"
	v0 := []byte("0")

	// Create-if-absent.
	swapped, _, err := cas.CompareAndSwap(ctx, key, nil, v0)
	require.NoError(t, err)
	assert.True(t, swapped)

	// Create-if-absent against a present key fails and returns the current value.
	swapped, current, err := cas.CompareAndSwap(ctx, key, nil, []byte("99"))
	require.NoError(t, err)
	assert.False(t, swapped)
	assert.Equal(t, v0, current)

	// Matching swap.
	v1 := []byte("1")
	swapped, _, err = cas.CompareAndSwap(ctx, key, v0, v1)
	require.NoError(t, err)
	assert.True(t, swapped)

	// Stale expected is rejected and returns the current value.
	swapped, current, err = cas.CompareAndSwap(ctx, key, v0, []byte("2"))
	require.NoError(t, err)
	assert.False(t, swapped)
	assert.Equal(t, v1, current)
}
