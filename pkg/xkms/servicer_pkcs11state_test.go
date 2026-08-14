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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11state"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPKCS11StateService(t *testing.T) *XKMSService {
	t.Helper()
	store, err := pkcs11state.NewStore(storage.NewMemory())
	require.NoError(t, err)
	svc := &XKMSService{}
	svc.SetPKCS11StateStore(store)
	return svc
}

func TestServicer_PKCS11State_RoundTrip(t *testing.T) {
	svc := newPKCS11StateService(t)
	ctx := context.Background()

	_, err := svc.PKCS11StatePut(ctx, &transport.PKCS11StatePutRequest{
		Token: "tok0", Key: "pkcs11/tokens/0", Value: []byte("state"),
	})
	require.NoError(t, err)

	got, err := svc.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{Token: "tok0", Key: "pkcs11/tokens/0"})
	require.NoError(t, err)
	assert.True(t, got.Found)
	assert.Equal(t, []byte("state"), got.Value)

	_, err = svc.PKCS11StateDelete(ctx, &transport.PKCS11StateDeleteRequest{Token: "tok0", Key: "pkcs11/tokens/0"})
	require.NoError(t, err)

	got, err = svc.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{Token: "tok0", Key: "pkcs11/tokens/0"})
	require.NoError(t, err)
	assert.False(t, got.Found)
}

func TestServicer_PKCS11State_PutIfAbsentAndList(t *testing.T) {
	svc := newPKCS11StateService(t)
	ctx := context.Background()

	r1, err := svc.PKCS11StatePutIfAbsent(ctx, &transport.PKCS11StatePutIfAbsentRequest{Token: "tok0", Key: "m", Value: []byte("1")})
	require.NoError(t, err)
	assert.True(t, r1.Stored)

	r2, err := svc.PKCS11StatePutIfAbsent(ctx, &transport.PKCS11StatePutIfAbsentRequest{Token: "tok0", Key: "m", Value: []byte("2")})
	require.NoError(t, err)
	assert.False(t, r2.Stored)

	_, err = svc.PKCS11StatePut(ctx, &transport.PKCS11StatePutRequest{Token: "tok0", Key: "pkcs11/objects/1", Value: []byte("a")})
	require.NoError(t, err)
	list, err := svc.PKCS11StateList(ctx, &transport.PKCS11StateListRequest{Token: "tok0", Prefix: "pkcs11/objects/"})
	require.NoError(t, err)
	assert.Equal(t, []string{"pkcs11/objects/1"}, list.Keys)
}

func TestServicer_PKCS11State_Validation(t *testing.T) {
	svc := newPKCS11StateService(t)
	ctx := context.Background()

	_, err := svc.PKCS11StateGet(ctx, nil)
	assert.ErrorIs(t, err, ErrNilRequest)

	_, err = svc.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{Token: ""})
	assert.ErrorIs(t, err, ErrPKCS11StateTokenRequired, "every record is namespaced by token; an empty token is refused")
}

func TestServicer_PKCS11State_StoreUnavailable(t *testing.T) {
	// A service without the store wired must refuse the RPC rather than panic.
	svc := &XKMSService{}
	_, err := svc.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{Token: "tok0", Key: "k"})
	assert.ErrorIs(t, err, ErrPKCS11StateStoreUnavailable)
}
