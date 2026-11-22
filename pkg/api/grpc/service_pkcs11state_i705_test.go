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

package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// This file covers the PKCS11StatePut / PutIfAbsent / CAS / Get / Delete /
// List handlers in service_pkcs11state.go (go-xkms #705, batch A); only
// PKCS11StateCAD had a test (service_pkcs11state_cad_test.go). It reuses that
// file's newPKCS11StateGRPCService helper.

func TestServicePKCS11StatePut_MissingToken(t *testing.T) {
	svc, _ := newPKCS11StateGRPCService(t)
	_, err := svc.PKCS11StatePut(context.Background(), &pb.PKCS11StatePutRequest{Key: "k", Value: []byte("v")})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServicePKCS11StatePut_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.PKCS11StatePut(context.Background(), &pb.PKCS11StatePutRequest{Token: "tok0", Key: "k"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServicePKCS11StatePutIfAbsent_StoresOnlyOnce(t *testing.T) {
	svc, _ := newPKCS11StateGRPCService(t)
	ctx := context.Background()

	resp, err := svc.PKCS11StatePutIfAbsent(ctx, &pb.PKCS11StatePutIfAbsentRequest{Token: "tok0", Key: "k", Value: []byte("first")})
	require.NoError(t, err)
	assert.True(t, resp.Stored)

	resp, err = svc.PKCS11StatePutIfAbsent(ctx, &pb.PKCS11StatePutIfAbsentRequest{Token: "tok0", Key: "k", Value: []byte("second")})
	require.NoError(t, err)
	assert.False(t, resp.Stored, "a key that already exists is never overwritten")

	got, err := svc.PKCS11StateGet(ctx, &pb.PKCS11StateGetRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	assert.Equal(t, []byte("first"), got.Value)
}

func TestServicePKCS11StatePutIfAbsent_MissingToken(t *testing.T) {
	svc, _ := newPKCS11StateGRPCService(t)
	_, err := svc.PKCS11StatePutIfAbsent(context.Background(), &pb.PKCS11StatePutIfAbsentRequest{Key: "k"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServicePKCS11StatePutIfAbsent_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.PKCS11StatePutIfAbsent(context.Background(), &pb.PKCS11StatePutIfAbsentRequest{Token: "tok0", Key: "k"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServicePKCS11StateCAS_SwapsOnlyOnMatch(t *testing.T) {
	svc, _ := newPKCS11StateGRPCService(t)
	ctx := context.Background()
	_, err := svc.PKCS11StatePut(ctx, &pb.PKCS11StatePutRequest{Token: "tok0", Key: "k", Value: []byte("old")})
	require.NoError(t, err)

	resp, err := svc.PKCS11StateCAS(ctx, &pb.PKCS11StateCASRequest{Token: "tok0", Key: "k", Expected: []byte("wrong"), New: []byte("new")})
	require.NoError(t, err)
	assert.False(t, resp.Swapped)
	assert.Equal(t, []byte("old"), resp.Current, "a failed swap reports the actual current value")

	resp, err = svc.PKCS11StateCAS(ctx, &pb.PKCS11StateCASRequest{Token: "tok0", Key: "k", Expected: []byte("old"), New: []byte("new")})
	require.NoError(t, err)
	assert.True(t, resp.Swapped)

	got, err := svc.PKCS11StateGet(ctx, &pb.PKCS11StateGetRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	assert.Equal(t, []byte("new"), got.Value)
}

func TestServicePKCS11StateCAS_MissingToken(t *testing.T) {
	svc, _ := newPKCS11StateGRPCService(t)
	_, err := svc.PKCS11StateCAS(context.Background(), &pb.PKCS11StateCASRequest{Key: "k"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServicePKCS11StateCAS_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.PKCS11StateCAS(context.Background(), &pb.PKCS11StateCASRequest{Token: "tok0", Key: "k"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServicePKCS11StateGet_MissingToken(t *testing.T) {
	svc, _ := newPKCS11StateGRPCService(t)
	_, err := svc.PKCS11StateGet(context.Background(), &pb.PKCS11StateGetRequest{Key: "k"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServicePKCS11StateGet_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.PKCS11StateGet(context.Background(), &pb.PKCS11StateGetRequest{Token: "tok0", Key: "k"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServicePKCS11StateDelete_Success(t *testing.T) {
	svc, _ := newPKCS11StateGRPCService(t)
	ctx := context.Background()
	_, err := svc.PKCS11StatePut(ctx, &pb.PKCS11StatePutRequest{Token: "tok0", Key: "k", Value: []byte("v")})
	require.NoError(t, err)

	_, err = svc.PKCS11StateDelete(ctx, &pb.PKCS11StateDeleteRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)

	got, err := svc.PKCS11StateGet(ctx, &pb.PKCS11StateGetRequest{Token: "tok0", Key: "k"})
	require.NoError(t, err)
	assert.False(t, got.Found)
}

func TestServicePKCS11StateDelete_MissingToken(t *testing.T) {
	svc, _ := newPKCS11StateGRPCService(t)
	_, err := svc.PKCS11StateDelete(context.Background(), &pb.PKCS11StateDeleteRequest{Key: "k"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServicePKCS11StateDelete_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.PKCS11StateDelete(context.Background(), &pb.PKCS11StateDeleteRequest{Token: "tok0", Key: "k"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServicePKCS11StateList_FiltersByPrefix(t *testing.T) {
	svc, _ := newPKCS11StateGRPCService(t)
	ctx := context.Background()
	for _, key := range []string{"ns/a", "ns/b", "other/c"} {
		_, err := svc.PKCS11StatePut(ctx, &pb.PKCS11StatePutRequest{Token: "tok0", Key: key, Value: []byte("v")})
		require.NoError(t, err)
	}

	resp, err := svc.PKCS11StateList(ctx, &pb.PKCS11StateListRequest{Token: "tok0", Prefix: "ns/"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"ns/a", "ns/b"}, resp.Keys)
}

func TestServicePKCS11StateList_MissingToken(t *testing.T) {
	svc, _ := newPKCS11StateGRPCService(t)
	_, err := svc.PKCS11StateList(context.Background(), &pb.PKCS11StateListRequest{Prefix: "ns/"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServicePKCS11StateList_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.PKCS11StateList(context.Background(), &pb.PKCS11StateListRequest{Token: "tok0"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}
