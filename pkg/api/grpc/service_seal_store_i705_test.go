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
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// This file covers service_seal_store.go (go-xkms #705, batch A): the
// SealStore* RPCs shipped without any test.

// newSealStoreGRPCService wires a fresh XKMSService over an in-memory
// platform store and returns the gRPC Service in front of it.
func newSealStoreGRPCService(t *testing.T) *Service {
	t.Helper()
	store, err := seal.NewPlatformStore(storage.NewMemory(), nil)
	require.NoError(t, err)
	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetPlatformStore(store)
	return NewService(nil, nil, xkmsSvc)
}

func TestServiceSealStorePut_Success(t *testing.T) {
	svc := newSealStoreGRPCService(t)
	resp, err := svc.SealStorePut(context.Background(), &pb.SealStorePutRequest{Name: "db-password", Secret: []byte("hunter2")})
	require.NoError(t, err)
	assert.Equal(t, "db-password", resp.Name)
}

func TestServiceSealStorePut_MissingName(t *testing.T) {
	svc := newSealStoreGRPCService(t)
	_, err := svc.SealStorePut(context.Background(), &pb.SealStorePutRequest{Secret: []byte("x")})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceSealStorePut_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.SealStorePut(context.Background(), &pb.SealStorePutRequest{Name: "x", Secret: []byte("y")})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceSealStoreGet_Success(t *testing.T) {
	svc := newSealStoreGRPCService(t)
	_, err := svc.SealStorePut(context.Background(), &pb.SealStorePutRequest{Name: "db-password", Secret: []byte("hunter2")})
	require.NoError(t, err)

	resp, err := svc.SealStoreGet(context.Background(), &pb.SealStoreGetRequest{Name: "db-password"})
	require.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), resp.Secret)
}

func TestServiceSealStoreGet_NotFound(t *testing.T) {
	svc := newSealStoreGRPCService(t)
	_, err := svc.SealStoreGet(context.Background(), &pb.SealStoreGetRequest{Name: "missing"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestServiceSealStoreGet_MissingName(t *testing.T) {
	svc := newSealStoreGRPCService(t)
	_, err := svc.SealStoreGet(context.Background(), &pb.SealStoreGetRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceSealStoreGet_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.SealStoreGet(context.Background(), &pb.SealStoreGetRequest{Name: "x"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceSealStoreDelete_Success(t *testing.T) {
	svc := newSealStoreGRPCService(t)
	_, err := svc.SealStorePut(context.Background(), &pb.SealStorePutRequest{Name: "db-password", Secret: []byte("hunter2")})
	require.NoError(t, err)

	_, err = svc.SealStoreDelete(context.Background(), &pb.SealStoreDeleteRequest{Name: "db-password"})
	require.NoError(t, err)

	_, err = svc.SealStoreGet(context.Background(), &pb.SealStoreGetRequest{Name: "db-password"})
	assert.Equal(t, codes.NotFound, status.Code(err), "a deleted secret is gone, not silently retrievable")
}

func TestServiceSealStoreDelete_MissingName(t *testing.T) {
	svc := newSealStoreGRPCService(t)
	_, err := svc.SealStoreDelete(context.Background(), &pb.SealStoreDeleteRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceSealStoreDelete_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.SealStoreDelete(context.Background(), &pb.SealStoreDeleteRequest{Name: "x"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceSealStoreList_Success(t *testing.T) {
	svc := newSealStoreGRPCService(t)
	_, err := svc.SealStorePut(context.Background(), &pb.SealStorePutRequest{Name: "a", Secret: []byte("1")})
	require.NoError(t, err)
	_, err = svc.SealStorePut(context.Background(), &pb.SealStorePutRequest{Name: "b", Secret: []byte("2")})
	require.NoError(t, err)

	resp, err := svc.SealStoreList(context.Background(), &pb.SealStoreListRequest{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a", "b"}, resp.Names)
}

func TestServiceSealStoreList_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.SealStoreList(context.Background(), &pb.SealStoreListRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceSealStoreReseal_Success(t *testing.T) {
	svc := newSealStoreGRPCService(t)
	_, err := svc.SealStorePut(context.Background(), &pb.SealStorePutRequest{Name: "db-password", Secret: []byte("hunter2")})
	require.NoError(t, err)

	resp, err := svc.SealStoreReseal(context.Background(), &pb.SealStoreResealRequest{Name: "db-password"})
	require.NoError(t, err)
	assert.Equal(t, "db-password", resp.Name)

	got, err := svc.SealStoreGet(context.Background(), &pb.SealStoreGetRequest{Name: "db-password"})
	require.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), got.Secret, "resealing never changes the plaintext")
}

func TestServiceSealStoreReseal_MissingName(t *testing.T) {
	svc := newSealStoreGRPCService(t)
	_, err := svc.SealStoreReseal(context.Background(), &pb.SealStoreResealRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceSealStoreReseal_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.SealStoreReseal(context.Background(), &pb.SealStoreResealRequest{Name: "x"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceSealStoreStatus_Success(t *testing.T) {
	svc := newSealStoreGRPCService(t)
	_, err := svc.SealStorePut(context.Background(), &pb.SealStorePutRequest{Name: "db-password", Secret: []byte("hunter2")})
	require.NoError(t, err)

	resp, err := svc.SealStoreStatus(context.Background(), &pb.SealStoreStatusRequest{})
	require.NoError(t, err)
	assert.True(t, resp.Available)
	assert.Equal(t, int32(1), resp.SecretCount)
	assert.Equal(t, []string{"db-password"}, resp.SecretNames)
}

func TestServiceSealStoreStatus_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.SealStoreStatus(context.Background(), &pb.SealStoreStatusRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// newCredentialSealStoreGRPCService returns a service over a platform store
// holding a backend credential (credentials/db-password) and an ordinary
// platform secret (vault-token).
func newCredentialSealStoreGRPCService(t *testing.T) *Service {
	t.Helper()
	store, err := seal.NewPlatformStore(storage.NewMemory(), nil)
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), "credentials/db-password", []byte("hunter2")))
	require.NoError(t, store.Put(context.Background(), "vault-token", []byte("token")))
	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetPlatformStore(store)
	return NewService(nil, nil, xkmsSvc)
}

func TestServiceSealStoreGet_CredentialNamespaceDenied(t *testing.T) {
	svc := newCredentialSealStoreGRPCService(t)
	resp, err := svc.SealStoreGet(context.Background(), &pb.SealStoreGetRequest{Name: "credentials/db-password"})
	assert.Nil(t, resp)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestServiceSealStoreGet_PlatformSecretBesideCredential(t *testing.T) {
	svc := newCredentialSealStoreGRPCService(t)
	resp, err := svc.SealStoreGet(context.Background(), &pb.SealStoreGetRequest{Name: "vault-token"})
	require.NoError(t, err)
	assert.Equal(t, []byte("token"), resp.Secret)
}

func TestServiceSealStoreList_OmitsCredentials(t *testing.T) {
	svc := newCredentialSealStoreGRPCService(t)
	resp, err := svc.SealStoreList(context.Background(), &pb.SealStoreListRequest{})
	require.NoError(t, err)
	assert.Equal(t, []string{"vault-token"}, resp.Names)
}
