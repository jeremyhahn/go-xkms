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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11state"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newPKCS11StateGRPCService(t *testing.T) (*Service, *xkms.XKMSService) {
	t.Helper()
	store, err := pkcs11state.NewStore(storage.NewMemory())
	require.NoError(t, err)
	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetPKCS11StateStore(store)
	return NewService(nil, nil, xkmsSvc), xkmsSvc
}

func TestServicePKCS11StateCAD_ReleasesOnlyTheObservedValue(t *testing.T) {
	svc, xkmsSvc := newPKCS11StateGRPCService(t)
	ctx := context.Background()
	_, err := xkmsSvc.PKCS11StatePut(ctx, &transport.PKCS11StatePutRequest{
		Token: "tok0", Key: "pkcs11/markers/claim", Value: []byte("holder-A"),
	})
	require.NoError(t, err)

	resp, err := svc.PKCS11StateCAD(ctx, &pb.PKCS11StateCADRequest{Token: "tok0", Key: "pkcs11/markers/claim", Expected: []byte("holder-B")})
	require.NoError(t, err)
	assert.False(t, resp.Deleted, "a guard that does not match is a refusal, not an error")

	resp, err = svc.PKCS11StateCAD(ctx, &pb.PKCS11StateCADRequest{Token: "tok0", Key: "pkcs11/markers/claim", Expected: []byte("holder-A")})
	require.NoError(t, err)
	assert.True(t, resp.Deleted)

	got, err := xkmsSvc.PKCS11StateGet(ctx, &transport.PKCS11StateGetRequest{Token: "tok0", Key: "pkcs11/markers/claim"})
	require.NoError(t, err)
	assert.False(t, got.Found)
}

func TestServicePKCS11StateCAD_RejectsBadInput(t *testing.T) {
	svc, _ := newPKCS11StateGRPCService(t)
	ctx := context.Background()

	_, err := svc.PKCS11StateCAD(ctx, nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = svc.PKCS11StateCAD(ctx, &pb.PKCS11StateCADRequest{Key: "pkcs11/markers/claim"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	unwired := NewService(nil, nil, nil)
	_, err = unwired.PKCS11StateCAD(ctx, &pb.PKCS11StateCADRequest{Token: "tok0", Key: "pkcs11/markers/claim"})
	assert.Equal(t, codes.Unavailable, status.Code(err))

	noStore := NewService(nil, nil, &xkms.XKMSService{})
	_, err = noStore.PKCS11StateCAD(ctx, &pb.PKCS11StateCADRequest{Token: "tok0", Key: "pkcs11/markers/claim"})
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Contains(t, err.Error(), xkms.ErrPKCS11StateStoreUnavailable.Error())
}
