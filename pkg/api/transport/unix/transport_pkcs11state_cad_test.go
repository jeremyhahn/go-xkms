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

package unix

import (
	"bytes"
	"context"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// pkcs11StateCADGuard is the one value the mock server holds; the guard is
// evaluated against it exactly as the server's store would.
var pkcs11StateCADGuard = []byte("holder-A")

func (s *mockKeystoreServer) PKCS11StateCAD(_ context.Context, req *pb.PKCS11StateCADRequest) (*pb.PKCS11StateCADResponse, error) {
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if req.TenantId != "tenant-x" || req.Key != "pkcs11/markers/claim" {
		return &pb.PKCS11StateCADResponse{Deleted: false}, nil
	}
	return &pb.PKCS11StateCADResponse{Deleted: bytes.Equal(req.Expected, pkcs11StateCADGuard)}, nil
}

func TestPKCS11StateCAD_ForwardsNamespaceAndGuard(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	ctx := context.Background()

	resp, err := tr.PKCS11StateCAD(ctx, &transport.PKCS11StateCADRequest{
		TenantID: "tenant-x", Token: "tok0", Key: "pkcs11/markers/claim", Expected: []byte("holder-B"),
	})
	require.NoError(t, err)
	assert.False(t, resp.Deleted, "a guard the server does not hold is a refusal")

	resp, err = tr.PKCS11StateCAD(ctx, &transport.PKCS11StateCADRequest{
		TenantID: "tenant-x", Token: "tok0", Key: "pkcs11/markers/claim", Expected: pkcs11StateCADGuard,
	})
	require.NoError(t, err)
	assert.True(t, resp.Deleted)

	resp, err = tr.PKCS11StateCAD(ctx, &transport.PKCS11StateCADRequest{
		TenantID: "tenant-y", Token: "tok0", Key: "pkcs11/markers/claim", Expected: pkcs11StateCADGuard,
	})
	require.NoError(t, err)
	assert.False(t, resp.Deleted, "the tenant reaches the server, so another tenant's guard cannot release the record")
}

func TestPKCS11StateCAD_ErrorsAreNotRefusals(t *testing.T) {
	disconnected := &Transport{config: transport.DefaultConfig()}
	_, err := disconnected.PKCS11StateCAD(context.Background(), &transport.PKCS11StateCADRequest{Token: "tok0", Key: "k"})
	require.ErrorIs(t, err, ErrNotConnected)

	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StateCAD(context.Background(), &transport.PKCS11StateCADRequest{Key: "pkcs11/markers/claim", Expected: pkcs11StateCADGuard})
	require.Error(t, err, "the server's rejection surfaces as an error, not as deleted=false")
	assert.Nil(t, resp)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
