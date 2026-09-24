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

// This file covers three service_custodian_share_tenant.go paths (go-xkms
// #705, batch A) that shipped without a test: shareCoordinates directly,
// GetShare/DeleteShare (which depend on it), and TenantBarrierStatus.

// --- shareCoordinates ---

func TestShareCoordinates_MissingServerURL(t *testing.T) {
	_, _, _, err := shareCoordinates("", "g1", 0)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestShareCoordinates_MissingGroupID(t *testing.T) {
	_, _, _, err := shareCoordinates("https://a.example", "", 0)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestShareCoordinates_Valid(t *testing.T) {
	url, group, idx, err := shareCoordinates("https://a.example", "g1", 3)
	require.NoError(t, err)
	assert.Equal(t, "https://a.example", url)
	assert.Equal(t, "g1", group)
	assert.Equal(t, 3, idx)
}

// --- GetShare / DeleteShare ---

func TestServiceGetShare_NotConfigured(t *testing.T) {
	old := GetShareClient()
	SetShareClient(nil)
	defer SetShareClient(old)

	svc := NewService(nil, nil, nil)
	_, err := svc.GetShare(context.Background(), &pb.GetShareRequest{ServerUrl: "https://a", GroupId: "g1"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestServiceGetShare_InvalidCoordinates(t *testing.T) {
	old := GetShareClient()
	SetShareClient(setupShareClient(t))
	defer SetShareClient(old)

	svc := NewService(nil, nil, nil)
	_, err := svc.GetShare(context.Background(), &pb.GetShareRequest{GroupId: "g1"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceGetShare_NotFound(t *testing.T) {
	old := GetShareClient()
	SetShareClient(setupShareClient(t))
	defer SetShareClient(old)

	svc := NewService(nil, nil, nil)
	_, err := svc.GetShare(context.Background(), &pb.GetShareRequest{ServerUrl: "https://a", GroupId: "ghost"})
	require.Error(t, err)
}

func TestServiceGetShare_Success(t *testing.T) {
	old := GetShareClient()
	sc := setupShareClient(t)
	SetShareClient(sc)
	defer SetShareClient(old)

	svc := NewService(nil, nil, nil)
	_, err := svc.SubmitShare(context.Background(), &pb.SubmitShareRequest{
		GroupId: "g1", ShareData: "secret-share", ServerUrl: "https://a.example", GroupName: "group-1",
	})
	require.NoError(t, err)

	info, err := svc.GetShare(context.Background(), &pb.GetShareRequest{ServerUrl: "https://a.example", GroupId: "g1", ShareIndex: 0})
	require.NoError(t, err)
	assert.Equal(t, "g1", info.GroupId)
	assert.Equal(t, "group-1", info.GroupName)
}

func TestServiceDeleteShare_NotConfigured(t *testing.T) {
	old := GetShareClient()
	SetShareClient(nil)
	defer SetShareClient(old)

	svc := NewService(nil, nil, nil)
	_, err := svc.DeleteShare(context.Background(), &pb.DeleteShareRequest{ServerUrl: "https://a", GroupId: "g1"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestServiceDeleteShare_InvalidCoordinates(t *testing.T) {
	old := GetShareClient()
	SetShareClient(setupShareClient(t))
	defer SetShareClient(old)

	svc := NewService(nil, nil, nil)
	_, err := svc.DeleteShare(context.Background(), &pb.DeleteShareRequest{ServerUrl: "https://a"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceDeleteShare_Success(t *testing.T) {
	old := GetShareClient()
	sc := setupShareClient(t)
	SetShareClient(sc)
	defer SetShareClient(old)

	svc := NewService(nil, nil, nil)
	_, err := svc.SubmitShare(context.Background(), &pb.SubmitShareRequest{
		GroupId: "g1", ShareData: "secret-share", ServerUrl: "https://a.example",
	})
	require.NoError(t, err)

	_, err = svc.DeleteShare(context.Background(), &pb.DeleteShareRequest{ServerUrl: "https://a.example", GroupId: "g1", ShareIndex: 0})
	require.NoError(t, err)

	_, err = svc.GetShare(context.Background(), &pb.GetShareRequest{ServerUrl: "https://a.example", GroupId: "g1", ShareIndex: 0})
	require.Error(t, err, "a deleted share is gone, not silently retrievable")
}

// --- TenantBarrierStatus ---

func TestServiceTenantBarrierStatus_MissingTenantID(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.TenantBarrierStatus(context.Background(), &pb.TenantBarrierStatusRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceTenantBarrierStatus_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.TenantBarrierStatus(context.Background(), &pb.TenantBarrierStatusRequest{TenantId: "acme"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceTenantBarrierStatus_ServicerRouted(t *testing.T) {
	xkmsSvc := newTenantServiceWiredXKMS(t)
	grpcSvc := NewService(nil, nil, xkmsSvc)
	ctx := context.Background()

	_, err := grpcSvc.CreateTenant(ctx, &pb.CreateTenantRequest{Id: "acme", Name: "Acme", IsolationType: "prefix"})
	require.NoError(t, err)

	resp, err := grpcSvc.TenantBarrierStatus(ctx, &pb.TenantBarrierStatusRequest{TenantId: "acme"})
	require.NoError(t, err)
	assert.Equal(t, "acme", resp.TenantId)
}
