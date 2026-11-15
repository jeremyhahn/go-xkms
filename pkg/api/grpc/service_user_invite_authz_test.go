package grpc

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/invitetest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// grpcInviteDenyRBAC grants everything but users:invite: a caller that
// passes the users:create transport gate and lacks the invite grant.
type grpcInviteDenyRBAC struct{}

func (grpcInviteDenyRBAC) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	if resource+":"+action == string(qrdbsdk.PermissionUsersInvite) {
		return &qrdbsdk.PermissionDeniedError{}
	}
	return nil
}

func (grpcInviteDenyRBAC) ListPermissions(context.Context, *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

func (grpcInviteDenyRBAC) ListOwnPermissions(context.Context) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

// TestCreateUser_InviteDeniedIsPermissionDenied is SPEC row
// authz-device-onboarding on gRPC: the service's users:invite refusal is
// the caller's missing grant, so it answers PermissionDenied, not Internal.
func TestCreateUser_InviteDeniedIsPermissionDenied(t *testing.T) {
	invites, err := invitetest.New(grpcSingleStoreResolver{store: qrdbsdk.NewMemoryKVStore()})
	require.NoError(t, err)
	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetUserClients(newGRPCFakeUserClient(), &grpcFakeRoleClient{})
	xkmsSvc.SetInviteStore(invites)
	xkmsSvc.SetAuthorizer(auth.NewAuthorizer(grpcInviteDenyRBAC{}))
	s := NewService(nil, nil, xkmsSvc)

	ctx := auth.WithIdentity(context.Background(),
		&auth.Identity{Subject: "creator", TenantID: qrdbsdk.SystemTenantID})
	_, err = s.CreateUser(ctx, &pb.CreateUserRequest{Username: "invitee", Email: "invitee@example.com"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "err: %v", err)
}
