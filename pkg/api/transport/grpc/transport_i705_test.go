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
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// This file covers RPC-wired client methods (go-xkms #705, batch A) that
// shipped without a NotConnected / Connected / ServerError triple: the user
// admin operations, per-share and audit queries, tenant entitlement/quota
// updates, algorithm discovery and the PKCS11State remote-storage bridge.
// Each mock/error handler proves the request fields the client sends survive
// the round trip, not just that a response comes back.

// --- mockKeystoreServer additions (happy path, field echo) ---

func (s *mockKeystoreServer) CreateUser(_ context.Context, req *pb.CreateUserRequest) (*pb.UserResponse, error) {
	return &pb.UserResponse{User: &pb.UserInfo{
		Username: req.GetUsername(), Email: req.GetEmail(), DisplayName: req.GetDisplayName(),
		Role: req.GetRole(), Enabled: true, Id: 1,
	}}, nil
}

func (s *mockKeystoreServer) ListUsers(_ context.Context, _ *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	return &pb.ListUsersResponse{Users: []*pb.UserInfo{
		{Username: "alice", Email: "alice@example.com", Role: "admin", Enabled: true},
	}}, nil
}

func (s *mockKeystoreServer) GetUser(_ context.Context, req *pb.GetUserRequest) (*pb.UserResponse, error) {
	return &pb.UserResponse{User: &pb.UserInfo{Username: req.GetUsername(), Email: "found@example.com", Enabled: true}}, nil
}

func (s *mockKeystoreServer) DeleteUser(_ context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	return &pb.DeleteUserResponse{Username: req.GetUsername(), Deleted: true}, nil
}

func (s *mockKeystoreServer) EnableUser(_ context.Context, req *pb.EnableUserRequest) (*pb.UserResponse, error) {
	return &pb.UserResponse{User: &pb.UserInfo{Username: req.GetUsername(), Enabled: true}}, nil
}

func (s *mockKeystoreServer) DisableUser(_ context.Context, req *pb.DisableUserRequest) (*pb.UserResponse, error) {
	return &pb.UserResponse{User: &pb.UserInfo{Username: req.GetUsername(), Enabled: false}}, nil
}

func (s *mockKeystoreServer) BindUserCert(_ context.Context, req *pb.BindUserCertRequest) (*pb.UserResponse, error) {
	return &pb.UserResponse{User: &pb.UserInfo{Username: req.GetUsername()}}, nil
}

func (s *mockKeystoreServer) ListUserCredentials(_ context.Context, req *pb.ListUserCredentialsRequest) (*pb.ListUserCredentialsResponse, error) {
	return &pb.ListUserCredentialsResponse{Credentials: []*pb.UserCredential{
		{Id: "cred-1", Name: "yubikey-" + req.GetUsername()},
	}}, nil
}

func (s *mockKeystoreServer) UpdateTenantEntitlements(_ context.Context, req *pb.UpdateTenantEntitlementsRequest) (*pb.UpdateTenantEntitlementsResponse, error) {
	return &pb.UpdateTenantEntitlementsResponse{Tenant: &pb.TenantInfo{
		Id: req.GetTenantId(), Entitlements: req.GetEntitlements(),
	}}, nil
}

func (s *mockKeystoreServer) UpdateTenantQuotas(_ context.Context, req *pb.UpdateTenantQuotasRequest) (*pb.UpdateTenantQuotasResponse, error) {
	return &pb.UpdateTenantQuotasResponse{Tenant: &pb.TenantInfo{
		Id: req.GetTenantId(), Quotas: req.GetQuotas(),
	}}, nil
}

func (s *mockKeystoreServer) Algorithms(_ context.Context, _ *pb.AlgorithmsRequest) (*pb.AlgorithmsResponse, error) {
	return &pb.AlgorithmsResponse{
		Signing: []*pb.AlgorithmInfo{
			{Algorithm: "ECDSA", Curves: []string{"P-256"}, KeySizes: []int32{256}, Backends: []string{"software"}},
		},
		KeyEncapsulation: []*pb.AlgorithmInfo{
			{Algorithm: "ML-KEM", KeySizes: []int32{768}, PostQuantum: true},
		},
	}, nil
}

func (s *mockKeystoreServer) BootstrapListenerKeys(_ context.Context, _ *emptypb.Empty) (*pb.BootstrapListenerKeysResponse, error) {
	return &pb.BootstrapListenerKeysResponse{NoisePublicKey: "noise-hex", P256PublicKey: "p256-hex"}, nil
}

func (s *mockKeystoreServer) GeneratePIVCSR(_ context.Context, req *pb.GeneratePIVCSRRequest) (*pb.GeneratePIVCSRResponse, error) {
	return &pb.GeneratePIVCSRResponse{Slot: req.GetSlot(), Csr: []byte("-----BEGIN CERTIFICATE REQUEST-----")}, nil
}

func (s *mockKeystoreServer) PKCS11StatePut(_ context.Context, _ *pb.PKCS11StatePutRequest) (*pb.PKCS11StatePutResponse, error) {
	return &pb.PKCS11StatePutResponse{}, nil
}

func (s *mockKeystoreServer) PKCS11StatePutIfAbsent(_ context.Context, _ *pb.PKCS11StatePutIfAbsentRequest) (*pb.PKCS11StatePutIfAbsentResponse, error) {
	return &pb.PKCS11StatePutIfAbsentResponse{Stored: true}, nil
}

func (s *mockKeystoreServer) PKCS11StateCAS(_ context.Context, req *pb.PKCS11StateCASRequest) (*pb.PKCS11StateCASResponse, error) {
	return &pb.PKCS11StateCASResponse{Swapped: true, Current: req.GetNew()}, nil
}

func (s *mockKeystoreServer) PKCS11StateGet(_ context.Context, req *pb.PKCS11StateGetRequest) (*pb.PKCS11StateGetResponse, error) {
	if req.GetKey() == "missing" {
		return &pb.PKCS11StateGetResponse{Found: false}, nil
	}
	return &pb.PKCS11StateGetResponse{Value: []byte("state-value"), Found: true}, nil
}

func (s *mockKeystoreServer) PKCS11StateDelete(_ context.Context, _ *pb.PKCS11StateDeleteRequest) (*pb.PKCS11StateDeleteResponse, error) {
	return &pb.PKCS11StateDeleteResponse{}, nil
}

func (s *mockKeystoreServer) PKCS11StateList(_ context.Context, req *pb.PKCS11StateListRequest) (*pb.PKCS11StateListResponse, error) {
	return &pb.PKCS11StateListResponse{Keys: []string{req.GetPrefix() + "/a", req.GetPrefix() + "/b"}}, nil
}

// --- errorKeystoreServer additions (uniform Internal status) ---

func (s *errorKeystoreServer) CreateUser(_ context.Context, _ *pb.CreateUserRequest) (*pb.UserResponse, error) {
	return nil, status.Error(codes.Internal, "create user failed")
}

func (s *errorKeystoreServer) ListUsers(_ context.Context, _ *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	return nil, status.Error(codes.Internal, "list users failed")
}

func (s *errorKeystoreServer) GetUser(_ context.Context, _ *pb.GetUserRequest) (*pb.UserResponse, error) {
	return nil, status.Error(codes.NotFound, "get user failed")
}

func (s *errorKeystoreServer) DeleteUser(_ context.Context, _ *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	return nil, status.Error(codes.Internal, "delete user failed")
}

func (s *errorKeystoreServer) EnableUser(_ context.Context, _ *pb.EnableUserRequest) (*pb.UserResponse, error) {
	return nil, status.Error(codes.Internal, "enable user failed")
}

func (s *errorKeystoreServer) DisableUser(_ context.Context, _ *pb.DisableUserRequest) (*pb.UserResponse, error) {
	return nil, status.Error(codes.Internal, "disable user failed")
}

func (s *errorKeystoreServer) BindUserCert(_ context.Context, _ *pb.BindUserCertRequest) (*pb.UserResponse, error) {
	return nil, status.Error(codes.Internal, "bind user cert failed")
}

func (s *errorKeystoreServer) ListUserCredentials(_ context.Context, _ *pb.ListUserCredentialsRequest) (*pb.ListUserCredentialsResponse, error) {
	return nil, status.Error(codes.Internal, "list user credentials failed")
}

func (s *errorKeystoreServer) UpdateTenantEntitlements(_ context.Context, _ *pb.UpdateTenantEntitlementsRequest) (*pb.UpdateTenantEntitlementsResponse, error) {
	return nil, status.Error(codes.Internal, "update tenant entitlements failed")
}

func (s *errorKeystoreServer) UpdateTenantQuotas(_ context.Context, _ *pb.UpdateTenantQuotasRequest) (*pb.UpdateTenantQuotasResponse, error) {
	return nil, status.Error(codes.Internal, "update tenant quotas failed")
}

func (s *errorKeystoreServer) Algorithms(_ context.Context, _ *pb.AlgorithmsRequest) (*pb.AlgorithmsResponse, error) {
	return nil, status.Error(codes.Internal, "algorithms failed")
}

func (s *errorKeystoreServer) BootstrapListenerKeys(_ context.Context, _ *emptypb.Empty) (*pb.BootstrapListenerKeysResponse, error) {
	return nil, status.Error(codes.Internal, "bootstrap listener keys failed")
}

func (s *errorKeystoreServer) PKCS11StatePut(_ context.Context, _ *pb.PKCS11StatePutRequest) (*pb.PKCS11StatePutResponse, error) {
	return nil, status.Error(codes.Internal, "pkcs11 state put failed")
}

func (s *errorKeystoreServer) PKCS11StatePutIfAbsent(_ context.Context, _ *pb.PKCS11StatePutIfAbsentRequest) (*pb.PKCS11StatePutIfAbsentResponse, error) {
	return nil, status.Error(codes.Internal, "pkcs11 state put-if-absent failed")
}

func (s *errorKeystoreServer) PKCS11StateCAS(_ context.Context, _ *pb.PKCS11StateCASRequest) (*pb.PKCS11StateCASResponse, error) {
	return nil, status.Error(codes.Internal, "pkcs11 state compare-and-swap failed")
}

func (s *errorKeystoreServer) PKCS11StateGet(_ context.Context, _ *pb.PKCS11StateGetRequest) (*pb.PKCS11StateGetResponse, error) {
	return nil, status.Error(codes.Internal, "pkcs11 state get failed")
}

func (s *errorKeystoreServer) PKCS11StateDelete(_ context.Context, _ *pb.PKCS11StateDeleteRequest) (*pb.PKCS11StateDeleteResponse, error) {
	return nil, status.Error(codes.Internal, "pkcs11 state delete failed")
}

func (s *errorKeystoreServer) PKCS11StateList(_ context.Context, _ *pb.PKCS11StateListRequest) (*pb.PKCS11StateListResponse, error) {
	return nil, status.Error(codes.Internal, "pkcs11 state list failed")
}

// --- NotConnected: ErrNotConnected, never the zero value ---

func TestCreateUser_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).CreateUser(context.Background(), &transport.CreateUserRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListUsers_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ListUsers(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetUser_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).GetUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeleteUser_NotConnected(t *testing.T) {
	err := newDisconnected(t).DeleteUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestEnableUser_NotConnected(t *testing.T) {
	err := newDisconnected(t).EnableUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDisableUser_NotConnected(t *testing.T) {
	err := newDisconnected(t).DisableUser(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBindUserCert_NotConnected(t *testing.T) {
	err := newDisconnected(t).BindUserCert(context.Background(), "alice", "thumb", 0)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListUserCredentials_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).ListUserCredentials(context.Background(), "alice")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUpdateTenantEntitlements_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUpdateTenantQuotas_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestAlgorithms_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).Algorithms(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBootstrapListenerKeys_NotConnected_I705(t *testing.T) {
	_, err := newDisconnected(t).BootstrapListenerKeys(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGeneratePIVCSR_NotConnected_I705(t *testing.T) {
	_, err := newDisconnected(t).GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StatePut_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StatePutIfAbsent_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PKCS11StatePutIfAbsent(context.Background(), &transport.PKCS11StatePutIfAbsentRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateCAS_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PKCS11StateCAS(context.Background(), &transport.PKCS11StateCASRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateGet_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateDelete_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PKCS11StateDelete(context.Background(), &transport.PKCS11StateDeleteRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestPKCS11StateList_NotConnected(t *testing.T) {
	_, err := newDisconnected(t).PKCS11StateList(context.Background(), &transport.PKCS11StateListRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Connected: the wire contract round trip ---

func TestCreateUser_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username: "bob", Email: "bob@example.com", DisplayName: "Bob", Role: "operator", TenantID: "tenant-a",
	})
	require.NoError(t, err)
	assert.Equal(t, "bob", resp.User.Username)
	assert.Equal(t, "bob@example.com", resp.User.Email)
	assert.Equal(t, "operator", resp.User.Role)
}

func TestListUsers_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.ListUsers(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Users, 1)
	assert.Equal(t, "alice", resp.Users[0].Username)
}

func TestGetUser_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.GetUser(context.Background(), "alice")
	require.NoError(t, err)
	assert.Equal(t, "alice", resp.User.Username)
}

func TestDeleteUser_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.DeleteUser(context.Background(), "alice"))
}

func TestEnableUser_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.EnableUser(context.Background(), "alice"))
}

func TestDisableUser_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.DisableUser(context.Background(), "alice"))
}

func TestBindUserCert_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	require.NoError(t, tr.BindUserCert(context.Background(), "alice", "thumbprint", 1234))
}

func TestListUserCredentials_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.ListUserCredentials(context.Background(), "alice")
	require.NoError(t, err)
	require.Len(t, resp.Credentials, 1)
	assert.Equal(t, "cred-1", resp.Credentials[0].ID)
	assert.Equal(t, "yubikey-alice", resp.Credentials[0].DisplayName)
}

func TestUpdateTenantEntitlements_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{
		TenantID: "tenant-a",
		Entitlements: transport.TenantEntitlements{
			AllowedIsolationModes: []string{"dedicated"}, AllowDedicatedRaft: true,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", resp.Tenant.ID)
	require.NotNil(t, resp.Tenant.Entitlements)
	assert.True(t, resp.Tenant.Entitlements.AllowDedicatedRaft)
	assert.Equal(t, []string{"dedicated"}, resp.Tenant.Entitlements.AllowedIsolationModes)
}

func TestUpdateTenantQuotas_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{
		TenantID: "tenant-a",
		Quotas:   transport.TenantQuotas{MaxKeys: 100, MaxUsers: 10},
	})
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", resp.Tenant.ID)
	require.NotNil(t, resp.Tenant.Quotas)
	assert.Equal(t, int64(100), resp.Tenant.Quotas.MaxKeys)
	assert.Equal(t, int64(10), resp.Tenant.Quotas.MaxUsers)
}

func TestAlgorithms_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.Algorithms(context.Background())
	require.NoError(t, err)
	require.Len(t, resp.Signing, 1)
	assert.Equal(t, "ECDSA", resp.Signing[0].Algorithm)
	assert.Equal(t, []int{256}, resp.Signing[0].KeySizes)
	require.Len(t, resp.KeyEncapsulation, 1)
	assert.True(t, resp.KeyEncapsulation[0].PostQuantum)
}

func TestBootstrapListenerKeys_Connected_I705(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	tr.connected = true
	resp, err := tr.BootstrapListenerKeys(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "noise-hex", resp.NoisePublicKey)
	assert.Equal(t, "p256-hex", resp.P256PublicKey)
}

func TestGeneratePIVCSR_Connected_I705(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	tr.connected = true
	resp, err := tr.GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{Backend: "software", Slot: "9a"})
	require.NoError(t, err)
	assert.Equal(t, "9a", resp.Slot)
	assert.NotEmpty(t, resp.CSR)
}

func TestPKCS11StatePut_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{
		TenantID: "tenant-a", Token: "tok0", Key: "k", Value: []byte("v"),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestPKCS11StatePutIfAbsent_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StatePutIfAbsent(context.Background(), &transport.PKCS11StatePutIfAbsentRequest{
		TenantID: "tenant-a", Token: "tok0", Key: "k", Value: []byte("v"),
	})
	require.NoError(t, err)
	assert.True(t, resp.Stored)
}

func TestPKCS11StateCAS_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StateCAS(context.Background(), &transport.PKCS11StateCASRequest{
		TenantID: "tenant-a", Token: "tok0", Key: "k", Expected: []byte("old"), New: []byte("new"),
	})
	require.NoError(t, err)
	assert.True(t, resp.Swapped)
	assert.Equal(t, []byte("new"), resp.Current)
}

func TestPKCS11StateGet_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{
		TenantID: "tenant-a", Token: "tok0", Key: "k",
	})
	require.NoError(t, err)
	assert.True(t, resp.Found)
	assert.Equal(t, []byte("state-value"), resp.Value)

	resp, err = tr.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{
		TenantID: "tenant-a", Token: "tok0", Key: "missing",
	})
	require.NoError(t, err)
	assert.False(t, resp.Found)
}

func TestPKCS11StateDelete_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StateDelete(context.Background(), &transport.PKCS11StateDeleteRequest{
		TenantID: "tenant-a", Token: "tok0", Key: "k",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestPKCS11StateList_Connected(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	resp, err := tr.PKCS11StateList(context.Background(), &transport.PKCS11StateListRequest{
		TenantID: "tenant-a", Token: "tok0", Prefix: "ns",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"ns/a", "ns/b"}, resp.Keys)
}

// --- ServerError: the failure surfaces as a typed, wrapped error ---

func TestCreateUser_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.CreateUser(context.Background(), &transport.CreateUserRequest{Username: "x"})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestListUsers_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.ListUsers(context.Background())
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestGetUser_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.GetUser(context.Background(), "x")
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestDeleteUser_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	err := tr.DeleteUser(context.Background(), "x")
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestEnableUser_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	err := tr.EnableUser(context.Background(), "x")
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestDisableUser_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	err := tr.DisableUser(context.Background(), "x")
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestBindUserCert_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	err := tr.BindUserCert(context.Background(), "x", "thumb", 0)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestListUserCredentials_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.ListUserCredentials(context.Background(), "x")
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestUpdateTenantEntitlements_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.UpdateTenantEntitlements(context.Background(), &transport.UpdateTenantEntitlementsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestUpdateTenantQuotas_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.UpdateTenantQuotas(context.Background(), &transport.UpdateTenantQuotasRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestAlgorithms_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.Algorithms(context.Background())
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestBootstrapListenerKeys_ServerError_I705(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.BootstrapListenerKeys(context.Background())
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPKCS11StatePut_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.PKCS11StatePut(context.Background(), &transport.PKCS11StatePutRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPKCS11StatePutIfAbsent_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.PKCS11StatePutIfAbsent(context.Background(), &transport.PKCS11StatePutIfAbsentRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPKCS11StateCAS_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.PKCS11StateCAS(context.Background(), &transport.PKCS11StateCASRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPKCS11StateGet_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.PKCS11StateGet(context.Background(), &transport.PKCS11StateGetRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPKCS11StateDelete_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.PKCS11StateDelete(context.Background(), &transport.PKCS11StateDeleteRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestPKCS11StateList_ServerError(t *testing.T) {
	tr, cleanup := newErrorBufconnTransport(t)
	defer cleanup()
	_, err := tr.PKCS11StateList(context.Background(), &transport.PKCS11StateListRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}
