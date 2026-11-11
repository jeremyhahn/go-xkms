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

//go:build grpc

package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
)

// mockAdminServiceClient implements pb.AdminServiceClient for testing.
type mockAdminServiceClient struct {
	// Tenant operation mocks
	createTenantFunc func(ctx context.Context, in *pb.CreateTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error)
	getTenantFunc    func(ctx context.Context, in *pb.GetTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error)
	updateTenantFunc func(ctx context.Context, in *pb.UpdateTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error)
	deleteTenantFunc func(ctx context.Context, in *pb.DeleteTenantRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	listTenantsFunc  func(ctx context.Context, in *pb.ListTenantsRequest, opts ...grpc.CallOption) (*pb.ListTenantsResponse, error)

	// EAB operation mocks
	createEABFunc func(ctx context.Context, in *pb.CreateEABRequest, opts ...grpc.CallOption) (*pb.CreateEABResponse, error)
	getEABFunc    func(ctx context.Context, in *pb.GetEABRequest, opts ...grpc.CallOption) (*pb.EABInfo, error)
	deleteEABFunc func(ctx context.Context, in *pb.DeleteEABRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	listEABsFunc  func(ctx context.Context, in *pb.ListEABsRequest, opts ...grpc.CallOption) (*pb.ListEABsResponse, error)

	// Role operation mocks
	createTenantRoleFunc func(ctx context.Context, in *pb.CreateTenantRoleRequest, opts ...grpc.CallOption) (*pb.Role, error)
	getTenantRoleFunc    func(ctx context.Context, in *pb.GetTenantRoleRequest, opts ...grpc.CallOption) (*pb.Role, error)
	updateTenantRoleFunc func(ctx context.Context, in *pb.UpdateTenantRoleRequest, opts ...grpc.CallOption) (*pb.Role, error)
	deleteTenantRoleFunc func(ctx context.Context, in *pb.DeleteTenantRoleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	listTenantRolesFunc  func(ctx context.Context, in *pb.ListTenantRolesRequest, opts ...grpc.CallOption) (*pb.ListTenantRolesResponse, error)

	// User operation mocks
	createTenantUserFunc func(ctx context.Context, in *pb.CreateTenantUserRequest, opts ...grpc.CallOption) (*pb.User, error)
	getTenantUserFunc    func(ctx context.Context, in *pb.GetTenantUserRequest, opts ...grpc.CallOption) (*pb.User, error)
	updateTenantUserFunc func(ctx context.Context, in *pb.UpdateTenantUserRequest, opts ...grpc.CallOption) (*pb.User, error)
	deleteTenantUserFunc func(ctx context.Context, in *pb.DeleteTenantUserRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	listTenantUsersFunc  func(ctx context.Context, in *pb.ListTenantUsersRequest, opts ...grpc.CallOption) (*pb.ListTenantUsersResponse, error)

	// Certificate operation mocks
	listCertificatesFunc  func(ctx context.Context, in *pb.ListCertificatesRequest, opts ...grpc.CallOption) (*pb.ListCertificatesResponse, error)
	getCertificateFunc    func(ctx context.Context, in *pb.GetCertificateRequest, opts ...grpc.CallOption) (*pb.CertificateInfo, error)
	revokeCertificateFunc func(ctx context.Context, in *pb.RevokeCertificateRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)

	// Account operation mocks
	listAccountsFunc   func(ctx context.Context, in *pb.ListAccountsRequest, opts ...grpc.CallOption) (*pb.ListAccountsResponse, error)
	getAccountFunc     func(ctx context.Context, in *pb.GetAccountRequest, opts ...grpc.CallOption) (*pb.AccountInfo, error)
	disableAccountFunc func(ctx context.Context, in *pb.DisableAccountRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)

	// Status operation mocks
	getStatusFunc func(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*pb.CAStatus, error)
	getStatsFunc  func(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*pb.CAStats, error)
}

// Tenant operations
func (m *mockAdminServiceClient) CreateTenant(ctx context.Context, in *pb.CreateTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error) {
	if m.createTenantFunc != nil {
		return m.createTenantFunc(ctx, in, opts...)
	}
	return &pb.TenantInfo{}, nil
}

func (m *mockAdminServiceClient) GetTenant(ctx context.Context, in *pb.GetTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error) {
	if m.getTenantFunc != nil {
		return m.getTenantFunc(ctx, in, opts...)
	}
	return &pb.TenantInfo{}, nil
}

func (m *mockAdminServiceClient) UpdateTenant(ctx context.Context, in *pb.UpdateTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error) {
	if m.updateTenantFunc != nil {
		return m.updateTenantFunc(ctx, in, opts...)
	}
	return &pb.TenantInfo{}, nil
}

func (m *mockAdminServiceClient) DeleteTenant(ctx context.Context, in *pb.DeleteTenantRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if m.deleteTenantFunc != nil {
		return m.deleteTenantFunc(ctx, in, opts...)
	}
	return &emptypb.Empty{}, nil
}

func (m *mockAdminServiceClient) ListTenants(ctx context.Context, in *pb.ListTenantsRequest, opts ...grpc.CallOption) (*pb.ListTenantsResponse, error) {
	if m.listTenantsFunc != nil {
		return m.listTenantsFunc(ctx, in, opts...)
	}
	return &pb.ListTenantsResponse{}, nil
}

// EAB operations
func (m *mockAdminServiceClient) CreateEAB(ctx context.Context, in *pb.CreateEABRequest, opts ...grpc.CallOption) (*pb.CreateEABResponse, error) {
	if m.createEABFunc != nil {
		return m.createEABFunc(ctx, in, opts...)
	}
	return &pb.CreateEABResponse{}, nil
}

func (m *mockAdminServiceClient) GetEAB(ctx context.Context, in *pb.GetEABRequest, opts ...grpc.CallOption) (*pb.EABInfo, error) {
	if m.getEABFunc != nil {
		return m.getEABFunc(ctx, in, opts...)
	}
	return &pb.EABInfo{}, nil
}

func (m *mockAdminServiceClient) DeleteEAB(ctx context.Context, in *pb.DeleteEABRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if m.deleteEABFunc != nil {
		return m.deleteEABFunc(ctx, in, opts...)
	}
	return &emptypb.Empty{}, nil
}

func (m *mockAdminServiceClient) ListEABs(ctx context.Context, in *pb.ListEABsRequest, opts ...grpc.CallOption) (*pb.ListEABsResponse, error) {
	if m.listEABsFunc != nil {
		return m.listEABsFunc(ctx, in, opts...)
	}
	return &pb.ListEABsResponse{}, nil
}

// Role operations
func (m *mockAdminServiceClient) CreateTenantRole(ctx context.Context, in *pb.CreateTenantRoleRequest, opts ...grpc.CallOption) (*pb.Role, error) {
	if m.createTenantRoleFunc != nil {
		return m.createTenantRoleFunc(ctx, in, opts...)
	}
	return &pb.Role{}, nil
}

func (m *mockAdminServiceClient) GetTenantRole(ctx context.Context, in *pb.GetTenantRoleRequest, opts ...grpc.CallOption) (*pb.Role, error) {
	if m.getTenantRoleFunc != nil {
		return m.getTenantRoleFunc(ctx, in, opts...)
	}
	return &pb.Role{}, nil
}

func (m *mockAdminServiceClient) UpdateTenantRole(ctx context.Context, in *pb.UpdateTenantRoleRequest, opts ...grpc.CallOption) (*pb.Role, error) {
	if m.updateTenantRoleFunc != nil {
		return m.updateTenantRoleFunc(ctx, in, opts...)
	}
	return &pb.Role{}, nil
}

func (m *mockAdminServiceClient) DeleteTenantRole(ctx context.Context, in *pb.DeleteTenantRoleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if m.deleteTenantRoleFunc != nil {
		return m.deleteTenantRoleFunc(ctx, in, opts...)
	}
	return &emptypb.Empty{}, nil
}

func (m *mockAdminServiceClient) ListTenantRoles(ctx context.Context, in *pb.ListTenantRolesRequest, opts ...grpc.CallOption) (*pb.ListTenantRolesResponse, error) {
	if m.listTenantRolesFunc != nil {
		return m.listTenantRolesFunc(ctx, in, opts...)
	}
	return &pb.ListTenantRolesResponse{}, nil
}

// User operations
func (m *mockAdminServiceClient) CreateTenantUser(ctx context.Context, in *pb.CreateTenantUserRequest, opts ...grpc.CallOption) (*pb.User, error) {
	if m.createTenantUserFunc != nil {
		return m.createTenantUserFunc(ctx, in, opts...)
	}
	return &pb.User{}, nil
}

func (m *mockAdminServiceClient) GetTenantUser(ctx context.Context, in *pb.GetTenantUserRequest, opts ...grpc.CallOption) (*pb.User, error) {
	if m.getTenantUserFunc != nil {
		return m.getTenantUserFunc(ctx, in, opts...)
	}
	return &pb.User{}, nil
}

func (m *mockAdminServiceClient) UpdateTenantUser(ctx context.Context, in *pb.UpdateTenantUserRequest, opts ...grpc.CallOption) (*pb.User, error) {
	if m.updateTenantUserFunc != nil {
		return m.updateTenantUserFunc(ctx, in, opts...)
	}
	return &pb.User{}, nil
}

func (m *mockAdminServiceClient) DeleteTenantUser(ctx context.Context, in *pb.DeleteTenantUserRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if m.deleteTenantUserFunc != nil {
		return m.deleteTenantUserFunc(ctx, in, opts...)
	}
	return &emptypb.Empty{}, nil
}

func (m *mockAdminServiceClient) ListTenantUsers(ctx context.Context, in *pb.ListTenantUsersRequest, opts ...grpc.CallOption) (*pb.ListTenantUsersResponse, error) {
	if m.listTenantUsersFunc != nil {
		return m.listTenantUsersFunc(ctx, in, opts...)
	}
	return &pb.ListTenantUsersResponse{}, nil
}

// Certificate operations
func (m *mockAdminServiceClient) ListCertificates(ctx context.Context, in *pb.ListCertificatesRequest, opts ...grpc.CallOption) (*pb.ListCertificatesResponse, error) {
	if m.listCertificatesFunc != nil {
		return m.listCertificatesFunc(ctx, in, opts...)
	}
	return &pb.ListCertificatesResponse{}, nil
}

func (m *mockAdminServiceClient) GetCertificate(ctx context.Context, in *pb.GetCertificateRequest, opts ...grpc.CallOption) (*pb.CertificateInfo, error) {
	if m.getCertificateFunc != nil {
		return m.getCertificateFunc(ctx, in, opts...)
	}
	return &pb.CertificateInfo{}, nil
}

func (m *mockAdminServiceClient) RevokeCertificate(ctx context.Context, in *pb.RevokeCertificateRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if m.revokeCertificateFunc != nil {
		return m.revokeCertificateFunc(ctx, in, opts...)
	}
	return &emptypb.Empty{}, nil
}

// Account operations
func (m *mockAdminServiceClient) ListAccounts(ctx context.Context, in *pb.ListAccountsRequest, opts ...grpc.CallOption) (*pb.ListAccountsResponse, error) {
	if m.listAccountsFunc != nil {
		return m.listAccountsFunc(ctx, in, opts...)
	}
	return &pb.ListAccountsResponse{}, nil
}

func (m *mockAdminServiceClient) GetAccount(ctx context.Context, in *pb.GetAccountRequest, opts ...grpc.CallOption) (*pb.AccountInfo, error) {
	if m.getAccountFunc != nil {
		return m.getAccountFunc(ctx, in, opts...)
	}
	return &pb.AccountInfo{}, nil
}

func (m *mockAdminServiceClient) DisableAccount(ctx context.Context, in *pb.DisableAccountRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if m.disableAccountFunc != nil {
		return m.disableAccountFunc(ctx, in, opts...)
	}
	return &emptypb.Empty{}, nil
}

// Status operations
func (m *mockAdminServiceClient) GetStatus(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*pb.CAStatus, error) {
	if m.getStatusFunc != nil {
		return m.getStatusFunc(ctx, in, opts...)
	}
	return &pb.CAStatus{}, nil
}

func (m *mockAdminServiceClient) GetStats(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*pb.CAStats, error) {
	if m.getStatsFunc != nil {
		return m.getStatsFunc(ctx, in, opts...)
	}
	return &pb.CAStats{}, nil
}

// Verify mockAdminServiceClient implements the interface
var _ pb.AdminServiceClient = (*mockAdminServiceClient)(nil)

// Helper to create adapter with mock client
func newTestAdapter(client pb.AdminServiceClient, authToken string) *Adapter {
	return &Adapter{
		conn:      nil, // No real connection in tests
		client:    client,
		authToken: authToken,
	}
}

// =============================================================================
// NewAdapter Tests
// =============================================================================

func TestNewAdapter_MissingAddress(t *testing.T) {
	_, err := NewAdapter(&api.AdapterConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gRPC address is required")
}

// =============================================================================
// Protocol and Close Tests
// =============================================================================

func TestProtocol(t *testing.T) {
	adapter := newTestAdapter(&mockAdminServiceClient{}, "")
	assert.Equal(t, api.ProtocolGRPC, adapter.Protocol())
}

func TestClose_NilConnection(t *testing.T) {
	adapter := newTestAdapter(&mockAdminServiceClient{}, "")
	err := adapter.Close()
	assert.NoError(t, err)
}

// =============================================================================
// Tenant Operation Tests
// =============================================================================

func TestCreateTenant_Success(t *testing.T) {
	now := time.Now()
	mockClient := &mockAdminServiceClient{
		createTenantFunc: func(ctx context.Context, in *pb.CreateTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error) {
			assert.Equal(t, "tenant-1", in.Id)
			assert.Equal(t, "Test Tenant", in.Name)
			assert.NotNil(t, in.Settings)
			assert.Equal(t, int32(100), in.Settings.MaxCertificates)
			return &pb.TenantInfo{
				Id:        in.Id,
				Name:      in.Name,
				Status:    "active",
				CreatedAt: timestamppb.New(now),
				UpdatedAt: timestamppb.New(now),
				CreatedBy: "admin",
				Settings:  in.Settings,
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "test-token")
	result, err := adapter.CreateTenant(context.Background(), &admin.CreateTenantRequest{
		ID:   "tenant-1",
		Name: "Test Tenant",
		Settings: &admin.TenantSettingsInfo{
			MaxCertificates: 100,
			MaxAccounts:     50,
		},
	})

	require.NoError(t, err)
	assert.Equal(t, "tenant-1", result.ID)
	assert.Equal(t, "Test Tenant", result.Name)
	assert.Equal(t, "active", result.Status)
	assert.Equal(t, "admin", result.CreatedBy)
	assert.NotNil(t, result.Settings)
	assert.Equal(t, 100, result.Settings.MaxCertificates)
}

func TestCreateTenant_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		createTenantFunc: func(ctx context.Context, in *pb.CreateTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error) {
			return nil, errors.New("failed to create tenant")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.CreateTenant(context.Background(), &admin.CreateTenantRequest{
		ID:   "tenant-1",
		Name: "Test Tenant",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create tenant")
}

func TestGetTenant_Success(t *testing.T) {
	now := time.Now()
	mockClient := &mockAdminServiceClient{
		getTenantFunc: func(ctx context.Context, in *pb.GetTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			return &pb.TenantInfo{
				Id:        "tenant-1",
				Name:      "Test Tenant",
				Status:    "active",
				CreatedAt: timestamppb.New(now),
				UpdatedAt: timestamppb.New(now),
				RootCa: &pb.TenantRootCAInfo{
					CommonName:   "Test Root CA",
					SerialNumber: "1234567890",
					KeyAlgorithm: "RSA-4096",
					NotBefore:    timestamppb.New(now),
					NotAfter:     timestamppb.New(now.Add(365 * 24 * time.Hour)),
					Status:       "active",
					CreatedAt:    timestamppb.New(now),
				},
				IntermediateCas: []*pb.TenantIntermediateCAInfo{
					{
						Id:           "int-ca-1",
						CommonName:   "Test Intermediate CA",
						SerialNumber: "0987654321",
						ParentType:   "root",
						Purpose:      "tls",
						KeyAlgorithm: "ECDSA-P384",
						NotBefore:    timestamppb.New(now),
						NotAfter:     timestamppb.New(now.Add(180 * 24 * time.Hour)),
						Status:       "active",
						CreatedAt:    timestamppb.New(now),
						UpdatedAt:    timestamppb.New(now),
					},
				},
				DefaultIntermediateCaId: "int-ca-1",
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	result, err := adapter.GetTenant(context.Background(), "tenant-1")

	require.NoError(t, err)
	assert.Equal(t, "tenant-1", result.ID)
	assert.Equal(t, "Test Tenant", result.Name)
	assert.Equal(t, "active", result.Status)
	assert.NotNil(t, result.RootCA)
	assert.Equal(t, "Test Root CA", result.RootCA.CommonName)
	assert.Len(t, result.IntermediateCAs, 1)
	assert.Equal(t, "int-ca-1", result.IntermediateCAs[0].ID)
	assert.Equal(t, "int-ca-1", result.DefaultIntermediateCAID)
}

func TestGetTenant_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getTenantFunc: func(ctx context.Context, in *pb.GetTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error) {
			return nil, errors.New("tenant not found")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.GetTenant(context.Background(), "tenant-1")

	require.Error(t, err)
}

func TestUpdateTenant_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		updateTenantFunc: func(ctx context.Context, in *pb.UpdateTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, "Updated Name", in.Name)
			return &pb.TenantInfo{
				Id:   "tenant-1",
				Name: in.Name,
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	result, err := adapter.UpdateTenant(context.Background(), "tenant-1", &admin.UpdateTenantRequest{
		Name: "Updated Name",
	})

	require.NoError(t, err)
	assert.Equal(t, "Updated Name", result.Name)
}

func TestUpdateTenant_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		updateTenantFunc: func(ctx context.Context, in *pb.UpdateTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error) {
			return nil, errors.New("update failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.UpdateTenant(context.Background(), "tenant-1", &admin.UpdateTenantRequest{})

	require.Error(t, err)
}

func TestDeleteTenant_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		deleteTenantFunc: func(ctx context.Context, in *pb.DeleteTenantRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			return &emptypb.Empty{}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	err := adapter.DeleteTenant(context.Background(), "tenant-1")

	assert.NoError(t, err)
}

func TestDeleteTenant_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		deleteTenantFunc: func(ctx context.Context, in *pb.DeleteTenantRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
			return nil, errors.New("delete failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	err := adapter.DeleteTenant(context.Background(), "tenant-1")

	require.Error(t, err)
}

func TestListTenants_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		listTenantsFunc: func(ctx context.Context, in *pb.ListTenantsRequest, opts ...grpc.CallOption) (*pb.ListTenantsResponse, error) {
			return &pb.ListTenantsResponse{
				Tenants: []*pb.TenantInfo{
					{Id: "tenant-1", Name: "Tenant 1"},
					{Id: "tenant-2", Name: "Tenant 2"},
				},
				Pagination: &pb.Pagination{Page: 1, PerPage: 10, Total: 2},
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	tenants, pagination, err := adapter.ListTenants(context.Background(), &admin.ListTenantsRequest{
		Page:    1,
		PerPage: 10,
	})

	require.NoError(t, err)
	assert.Len(t, tenants, 2)
	assert.Equal(t, 2, pagination.Total)
}

func TestListTenants_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		listTenantsFunc: func(ctx context.Context, in *pb.ListTenantsRequest, opts ...grpc.CallOption) (*pb.ListTenantsResponse, error) {
			return nil, errors.New("list failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, _, err := adapter.ListTenants(context.Background(), &admin.ListTenantsRequest{})

	require.Error(t, err)
}

// =============================================================================
// EAB Operation Tests
// =============================================================================

func TestCreateEAB_Success(t *testing.T) {
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	mockClient := &mockAdminServiceClient{
		createEABFunc: func(ctx context.Context, in *pb.CreateEABRequest, opts ...grpc.CallOption) (*pb.CreateEABResponse, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, "standard", in.Purpose)
			assert.Equal(t, int32(30), in.ExpiresInDays)
			assert.Equal(t, []string{"admin@example.com"}, in.Contact)
			assert.Equal(t, "ext-123", in.ExternalAccountId)
			assert.NotNil(t, in.DeviceInfo)
			return &pb.CreateEABResponse{
				Id:        "eab-123",
				MacKey:    "test-mac-key",
				Algorithm: "HS256",
				ExpiresAt: timestamppb.New(expiresAt),
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "test-token")
	result, err := adapter.CreateEAB(context.Background(), "tenant-1", &admin.CreateEABRequest{
		Purpose:           "standard",
		ExpiresInDays:     30,
		Contact:           []string{"admin@example.com"},
		ExternalAccountID: "ext-123",
		DeviceInfo: &admin.EABDeviceInfoDTO{
			DeviceID: "device-1",
		},
	})

	require.NoError(t, err)
	assert.Equal(t, "eab-123", result.ID)
	assert.Equal(t, "test-mac-key", result.MACKey)
	assert.Equal(t, "HS256", result.Algorithm)
	assert.NotNil(t, result.ExpiresAt)
}

func TestCreateEAB_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		createEABFunc: func(ctx context.Context, in *pb.CreateEABRequest, opts ...grpc.CallOption) (*pb.CreateEABResponse, error) {
			return nil, errors.New("create EAB failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.CreateEAB(context.Background(), "tenant-1", &admin.CreateEABRequest{})

	require.Error(t, err)
}

func TestGetEAB_Success(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(30 * 24 * time.Hour)
	usedAt := now.Add(1 * time.Hour)
	mockClient := &mockAdminServiceClient{
		getEABFunc: func(ctx context.Context, in *pb.GetEABRequest, opts ...grpc.CallOption) (*pb.EABInfo, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, "eab-123", in.Kid)
			return &pb.EABInfo{
				Id:                "eab-123",
				TenantId:          "tenant-1",
				Purpose:           "tpm-enrollment",
				Status:            "used",
				AccountId:         456,
				ExternalAccountId: "ext-account-789",
				Contact:           []string{"admin@example.com"},
				CreatedAt:         timestamppb.New(now),
				CreatedBy:         "admin",
				ExpiresAt:         timestamppb.New(expiresAt),
				UsedAt:            timestamppb.New(usedAt),
				DeviceInfo: &pb.EABDeviceInfo{
					DeviceId:           "device-123",
					Manufacturer:       "ACME",
					Model:              "TestDevice",
					EkPublicKeyHash:    "sha256:abc123",
					TpmManufacturer:    "Infineon",
					TpmFirmwareVersion: "7.85",
					Metadata:           map[string]string{"key": "value"},
				},
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	result, err := adapter.GetEAB(context.Background(), "tenant-1", "eab-123")

	require.NoError(t, err)
	assert.Equal(t, "eab-123", result.ID)
	assert.Equal(t, "tenant-1", result.TenantID)
	assert.Equal(t, "tpm-enrollment", result.Purpose)
	assert.Equal(t, "used", result.Status)
	assert.Equal(t, uint64(456), result.AccountID)
	assert.Equal(t, "ext-account-789", result.ExternalAccountID)
	assert.NotNil(t, result.ExpiresAt)
	assert.NotNil(t, result.UsedAt)
	assert.NotNil(t, result.DeviceInfo)
	assert.Equal(t, "device-123", result.DeviceInfo.DeviceID)
	assert.Equal(t, "Infineon", result.DeviceInfo.TPMManufacturer)
}

func TestGetEAB_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getEABFunc: func(ctx context.Context, in *pb.GetEABRequest, opts ...grpc.CallOption) (*pb.EABInfo, error) {
			return nil, errors.New("EAB not found")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.GetEAB(context.Background(), "tenant-1", "eab-123")

	require.Error(t, err)
}

func TestDeleteEAB_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		deleteEABFunc: func(ctx context.Context, in *pb.DeleteEABRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, "eab-123", in.Kid)
			return &emptypb.Empty{}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	err := adapter.DeleteEAB(context.Background(), "tenant-1", "eab-123")

	assert.NoError(t, err)
}

func TestDeleteEAB_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		deleteEABFunc: func(ctx context.Context, in *pb.DeleteEABRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
			return nil, errors.New("delete EAB failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	err := adapter.DeleteEAB(context.Background(), "tenant-1", "eab-123")

	require.Error(t, err)
}

func TestListEABs_Success(t *testing.T) {
	now := time.Now()
	mockClient := &mockAdminServiceClient{
		listEABsFunc: func(ctx context.Context, in *pb.ListEABsRequest, opts ...grpc.CallOption) (*pb.ListEABsResponse, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, int32(1), in.Page)
			assert.Equal(t, int32(20), in.PerPage)
			return &pb.ListEABsResponse{
				Eabs: []*pb.EABInfo{
					{
						Id:        "eab-1",
						TenantId:  "tenant-1",
						Purpose:   "standard",
						Status:    "active",
						CreatedAt: timestamppb.New(now),
					},
					{
						Id:        "eab-2",
						TenantId:  "tenant-1",
						Purpose:   "tpm-enrollment",
						Status:    "used",
						CreatedAt: timestamppb.New(now),
					},
				},
				Pagination: &pb.Pagination{
					Page:    1,
					PerPage: 20,
					Total:   2,
				},
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	eabs, pagination, err := adapter.ListEABs(context.Background(), "tenant-1", &admin.ListEABRequest{
		Page:    1,
		PerPage: 20,
	})

	require.NoError(t, err)
	assert.Len(t, eabs, 2)
	assert.Equal(t, "eab-1", eabs[0].ID)
	assert.Equal(t, "standard", eabs[0].Purpose)
	assert.Equal(t, "eab-2", eabs[1].ID)
	assert.NotNil(t, pagination)
	assert.Equal(t, 2, pagination.Total)
}

func TestListEABs_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		listEABsFunc: func(ctx context.Context, in *pb.ListEABsRequest, opts ...grpc.CallOption) (*pb.ListEABsResponse, error) {
			return nil, errors.New("list EABs failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, _, err := adapter.ListEABs(context.Background(), "tenant-1", &admin.ListEABRequest{})

	require.Error(t, err)
}

// =============================================================================
// Role Operation Tests
// =============================================================================

func TestCreateTenantRole_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		createTenantRoleFunc: func(ctx context.Context, in *pb.CreateTenantRoleRequest, opts ...grpc.CallOption) (*pb.Role, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, "admin", in.Name)
			assert.Equal(t, []string{"read", "write"}, in.Permissions)
			return &pb.Role{
				Id:          "role-1",
				Name:        in.Name,
				TenantId:    in.TenantId,
				Permissions: in.Permissions,
				System:      false,
				CreatedAt:   "2026-03-11T00:00:00Z",
				UpdatedAt:   "2026-03-11T00:00:00Z",
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "test-token")
	result, err := adapter.CreateTenantRole(context.Background(), "tenant-1", &db.CreateRoleRequest{
		Name:        "admin",
		Permissions: []string{"read", "write"},
	})

	require.NoError(t, err)
	assert.Equal(t, "role-1", result.ID)
	assert.Equal(t, "admin", result.Name)
	assert.Equal(t, "tenant-1", result.TenantID)
	assert.Equal(t, []string{"read", "write"}, result.Permissions)
	assert.False(t, result.System)
}

func TestCreateTenantRole_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		createTenantRoleFunc: func(ctx context.Context, in *pb.CreateTenantRoleRequest, opts ...grpc.CallOption) (*pb.Role, error) {
			return nil, errors.New("failed to create role")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.CreateTenantRole(context.Background(), "tenant-1", &db.CreateRoleRequest{
		Name:        "admin",
		Permissions: []string{"read", "write"},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create role")
}

func TestGetTenantRole_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getTenantRoleFunc: func(ctx context.Context, in *pb.GetTenantRoleRequest, opts ...grpc.CallOption) (*pb.Role, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, "role-1", in.RoleId)
			return &pb.Role{
				Id:          "role-1",
				Name:        "admin",
				TenantId:    "tenant-1",
				Permissions: []string{"read", "write"},
				System:      true,
				CreatedAt:   "2026-03-11T00:00:00Z",
				UpdatedAt:   "2026-03-11T00:00:00Z",
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	result, err := adapter.GetTenantRole(context.Background(), "tenant-1", "role-1")

	require.NoError(t, err)
	assert.Equal(t, "role-1", result.ID)
	assert.Equal(t, "admin", result.Name)
	assert.True(t, result.System)
}

func TestGetTenantRole_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getTenantRoleFunc: func(ctx context.Context, in *pb.GetTenantRoleRequest, opts ...grpc.CallOption) (*pb.Role, error) {
			return nil, errors.New("role not found")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.GetTenantRole(context.Background(), "tenant-1", "role-1")

	require.Error(t, err)
}

func TestUpdateTenantRole_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		updateTenantRoleFunc: func(ctx context.Context, in *pb.UpdateTenantRoleRequest, opts ...grpc.CallOption) (*pb.Role, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, "role-1", in.RoleId)
			assert.Equal(t, "updated-role", in.Name)
			assert.Equal(t, []string{"read"}, in.Permissions)
			return &pb.Role{
				Id:          "role-1",
				Name:        in.Name,
				TenantId:    in.TenantId,
				Permissions: in.Permissions,
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	result, err := adapter.UpdateTenantRole(context.Background(), "tenant-1", &db.UpdateRoleRequest{
		ID:          "role-1",
		Name:        "updated-role",
		Permissions: []string{"read"},
	})

	require.NoError(t, err)
	assert.Equal(t, "role-1", result.ID)
	assert.Equal(t, "updated-role", result.Name)
	assert.Equal(t, []string{"read"}, result.Permissions)
}

func TestUpdateTenantRole_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		updateTenantRoleFunc: func(ctx context.Context, in *pb.UpdateTenantRoleRequest, opts ...grpc.CallOption) (*pb.Role, error) {
			return nil, errors.New("update role failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.UpdateTenantRole(context.Background(), "tenant-1", &db.UpdateRoleRequest{
		ID:          "role-1",
		Name:        "updated-role",
		Permissions: []string{"read"},
	})

	require.Error(t, err)
}

func TestDeleteTenantRole_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		deleteTenantRoleFunc: func(ctx context.Context, in *pb.DeleteTenantRoleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, "role-1", in.RoleId)
			return &emptypb.Empty{}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	err := adapter.DeleteTenantRole(context.Background(), "tenant-1", "role-1")

	assert.NoError(t, err)
}

func TestDeleteTenantRole_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		deleteTenantRoleFunc: func(ctx context.Context, in *pb.DeleteTenantRoleRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
			return nil, errors.New("delete role failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	err := adapter.DeleteTenantRole(context.Background(), "tenant-1", "role-1")

	require.Error(t, err)
}

func TestListTenantRoles_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		listTenantRolesFunc: func(ctx context.Context, in *pb.ListTenantRolesRequest, opts ...grpc.CallOption) (*pb.ListTenantRolesResponse, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, int32(1), in.Page)
			assert.Equal(t, int32(10), in.PageSize)
			return &pb.ListTenantRolesResponse{
				Roles: []*pb.Role{
					{Id: "role-1", Name: "admin", TenantId: "tenant-1", Permissions: []string{"read", "write"}},
					{Id: "role-2", Name: "viewer", TenantId: "tenant-1", Permissions: []string{"read"}},
				},
				Total:   2,
				HasMore: false,
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	result, err := adapter.ListTenantRoles(context.Background(), "tenant-1", &db.ListRolesRequest{
		Page:     1,
		PageSize: 10,
	})

	require.NoError(t, err)
	assert.Len(t, result.Roles, 2)
	assert.Equal(t, "role-1", result.Roles[0].ID)
	assert.Equal(t, "admin", result.Roles[0].Name)
	assert.Equal(t, "role-2", result.Roles[1].ID)
	assert.Equal(t, 2, result.Total)
	assert.False(t, result.HasMore)
}

func TestListTenantRoles_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		listTenantRolesFunc: func(ctx context.Context, in *pb.ListTenantRolesRequest, opts ...grpc.CallOption) (*pb.ListTenantRolesResponse, error) {
			return nil, errors.New("list roles failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.ListTenantRoles(context.Background(), "tenant-1", &db.ListRolesRequest{
		Page:     1,
		PageSize: 10,
	})

	require.Error(t, err)
}

// =============================================================================
// User Operation Tests
// =============================================================================

func TestCreateTenantUser_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		createTenantUserFunc: func(ctx context.Context, in *pb.CreateTenantUserRequest, opts ...grpc.CallOption) (*pb.User, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, "testuser", in.Username)
			assert.Equal(t, []string{"role-1"}, in.RoleIds)
			return &pb.User{
				Id:        "1",
				Username:  in.Username,
				TenantId:  in.TenantId,
				RoleIds:   in.RoleIds,
				Enabled:   true,
				System:    false,
				CreatedAt: "2026-03-11T00:00:00Z",
				UpdatedAt: "2026-03-11T00:00:00Z",
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "test-token")
	result, err := adapter.CreateTenantUser(context.Background(), "tenant-1", &db.CreateUserRequest{
		Username: "testuser",
		RoleIDs:  []string{"role-1"},
	})

	require.NoError(t, err)
	assert.Equal(t, uint64(1), result.ID)
	assert.Equal(t, "testuser", result.Username)
	assert.Equal(t, "tenant-1", result.TenantID)
	assert.Equal(t, []string{"role-1"}, result.RoleIDs)
	assert.Equal(t, string(qrdbsdk.LifecycleActive), result.Lifecycle)
	assert.False(t, result.System)
}

func TestCreateTenantUser_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		createTenantUserFunc: func(ctx context.Context, in *pb.CreateTenantUserRequest, opts ...grpc.CallOption) (*pb.User, error) {
			return nil, errors.New("failed to create user")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.CreateTenantUser(context.Background(), "tenant-1", &db.CreateUserRequest{
		Username: "testuser",
		RoleIDs:  []string{"role-1"},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create user")
}

func TestGetTenantUser_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getTenantUserFunc: func(ctx context.Context, in *pb.GetTenantUserRequest, opts ...grpc.CallOption) (*pb.User, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, "user-1", in.UserId)
			return &pb.User{
				Id:        "1",
				Username:  "testuser",
				TenantId:  "tenant-1",
				RoleIds:   []string{"role-1", "role-2"},
				Enabled:   true,
				System:    false,
				CreatedAt: "2026-03-11T00:00:00Z",
				UpdatedAt: "2026-03-11T00:00:00Z",
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	result, err := adapter.GetTenantUser(context.Background(), "tenant-1", "user-1")

	require.NoError(t, err)
	assert.Equal(t, uint64(1), result.ID)
	assert.Equal(t, "testuser", result.Username)
	assert.Equal(t, []string{"role-1", "role-2"}, result.RoleIDs)
	assert.Equal(t, string(qrdbsdk.LifecycleActive), result.Lifecycle)
}

func TestGetTenantUser_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getTenantUserFunc: func(ctx context.Context, in *pb.GetTenantUserRequest, opts ...grpc.CallOption) (*pb.User, error) {
			return nil, errors.New("user not found")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.GetTenantUser(context.Background(), "tenant-1", "user-1")

	require.Error(t, err)
}

func TestUpdateTenantUser_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		updateTenantUserFunc: func(ctx context.Context, in *pb.UpdateTenantUserRequest, opts ...grpc.CallOption) (*pb.User, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, "1", in.UserId)
			assert.Equal(t, "updated-user", in.Username)
			assert.Equal(t, []string{"role-2"}, in.RoleIds)
			return &pb.User{
				Id:       "1",
				Username: in.Username,
				TenantId: in.TenantId,
				RoleIds:  in.RoleIds,
				Enabled:  true,
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	result, err := adapter.UpdateTenantUser(context.Background(), "tenant-1", &db.UpdateUserRequest{
		ID:       1,
		Username: "updated-user",
		RoleIDs:  []string{"role-2"},
	})

	require.NoError(t, err)
	assert.Equal(t, uint64(1), result.ID)
	assert.Equal(t, "updated-user", result.Username)
	assert.Equal(t, []string{"role-2"}, result.RoleIDs)
}

func TestUpdateTenantUser_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		updateTenantUserFunc: func(ctx context.Context, in *pb.UpdateTenantUserRequest, opts ...grpc.CallOption) (*pb.User, error) {
			return nil, errors.New("update user failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.UpdateTenantUser(context.Background(), "tenant-1", &db.UpdateUserRequest{
		ID:       1,
		Username: "updated-user",
		RoleIDs:  []string{"role-2"},
	})

	require.Error(t, err)
}

func TestDeleteTenantUser_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		deleteTenantUserFunc: func(ctx context.Context, in *pb.DeleteTenantUserRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, "user-1", in.UserId)
			return &emptypb.Empty{}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	err := adapter.DeleteTenantUser(context.Background(), "tenant-1", "user-1")

	assert.NoError(t, err)
}

func TestDeleteTenantUser_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		deleteTenantUserFunc: func(ctx context.Context, in *pb.DeleteTenantUserRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
			return nil, errors.New("delete user failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	err := adapter.DeleteTenantUser(context.Background(), "tenant-1", "user-1")

	require.Error(t, err)
}

func TestListTenantUsers_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		listTenantUsersFunc: func(ctx context.Context, in *pb.ListTenantUsersRequest, opts ...grpc.CallOption) (*pb.ListTenantUsersResponse, error) {
			assert.Equal(t, "tenant-1", in.TenantId)
			assert.Equal(t, int32(1), in.Page)
			assert.Equal(t, int32(10), in.PageSize)
			return &pb.ListTenantUsersResponse{
				Users: []*pb.User{
					{Id: "1", Username: "alice", TenantId: "tenant-1", RoleIds: []string{"role-1"}, Enabled: true},
					{Id: "2", Username: "bob", TenantId: "tenant-1", RoleIds: []string{"role-2"}, Enabled: true},
				},
				Total:   2,
				HasMore: false,
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	result, err := adapter.ListTenantUsers(context.Background(), "tenant-1", &db.ListUsersRequest{
		Page:     1,
		PageSize: 10,
	})

	require.NoError(t, err)
	assert.Len(t, result.Users, 2)
	assert.Equal(t, uint64(1), result.Users[0].ID)
	assert.Equal(t, "alice", result.Users[0].Username)
	assert.Equal(t, uint64(2), result.Users[1].ID)
	assert.Equal(t, "bob", result.Users[1].Username)
	assert.Equal(t, 2, result.Total)
	assert.False(t, result.HasMore)
}

func TestListTenantUsers_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		listTenantUsersFunc: func(ctx context.Context, in *pb.ListTenantUsersRequest, opts ...grpc.CallOption) (*pb.ListTenantUsersResponse, error) {
			return nil, errors.New("list users failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.ListTenantUsers(context.Background(), "tenant-1", &db.ListUsersRequest{
		Page:     1,
		PageSize: 10,
	})

	require.Error(t, err)
}

// =============================================================================
// Certificate Operation Tests
// =============================================================================

func TestListCertificates_Success(t *testing.T) {
	now := time.Now()
	mockClient := &mockAdminServiceClient{
		listCertificatesFunc: func(ctx context.Context, in *pb.ListCertificatesRequest, opts ...grpc.CallOption) (*pb.ListCertificatesResponse, error) {
			assert.Equal(t, int32(1), in.Page)
			assert.Equal(t, int32(50), in.PerPage)
			assert.Equal(t, "valid", in.Status)
			return &pb.ListCertificatesResponse{
				Certificates: []*pb.CertificateInfo{
					{
						SerialNumber: "1234567890ABCDEF",
						Subject:      "CN=test.example.com",
						Issuer:       "CN=Test CA",
						Status:       "valid",
						NotBefore:    timestamppb.New(now),
						NotAfter:     timestamppb.New(now.Add(90 * 24 * time.Hour)),
						IssuedAt:     timestamppb.New(now),
						CertUrl:      "https://ca.example.com/certs/123",
					},
					{
						SerialNumber: "FEDCBA0987654321",
						Subject:      "CN=test2.example.com",
						Issuer:       "CN=Test CA",
						Status:       "valid",
						NotBefore:    timestamppb.New(now),
						NotAfter:     timestamppb.New(now.Add(90 * 24 * time.Hour)),
					},
				},
				Pagination: &pb.Pagination{
					Page:    1,
					PerPage: 50,
					Total:   2,
				},
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	certs, pagination, err := adapter.ListCertificates(context.Background(), &admin.ListCertificatesRequest{
		Page:    1,
		PerPage: 50,
		Status:  "valid",
	})

	require.NoError(t, err)
	assert.Len(t, certs, 2)
	assert.Equal(t, "1234567890ABCDEF", certs[0].SerialNumber)
	assert.Equal(t, "CN=test.example.com", certs[0].Subject)
	assert.Equal(t, "https://ca.example.com/certs/123", certs[0].CertURL)
	assert.NotNil(t, pagination)
	assert.Equal(t, 2, pagination.Total)
}

func TestListCertificates_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		listCertificatesFunc: func(ctx context.Context, in *pb.ListCertificatesRequest, opts ...grpc.CallOption) (*pb.ListCertificatesResponse, error) {
			return nil, errors.New("list certificates failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, _, err := adapter.ListCertificates(context.Background(), &admin.ListCertificatesRequest{})

	require.Error(t, err)
}

func TestGetCertificate_Success(t *testing.T) {
	now := time.Now()
	mockClient := &mockAdminServiceClient{
		getCertificateFunc: func(ctx context.Context, in *pb.GetCertificateRequest, opts ...grpc.CallOption) (*pb.CertificateInfo, error) {
			assert.Equal(t, "1234567890ABCDEF", in.Serial)
			return &pb.CertificateInfo{
				SerialNumber: in.Serial,
				Subject:      "CN=test.example.com",
				Issuer:       "CN=Test CA",
				Status:       "valid",
				NotBefore:    timestamppb.New(now),
				NotAfter:     timestamppb.New(now.Add(90 * 24 * time.Hour)),
				IssuedAt:     timestamppb.New(now),
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	cert, err := adapter.GetCertificate(context.Background(), "1234567890ABCDEF")

	require.NoError(t, err)
	assert.Equal(t, "1234567890ABCDEF", cert.SerialNumber)
	assert.Equal(t, "CN=test.example.com", cert.Subject)
	assert.Equal(t, "valid", cert.Status)
}

func TestGetCertificate_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getCertificateFunc: func(ctx context.Context, in *pb.GetCertificateRequest, opts ...grpc.CallOption) (*pb.CertificateInfo, error) {
			return nil, errors.New("certificate not found")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.GetCertificate(context.Background(), "1234567890ABCDEF")

	require.Error(t, err)
}

func TestRevokeCertificate_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		revokeCertificateFunc: func(ctx context.Context, in *pb.RevokeCertificateRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
			assert.Equal(t, "1234567890ABCDEF", in.Serial)
			assert.Equal(t, "keyCompromise", in.Reason)
			return &emptypb.Empty{}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	err := adapter.RevokeCertificate(context.Background(), "1234567890ABCDEF", "keyCompromise")

	assert.NoError(t, err)
}

func TestRevokeCertificate_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		revokeCertificateFunc: func(ctx context.Context, in *pb.RevokeCertificateRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
			return nil, errors.New("revocation failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	err := adapter.RevokeCertificate(context.Background(), "1234567890ABCDEF", "keyCompromise")

	require.Error(t, err)
}

// =============================================================================
// Status Operation Tests
// =============================================================================

func TestGetStatus_Success(t *testing.T) {
	now := time.Now()
	mockClient := &mockAdminServiceClient{
		getStatusFunc: func(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*pb.CAStatus, error) {
			return &pb.CAStatus{
				Identity:       "Test CA",
				Initialized:    true,
				Version:        "1.0.0",
				StartedAt:      timestamppb.New(now),
				KeyAlgorithm:   "RSA-4096",
				SignatureAlgo:  "SHA384WithRSA",
				RootCa:         "CN=Test Root CA",
				IntermediateCa: "CN=Test Intermediate CA",
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	status, err := adapter.GetStatus(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "Test CA", status.Identity)
	assert.True(t, status.Initialized)
	assert.Equal(t, "1.0.0", status.Version)
	assert.Equal(t, "RSA-4096", status.KeyAlgorithm)
	assert.Equal(t, "CN=Test Root CA", status.RootCA)
	assert.Equal(t, "CN=Test Intermediate CA", status.IntermediateCA)
	assert.False(t, status.StartedAt.IsZero())
}

func TestGetStatus_NoStartedAt(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getStatusFunc: func(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*pb.CAStatus, error) {
			return &pb.CAStatus{
				Identity:    "Test CA",
				Initialized: false,
				StartedAt:   nil,
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	status, err := adapter.GetStatus(context.Background())

	require.NoError(t, err)
	assert.False(t, status.Initialized)
	assert.True(t, status.StartedAt.IsZero())
}

func TestGetStatus_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getStatusFunc: func(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*pb.CAStatus, error) {
			return nil, errors.New("status unavailable")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.GetStatus(context.Background())

	require.Error(t, err)
}

func TestGetStats_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getStatsFunc: func(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*pb.CAStats, error) {
			return &pb.CAStats{
				TotalCertificates:   1000,
				ValidCertificates:   800,
				RevokedCertificates: 50,
				ExpiredCertificates: 150,
				TotalAccounts:       100,
				ActiveAccounts:      90,
				TotalOrders:         500,
				PendingOrders:       10,
				CompletedOrders:     480,
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	stats, err := adapter.GetStats(context.Background())

	require.NoError(t, err)
	assert.Equal(t, 1000, stats.TotalCertificates)
	assert.Equal(t, 800, stats.ValidCertificates)
	assert.Equal(t, 50, stats.RevokedCertificates)
	assert.Equal(t, 150, stats.ExpiredCertificates)
	assert.Equal(t, 100, stats.TotalAccounts)
	assert.Equal(t, 90, stats.ActiveAccounts)
	assert.Equal(t, 500, stats.TotalOrders)
	assert.Equal(t, 10, stats.PendingOrders)
	assert.Equal(t, 480, stats.CompletedOrders)
}

func TestGetStats_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getStatsFunc: func(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*pb.CAStats, error) {
			return nil, errors.New("stats unavailable")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	_, err := adapter.GetStats(context.Background())

	require.Error(t, err)
}

// =============================================================================
// Conversion Helper Tests
// =============================================================================

func TestPbToTenantInfo_Nil(t *testing.T) {
	result := pbToTenantInfo(nil)
	assert.Nil(t, result)
}

func TestPbToPagination_Nil(t *testing.T) {
	result := pbToPagination(nil)
	assert.Nil(t, result)
}

func TestPbToEABInfo_Nil(t *testing.T) {
	result := pbToEABInfo(nil)
	assert.Nil(t, result)
}

func TestPbToCertificateInfo_Nil(t *testing.T) {
	result := pbToCertificateInfo(nil)
	assert.Nil(t, result)
}

func TestPbToTenantSettings_Nil(t *testing.T) {
	result := pbToTenantSettings(nil)
	assert.Nil(t, result)
}

func TestTenantSettingsToPb_Nil(t *testing.T) {
	result := tenantSettingsToPb(nil)
	assert.Nil(t, result)
}

func TestTenantSettingsToPb_AllFields(t *testing.T) {
	settings := &admin.TenantSettingsInfo{
		MaxCertificates:         1000,
		MaxAccounts:             100,
		AllowedKeyAlgorithms:    []string{"RSA-4096", "ECDSA-P384"},
		AllowedChallengeTypes:   []string{"http-01", "dns-01"},
		CertificateValidityDays: 90,
		RequireEAB:              true,
		AllowEndorse01:          true,
		AllowEnroll01:           true,
	}

	result := tenantSettingsToPb(settings)

	assert.NotNil(t, result)
	assert.Equal(t, int32(1000), result.MaxCertificates)
	assert.Equal(t, int32(100), result.MaxAccounts)
	assert.Equal(t, []string{"RSA-4096", "ECDSA-P384"}, result.AllowedKeyAlgorithms)
	assert.Equal(t, []string{"http-01", "dns-01"}, result.AllowedChallengeTypes)
	assert.Equal(t, int32(90), result.CertificateValidityDays)
	assert.True(t, result.RequireEab)
	assert.True(t, result.AllowEndorse_01)
	assert.True(t, result.AllowEnroll_01)
}

func TestPbToTenantRootCAInfo_Nil(t *testing.T) {
	result := pbToTenantRootCAInfo(nil)
	assert.Nil(t, result)
}

func TestPbToTenantRootCAInfo_AllFields(t *testing.T) {
	now := time.Now()
	pbCA := &pb.TenantRootCAInfo{
		CommonName:   "Test Root CA",
		SerialNumber: "1234567890",
		KeyAlgorithm: "RSA-4096",
		NotBefore:    timestamppb.New(now),
		NotAfter:     timestamppb.New(now.Add(365 * 24 * time.Hour)),
		Status:       "active",
		CreatedAt:    timestamppb.New(now),
	}

	result := pbToTenantRootCAInfo(pbCA)

	assert.NotNil(t, result)
	assert.Equal(t, "Test Root CA", result.CommonName)
	assert.Equal(t, "1234567890", result.SerialNumber)
	assert.Equal(t, "RSA-4096", result.KeyAlgorithm)
	assert.Equal(t, "active", result.Status)
}

func TestPbToTenantIntCAInfo_Nil(t *testing.T) {
	result := pbToTenantIntCAInfo(nil)
	assert.Nil(t, result)
}

func TestPbToTenantIntCAInfo_AllFields(t *testing.T) {
	now := time.Now()
	pbCA := &pb.TenantIntermediateCAInfo{
		Id:           "int-ca-1",
		CommonName:   "Test Intermediate CA",
		SerialNumber: "0987654321",
		ParentType:   "root",
		Purpose:      "tls",
		KeyAlgorithm: "ECDSA-P384",
		NotBefore:    timestamppb.New(now),
		NotAfter:     timestamppb.New(now.Add(180 * 24 * time.Hour)),
		Status:       "active",
		CreatedAt:    timestamppb.New(now),
		UpdatedAt:    timestamppb.New(now),
	}

	result := pbToTenantIntCAInfo(pbCA)

	assert.NotNil(t, result)
	assert.Equal(t, "int-ca-1", result.ID)
	assert.Equal(t, "Test Intermediate CA", result.CommonName)
	assert.Equal(t, "0987654321", result.SerialNumber)
	assert.Equal(t, "root", result.ParentType)
	assert.Equal(t, "tls", result.Purpose)
	assert.Equal(t, "ECDSA-P384", result.KeyAlgorithm)
	assert.Equal(t, "active", result.Status)
}

func TestPbToDeviceInfo_Nil(t *testing.T) {
	result := pbToDeviceInfo(nil)
	assert.Nil(t, result)
}

func TestPbToDeviceInfo_AllFields(t *testing.T) {
	pbDevice := &pb.EABDeviceInfo{
		DeviceId:           "device-123",
		Manufacturer:       "ACME",
		Model:              "TestDevice",
		EkPublicKeyHash:    "sha256:abc123",
		TpmManufacturer:    "Infineon",
		TpmFirmwareVersion: "7.85",
		Metadata:           map[string]string{"key": "value"},
	}

	result := pbToDeviceInfo(pbDevice)

	assert.NotNil(t, result)
	assert.Equal(t, "device-123", result.DeviceID)
	assert.Equal(t, "ACME", result.Manufacturer)
	assert.Equal(t, "TestDevice", result.Model)
	assert.Equal(t, "sha256:abc123", result.EKPublicKeyHash)
	assert.Equal(t, "Infineon", result.TPMManufacturer)
	assert.Equal(t, "7.85", result.TPMFirmwareVersion)
	assert.Equal(t, map[string]string{"key": "value"}, result.Metadata)
}

func TestDeviceInfoToPb_Nil(t *testing.T) {
	result := deviceInfoToPb(nil)
	assert.Nil(t, result)
}

func TestDeviceInfoToPb_AllFields(t *testing.T) {
	device := &admin.EABDeviceInfoDTO{
		DeviceID:           "device-123",
		Manufacturer:       "ACME",
		Model:              "TestDevice",
		EKPublicKeyHash:    "sha256:abc123",
		TPMManufacturer:    "Infineon",
		TPMFirmwareVersion: "7.85",
		Metadata:           map[string]string{"key": "value"},
	}

	result := deviceInfoToPb(device)

	assert.NotNil(t, result)
	assert.Equal(t, "device-123", result.DeviceId)
	assert.Equal(t, "ACME", result.Manufacturer)
	assert.Equal(t, "TestDevice", result.Model)
	assert.Equal(t, "sha256:abc123", result.EkPublicKeyHash)
	assert.Equal(t, "Infineon", result.TpmManufacturer)
	assert.Equal(t, "7.85", result.TpmFirmwareVersion)
	assert.Equal(t, map[string]string{"key": "value"}, result.Metadata)
}

func TestPbToRole_Nil(t *testing.T) {
	result := pbToRole(nil)
	assert.Nil(t, result)
}

func TestPbToRole_AllFields(t *testing.T) {
	pbRole := &pb.Role{
		Id:          "role-1",
		Name:        "admin",
		TenantId:    "tenant-1",
		Permissions: []string{"read", "write", "delete"},
		System:      true,
		CreatedAt:   "2026-03-11T00:00:00Z",
		UpdatedAt:   "2026-03-11T12:00:00Z",
	}

	result := pbToRole(pbRole)

	assert.NotNil(t, result)
	assert.Equal(t, "role-1", result.ID)
	assert.Equal(t, "admin", result.Name)
	assert.Equal(t, "tenant-1", result.TenantID)
	assert.Equal(t, []string{"read", "write", "delete"}, result.Permissions)
	assert.True(t, result.System)
	assert.Equal(t, "2026-03-11T00:00:00Z", result.CreatedAt)
	assert.Equal(t, "2026-03-11T12:00:00Z", result.UpdatedAt)
}

func TestPbToUser_Nil(t *testing.T) {
	result, err := pbToUser(nil)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestPbToUser_AllFields(t *testing.T) {
	pbUser := &pb.User{
		Id:        "1",
		Username:  "alice",
		TenantId:  "tenant-1",
		RoleIds:   []string{"role-1", "role-2"},
		Enabled:   true,
		System:    false,
		CreatedAt: "2026-03-11T00:00:00Z",
		UpdatedAt: "2026-03-11T12:00:00Z",
	}

	result, err := pbToUser(pbUser)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, uint64(1), result.ID)
	assert.Equal(t, "alice", result.Username)
	assert.Equal(t, "tenant-1", result.TenantID)
	assert.Equal(t, []string{"role-1", "role-2"}, result.RoleIDs)
	assert.Equal(t, string(qrdbsdk.LifecycleActive), result.Lifecycle)
	assert.False(t, result.System)
	assert.Equal(t, "2026-03-11T00:00:00Z", result.CreatedAt)
	assert.Equal(t, "2026-03-11T12:00:00Z", result.UpdatedAt)
}

// =============================================================================
// withAuth Tests
// =============================================================================

func TestWithAuth_WithToken(t *testing.T) {
	adapter := newTestAdapter(&mockAdminServiceClient{}, "test-token-123")
	ctx := context.Background()

	authCtx := adapter.withAuth(ctx)

	// The context should have metadata added
	assert.NotEqual(t, ctx, authCtx)
}

func TestWithAuth_WithoutToken(t *testing.T) {
	adapter := newTestAdapter(&mockAdminServiceClient{}, "")
	ctx := context.Background()

	authCtx := adapter.withAuth(ctx)

	// The context should be unchanged
	assert.Equal(t, ctx, authCtx)
}

func TestPbToUser_DisabledMapsToDisabledLifecycle(t *testing.T) {
	result, err := pbToUser(&pb.User{Id: "2", Username: "bob", TenantId: "tenant-1", Enabled: false})

	require.NoError(t, err)
	assert.Equal(t, string(qrdbsdk.LifecycleDisabled), result.Lifecycle)
}
