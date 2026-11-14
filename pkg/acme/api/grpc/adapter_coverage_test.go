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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
)

// writeTestKeyPair writes a self-signed ECDSA P-256 certificate and its key
// as PEM files in dir and returns their paths.
func writeTestKeyPair(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "grpc-adapter-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}

func TestNewAdapter_Transports(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestKeyPair(t, dir)

	tests := []struct {
		name     string
		config   *api.AdapterConfig
		protocol api.Protocol
	}{
		{
			name:     "unix scheme address",
			config:   &api.AdapterConfig{GRPCAddr: "unix://" + filepath.Join(dir, "admin.sock")},
			protocol: api.ProtocolUnix,
		},
		{
			name:     "absolute socket path",
			config:   &api.AdapterConfig{GRPCAddr: filepath.Join(dir, "admin.sock")},
			protocol: api.ProtocolUnix,
		},
		{
			name:     "unix path used when no address is set",
			config:   &api.AdapterConfig{GRPCUnixPath: filepath.Join(dir, "admin.sock")},
			protocol: api.ProtocolUnix,
		},
		{
			name:     "tcp without TLS config",
			config:   &api.AdapterConfig{GRPCAddr: "localhost:50051"},
			protocol: api.ProtocolGRPC,
		},
		{
			name:     "tcp with empty TLS config",
			config:   &api.AdapterConfig{GRPCAddr: "localhost:50051", TLSConfig: &api.TLSConfig{}},
			protocol: api.ProtocolGRPC,
		},
		{
			name: "tcp with client certificate and CA",
			config: &api.AdapterConfig{
				GRPCAddr:  "localhost:50051",
				AuthToken: "token",
				TLSConfig: &api.TLSConfig{CertFile: certFile, KeyFile: keyFile, CAFile: certFile},
			},
			protocol: api.ProtocolGRPC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, err := NewAdapter(tt.config)
			require.NoError(t, err)
			require.NotNil(t, adapter)
			assert.Equal(t, tt.protocol, adapter.Protocol())
			assert.Equal(t, tt.config.AuthToken, adapter.authToken)
			assert.NoError(t, adapter.Close())
		})
	}
}

func TestNewAdapter_TLSRefusals(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestKeyPair(t, dir)
	missing := filepath.Join(dir, "missing.pem")

	tests := []struct {
		name    string
		tls     *api.TLSConfig
		wantMsg string
	}{
		{
			name:    "client certificate file missing",
			tls:     &api.TLSConfig{CertFile: missing, KeyFile: keyFile},
			wantMsg: "failed to load client certificate",
		},
		{
			name:    "client key does not match",
			tls:     &api.TLSConfig{CertFile: certFile, KeyFile: certFile},
			wantMsg: "failed to load client certificate",
		},
		{
			name:    "CA file missing",
			tls:     &api.TLSConfig{CAFile: missing},
			wantMsg: "failed to read CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, err := NewAdapter(&api.AdapterConfig{GRPCAddr: "localhost:50051", TLSConfig: tt.tls})
			require.Error(t, err)
			assert.Nil(t, adapter)
			assert.Contains(t, err.Error(), tt.wantMsg)
		})
	}
}

func TestNewAdapter_MissingAddressIsMalformed(t *testing.T) {
	adapter, err := NewAdapter(&api.AdapterConfig{AuthToken: "token"})
	require.Error(t, err)
	assert.Nil(t, adapter)
	assert.True(t, caerrors.IsType(err, caerrors.Malformed))
}

func TestUnixAddressHelpers(t *testing.T) {
	tests := []struct {
		addr     string
		isUnix   bool
		stripped string
	}{
		{addr: "unix:///run/xkms.sock", isUnix: true, stripped: "/run/xkms.sock"},
		{addr: "/run/xkms.sock", isUnix: true, stripped: "/run/xkms.sock"},
		{addr: "localhost:50051", isUnix: false, stripped: "localhost:50051"},
		{addr: "dns:///ca.example:443", isUnix: false, stripped: "dns:///ca.example:443"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			assert.Equal(t, tt.isUnix, isUnixSocketAddress(tt.addr))
			assert.Equal(t, tt.stripped, stripUnixPrefix(tt.addr))
		})
	}
}

func TestUpdateTenant_WithSettings(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		updateTenantFunc: func(ctx context.Context, in *pb.UpdateTenantRequest, opts ...grpc.CallOption) (*pb.TenantInfo, error) {
			require.NotNil(t, in.Settings)
			assert.Equal(t, int32(5), in.Settings.MaxAccounts)
			assert.True(t, in.Settings.RequireEab)
			return &pb.TenantInfo{Id: in.TenantId, Name: in.Name, Settings: in.Settings}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	result, err := adapter.UpdateTenant(context.Background(), "tenant-1", &admin.UpdateTenantRequest{
		Name:     "Renamed",
		Settings: &admin.TenantSettingsInfo{MaxAccounts: 5, RequireEAB: true},
	})

	require.NoError(t, err)
	assert.Equal(t, "Renamed", result.Name)
	require.NotNil(t, result.Settings)
	assert.Equal(t, 5, result.Settings.MaxAccounts)
	assert.True(t, result.Settings.RequireEAB)
}

func TestListTenantUsers_InvalidUserID(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		listTenantUsersFunc: func(ctx context.Context, in *pb.ListTenantUsersRequest, opts ...grpc.CallOption) (*pb.ListTenantUsersResponse, error) {
			return &pb.ListTenantUsersResponse{
				Users: []*pb.User{
					{Id: "1", Username: "alice", Enabled: true},
					{Id: "not-a-number", Username: "mallory", Enabled: true},
				},
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	result, err := adapter.ListTenantUsers(context.Background(), "tenant-1", &db.ListUsersRequest{Page: 1, PageSize: 10})

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "user_id")
}

func TestPbToUser_InvalidID(t *testing.T) {
	user, err := pbToUser(&pb.User{Id: "-1", Username: "alice"})
	require.Error(t, err)
	assert.Nil(t, user)
}

func TestPbToUser_EmptyIDIsZero(t *testing.T) {
	user, err := pbToUser(&pb.User{Username: "alice", Enabled: true})
	require.NoError(t, err)
	assert.Equal(t, uint64(0), user.ID)
	assert.Equal(t, "alice", user.Username)
}

// =============================================================================
// Account Operation Tests
// =============================================================================

func TestListAccounts_Success(t *testing.T) {
	created := time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC)
	mockClient := &mockAdminServiceClient{
		listAccountsFunc: func(ctx context.Context, in *pb.ListAccountsRequest, opts ...grpc.CallOption) (*pb.ListAccountsResponse, error) {
			assert.Equal(t, int32(2), in.Page)
			assert.Equal(t, int32(25), in.PerPage)
			assert.Equal(t, "valid", in.Status)
			return &pb.ListAccountsResponse{
				Accounts: []*pb.AccountInfo{
					{
						Id:                   7,
						Status:               "valid",
						Contact:              []string{"mailto:ops@example.com"},
						CreatedAt:            timestamppb.New(created),
						TermsOfServiceAgreed: true,
						OrdersUrl:            "https://ca.example/acme/orders/7",
						OrderCount:           3,
					},
					{Id: 8, Status: "valid"},
				},
				Pagination: &pb.Pagination{Page: 2, PerPage: 25, Total: 27},
			}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "token")
	accounts, pagination, err := adapter.ListAccounts(context.Background(), &admin.ListAccountsRequest{
		Page:    2,
		PerPage: 25,
		Status:  "valid",
	})

	require.NoError(t, err)
	require.Len(t, accounts, 2)
	assert.Equal(t, admin.FlexUint64(7), accounts[0].ID)
	assert.Equal(t, "valid", accounts[0].Status)
	assert.Equal(t, []string{"mailto:ops@example.com"}, accounts[0].Contact)
	assert.True(t, accounts[0].CreatedAt.Equal(created))
	assert.True(t, accounts[0].TermsOfServiceAgreed)
	assert.Equal(t, "https://ca.example/acme/orders/7", accounts[0].OrdersURL)
	assert.Equal(t, 3, accounts[0].OrderCount)
	assert.True(t, accounts[1].CreatedAt.IsZero())
	assert.Equal(t, &admin.Pagination{Page: 2, PerPage: 25, Total: 27}, pagination)
}

func TestListAccounts_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		listAccountsFunc: func(ctx context.Context, in *pb.ListAccountsRequest, opts ...grpc.CallOption) (*pb.ListAccountsResponse, error) {
			return nil, errors.New("list failed")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	accounts, pagination, err := adapter.ListAccounts(context.Background(), &admin.ListAccountsRequest{})

	require.Error(t, err)
	assert.Nil(t, accounts)
	assert.Nil(t, pagination)
}

func TestGetAccount_Success(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getAccountFunc: func(ctx context.Context, in *pb.GetAccountRequest, opts ...grpc.CallOption) (*pb.AccountInfo, error) {
			assert.Equal(t, uint64(42), in.AccountId)
			return &pb.AccountInfo{Id: in.AccountId, Status: "deactivated"}, nil
		},
	}

	adapter := newTestAdapter(mockClient, "")
	account, err := adapter.GetAccount(context.Background(), 42)

	require.NoError(t, err)
	assert.Equal(t, admin.FlexUint64(42), account.ID)
	assert.Equal(t, "deactivated", account.Status)
}

func TestGetAccount_Error(t *testing.T) {
	mockClient := &mockAdminServiceClient{
		getAccountFunc: func(ctx context.Context, in *pb.GetAccountRequest, opts ...grpc.CallOption) (*pb.AccountInfo, error) {
			return nil, errors.New("not found")
		},
	}

	adapter := newTestAdapter(mockClient, "")
	account, err := adapter.GetAccount(context.Background(), 42)

	require.Error(t, err)
	assert.Nil(t, account)
}

func TestDisableAccount(t *testing.T) {
	tests := []struct {
		name    string
		callErr error
	}{
		{name: "success"},
		{name: "server error", callErr: errors.New("disable failed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotID uint64
			mockClient := &mockAdminServiceClient{
				disableAccountFunc: func(ctx context.Context, in *pb.DisableAccountRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
					gotID = in.AccountId
					if tt.callErr != nil {
						return nil, tt.callErr
					}
					return &emptypb.Empty{}, nil
				},
			}

			adapter := newTestAdapter(mockClient, "")
			err := adapter.DisableAccount(context.Background(), 9)

			assert.Equal(t, uint64(9), gotID)
			if tt.callErr != nil {
				assert.ErrorIs(t, err, tt.callErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestPbToAccountInfo_Nil(t *testing.T) {
	assert.Nil(t, pbToAccountInfo(nil))
}

// =============================================================================
// REST-only Operation Tests
// =============================================================================

func TestRESTOnlyOperations(t *testing.T) {
	ctx := context.Background()
	adapter := newTestAdapter(&mockAdminServiceClient{}, "")

	tests := []struct {
		name string
		call func() (any, error)
	}{
		{name: "ListOrders", call: func() (any, error) {
			orders, pagination, err := adapter.ListOrders(ctx, &admin.ListOrdersRequest{})
			assert.Nil(t, pagination)
			return orders, err
		}},
		{name: "GetOrder", call: func() (any, error) { return adapter.GetOrder(ctx, 1, 2) }},
		{name: "UpdateTenantStatus", call: func() (any, error) {
			return nil, adapter.UpdateTenantStatus(ctx, "tenant-1", "suspended")
		}},
		{name: "CreateTenantRootCA", call: func() (any, error) {
			return adapter.CreateTenantRootCA(ctx, "tenant-1", &admin.CreateTenantRootCARequest{})
		}},
		{name: "GetTenantCAStatus", call: func() (any, error) { return adapter.GetTenantCAStatus(ctx, "tenant-1") }},
		{name: "CreateTenantIntermediateCA", call: func() (any, error) {
			return adapter.CreateTenantIntermediateCA(ctx, "tenant-1", &admin.CreateTenantIntermediateCARequest{})
		}},
		{name: "ListTenantIntermediateCAs", call: func() (any, error) {
			return adapter.ListTenantIntermediateCAs(ctx, "tenant-1")
		}},
		{name: "GetTenantIntermediateCA", call: func() (any, error) {
			return adapter.GetTenantIntermediateCA(ctx, "tenant-1", "int-1")
		}},
		{name: "UpdateTenantIntermediateCAStatus", call: func() (any, error) {
			return nil, adapter.UpdateTenantIntermediateCAStatus(ctx, "tenant-1", "int-1", "revoked")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.call()
			assert.ErrorIs(t, err, admin.ErrRESTOnly)
			assert.Nil(t, result)
		})
	}
}
