//go:build grpc

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

// Package grpc provides gRPC protocol adapter for go-xkms services.
// Build with -tags=grpc after running 'make proto' to generate protobuf code.
package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"strconv"
	"strings"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/api"
	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
)

// Adapter implements AdminAdapter using gRPC.
type Adapter struct {
	conn         *grpc.ClientConn
	client       pb.AdminServiceClient
	authToken    string
	isUnixSocket bool
}

// NewAdapter creates a new gRPC adapter.
// It supports both TCP addresses and Unix socket paths.
//
// For TCP connections, use config.GRPCAddr (e.g., "localhost:9443")
// For Unix socket connections, use either:
//   - config.GRPCUnixPath (e.g., "/run/trusted-ca-grpc.sock")
//   - config.GRPCAddr with "unix://" prefix (e.g., "unix:///run/trusted-ca-grpc.sock")
//   - config.GRPCAddr with absolute path (e.g., "/run/trusted-ca-grpc.sock")
func NewAdapter(config *api.AdapterConfig) (*Adapter, error) {
	// Determine the address to use
	addr := config.GRPCAddr
	if addr == "" && config.GRPCUnixPath != "" {
		// Use GRPCUnixPath if GRPCAddr is not set
		addr = config.GRPCUnixPath
	}

	if addr == "" {
		return nil, caerrors.MalformedError("gRPC address is required (set GRPCAddr or GRPCUnixPath)")
	}

	var opts []grpc.DialOption
	isUnixSocket := isUnixSocketAddress(addr)

	if isUnixSocket {
		// Unix socket connection - no TLS needed for local IPC
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials())) // insecure-ok: Unix domain socket, no network path for a MITM. Allowlisted in Makefile check-insecure-tls.

		// Extract socket path, stripping unix:// prefix if present
		socketPath := stripUnixPrefix(addr)

		// Use custom dialer for Unix socket
		opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, dialAddr string) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, "unix", socketPath)
		}))
	} else {
		// TCP connection - configure TLS if provided
		if config.TLSConfig != nil {
			tlsConfig := &tls.Config{
				MinVersion: tls.VersionTLS13,
			}

			// Load client certificate if provided
			if config.TLSConfig.CertFile != "" && config.TLSConfig.KeyFile != "" {
				cert, err := tls.LoadX509KeyPair(config.TLSConfig.CertFile, config.TLSConfig.KeyFile)
				if err != nil {
					return nil, caerrors.TLSErrorCreate("failed to load client certificate: %v", err)
				}
				tlsConfig.Certificates = []tls.Certificate{cert}
			}

			// Load CA certificate if provided
			if config.TLSConfig.CAFile != "" {
				caCert, err := os.ReadFile(config.TLSConfig.CAFile)
				if err != nil {
					return nil, caerrors.TLSErrorCreate("failed to read CA certificate: %v", err)
				}
				caCertPool := x509.NewCertPool()
				caCertPool.AppendCertsFromPEM(caCert)
				tlsConfig.RootCAs = caCertPool
			}

			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		} else {
			// config.TLSConfig == nil is the caller's own explicit api.AdapterConfig choice.
			opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials())) // insecure-ok: explicit-config transport. Allowlisted in Makefile check-insecure-tls.
		}
	}

	// Determine the target address for gRPC
	target := addr
	if isUnixSocket {
		// Use passthrough resolver with Unix socket path for gRPC
		socketPath := stripUnixPrefix(addr)
		target = "passthrough:///" + socketPath
	}

	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, caerrors.ConnectionFailureError("failed to connect to gRPC server: %v", err)
	}

	return &Adapter{
		conn:         conn,
		client:       pb.NewAdminServiceClient(conn),
		authToken:    config.AuthToken,
		isUnixSocket: isUnixSocket,
	}, nil
}

// isUnixSocketAddress checks if the address is a Unix socket path.
// Returns true if the address starts with "unix://" or is an absolute path.
func isUnixSocketAddress(addr string) bool {
	return strings.HasPrefix(addr, "unix://") || strings.HasPrefix(addr, "/")
}

// stripUnixPrefix removes the "unix://" prefix from an address if present.
func stripUnixPrefix(addr string) string {
	return strings.TrimPrefix(addr, "unix://")
}

// Protocol returns the protocol this adapter uses.
func (a *Adapter) Protocol() api.Protocol {
	if a.isUnixSocket {
		return api.ProtocolUnix
	}
	return api.ProtocolGRPC
}

// Close closes the gRPC connection.
func (a *Adapter) Close() error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// withAuth adds authentication metadata to the context.
func (a *Adapter) withAuth(ctx context.Context) context.Context {
	if a.authToken != "" {
		return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+a.authToken)
	}
	return ctx
}

// Tenant Operations

// CreateTenant creates a new tenant.
func (a *Adapter) CreateTenant(ctx context.Context, req *admin.CreateTenantRequest) (*admin.TenantInfo, error) {
	pbReq := &pb.CreateTenantRequest{
		Id:   req.ID,
		Name: req.Name,
	}
	if req.Settings != nil {
		pbReq.Settings = tenantSettingsToPb(req.Settings)
	}
	resp, err := a.client.CreateTenant(a.withAuth(ctx), pbReq)
	if err != nil {
		return nil, err
	}
	return pbToTenantInfo(resp), nil
}

// GetTenant retrieves a tenant by ID.
func (a *Adapter) GetTenant(ctx context.Context, tenantID string) (*admin.TenantInfo, error) {
	resp, err := a.client.GetTenant(a.withAuth(ctx), &pb.GetTenantRequest{
		TenantId: tenantID,
	})
	if err != nil {
		return nil, err
	}
	return pbToTenantInfo(resp), nil
}

// UpdateTenant updates an existing tenant.
func (a *Adapter) UpdateTenant(ctx context.Context, tenantID string, req *admin.UpdateTenantRequest) (*admin.TenantInfo, error) {
	pbReq := &pb.UpdateTenantRequest{
		TenantId: tenantID,
		Name:     req.Name,
	}
	if req.Settings != nil {
		pbReq.Settings = tenantSettingsToPb(req.Settings)
	}
	resp, err := a.client.UpdateTenant(a.withAuth(ctx), pbReq)
	if err != nil {
		return nil, err
	}
	return pbToTenantInfo(resp), nil
}

// DeleteTenant deletes a tenant.
func (a *Adapter) DeleteTenant(ctx context.Context, tenantID string) error {
	_, err := a.client.DeleteTenant(a.withAuth(ctx), &pb.DeleteTenantRequest{
		TenantId: tenantID,
	})
	return err
}

// ListTenants lists all tenants.
func (a *Adapter) ListTenants(ctx context.Context, req *admin.ListTenantsRequest) ([]*admin.TenantInfo, *admin.Pagination, error) {
	if req.Status != "" {
		return nil, nil, admin.TenantStatusUnsupported()
	}
	resp, err := a.client.ListTenants(a.withAuth(ctx), &pb.ListTenantsRequest{
		Page:    int32(req.Page),
		PerPage: int32(req.PerPage),
	})
	if err != nil {
		return nil, nil, err
	}

	tenants := make([]*admin.TenantInfo, len(resp.Tenants))
	for i, t := range resp.Tenants {
		tenants[i] = pbToTenantInfo(t)
	}

	return tenants, pbToPagination(resp.Pagination), nil
}

// EAB Operations

// CreateEAB creates a new External Account Binding.
func (a *Adapter) CreateEAB(ctx context.Context, tenantID string, req *admin.CreateEABRequest) (*admin.CreateEABResponse, error) {
	pbReq := &pb.CreateEABRequest{
		TenantId:          tenantID,
		Purpose:           req.Purpose,
		ExpiresInDays:     int32(req.ExpiresInDays),
		Contact:           req.Contact,
		ExternalAccountId: req.ExternalAccountID,
	}
	if req.DeviceInfo != nil {
		pbReq.DeviceInfo = deviceInfoToPb(req.DeviceInfo)
	}
	resp, err := a.client.CreateEAB(a.withAuth(ctx), pbReq)
	if err != nil {
		return nil, err
	}

	result := &admin.CreateEABResponse{
		ID:        resp.Id,
		MACKey:    resp.MacKey,
		Algorithm: resp.Algorithm,
	}
	if resp.ExpiresAt != nil {
		expiresAt := resp.ExpiresAt.AsTime()
		result.ExpiresAt = &expiresAt
	}
	return result, nil
}

// GetEAB retrieves an EAB by ID.
func (a *Adapter) GetEAB(ctx context.Context, tenantID, kid string) (*admin.EABInfo, error) {
	resp, err := a.client.GetEAB(a.withAuth(ctx), &pb.GetEABRequest{
		TenantId: tenantID,
		Kid:      kid,
	})
	if err != nil {
		return nil, err
	}
	return pbToEABInfo(resp), nil
}

// DeleteEAB deletes an EAB.
func (a *Adapter) DeleteEAB(ctx context.Context, tenantID, kid string) error {
	_, err := a.client.DeleteEAB(a.withAuth(ctx), &pb.DeleteEABRequest{
		TenantId: tenantID,
		Kid:      kid,
	})
	return err
}

// ListEABs lists all EABs for a tenant.
func (a *Adapter) ListEABs(ctx context.Context, tenantID string, req *admin.ListEABRequest) ([]*admin.EABInfo, *admin.Pagination, error) {
	resp, err := a.client.ListEABs(a.withAuth(ctx), &pb.ListEABsRequest{
		TenantId: tenantID,
		Page:     int32(req.Page),
		PerPage:  int32(req.PerPage),
	})
	if err != nil {
		return nil, nil, err
	}

	eabs := make([]*admin.EABInfo, len(resp.Eabs))
	for i, e := range resp.Eabs {
		eabs[i] = pbToEABInfo(e)
	}

	return eabs, pbToPagination(resp.Pagination), nil
}

// Role Operations

// CreateTenantRole creates a new role within a tenant.
func (a *Adapter) CreateTenantRole(ctx context.Context, tenantID string, req *db.CreateRoleRequest) (*db.Role, error) {
	resp, err := a.client.CreateTenantRole(a.withAuth(ctx), &pb.CreateTenantRoleRequest{
		TenantId:    tenantID,
		Name:        req.Name,
		Permissions: req.Permissions,
	})
	if err != nil {
		return nil, err
	}
	return pbToRole(resp), nil
}

// GetTenantRole retrieves a role by ID.
func (a *Adapter) GetTenantRole(ctx context.Context, tenantID, roleID string) (*db.Role, error) {
	resp, err := a.client.GetTenantRole(a.withAuth(ctx), &pb.GetTenantRoleRequest{
		TenantId: tenantID,
		RoleId:   roleID,
	})
	if err != nil {
		return nil, err
	}
	return pbToRole(resp), nil
}

// UpdateTenantRole updates an existing role.
func (a *Adapter) UpdateTenantRole(ctx context.Context, tenantID string, req *db.UpdateRoleRequest) (*db.Role, error) {
	resp, err := a.client.UpdateTenantRole(a.withAuth(ctx), &pb.UpdateTenantRoleRequest{
		TenantId:    tenantID,
		RoleId:      req.ID,
		Name:        req.Name,
		Permissions: req.Permissions,
	})
	if err != nil {
		return nil, err
	}
	return pbToRole(resp), nil
}

// DeleteTenantRole deletes a role.
func (a *Adapter) DeleteTenantRole(ctx context.Context, tenantID, roleID string) error {
	_, err := a.client.DeleteTenantRole(a.withAuth(ctx), &pb.DeleteTenantRoleRequest{
		TenantId: tenantID,
		RoleId:   roleID,
	})
	return err
}

// ListTenantRoles lists all roles for a tenant.
func (a *Adapter) ListTenantRoles(ctx context.Context, tenantID string, req *db.ListRolesRequest) (*db.ListRolesResponse, error) {
	resp, err := a.client.ListTenantRoles(a.withAuth(ctx), &pb.ListTenantRolesRequest{
		TenantId: tenantID,
		Page:     int32(req.Page),
		PageSize: int32(req.PageSize),
	})
	if err != nil {
		return nil, err
	}

	roles := make([]*db.Role, len(resp.Roles))
	for i, r := range resp.Roles {
		roles[i] = pbToRole(r)
	}

	return &db.ListRolesResponse{
		Roles:   roles,
		Total:   int(resp.Total),
		HasMore: resp.HasMore,
	}, nil
}

// User Operations

// CreateTenantUser creates a new user within a tenant.
func (a *Adapter) CreateTenantUser(ctx context.Context, tenantID string, req *db.CreateUserRequest) (*db.User, error) {
	resp, err := a.client.CreateTenantUser(a.withAuth(ctx), &pb.CreateTenantUserRequest{
		TenantId: tenantID,
		Username: req.Username,
		RoleIds:  req.RoleIDs,
	})
	if err != nil {
		return nil, err
	}
	return pbToUser(resp)
}

// GetTenantUser retrieves a user by ID.
func (a *Adapter) GetTenantUser(ctx context.Context, tenantID, userID string) (*db.User, error) {
	resp, err := a.client.GetTenantUser(a.withAuth(ctx), &pb.GetTenantUserRequest{
		TenantId: tenantID,
		UserId:   userID,
	})
	if err != nil {
		return nil, err
	}
	return pbToUser(resp)
}

// UpdateTenantUser updates an existing user.
func (a *Adapter) UpdateTenantUser(ctx context.Context, tenantID string, req *db.UpdateUserRequest) (*db.User, error) {
	resp, err := a.client.UpdateTenantUser(a.withAuth(ctx), &pb.UpdateTenantUserRequest{
		TenantId: tenantID,
		UserId:   strconv.FormatUint(req.ID, 10),
		Username: req.Username,
		RoleIds:  req.RoleIDs,
	})
	if err != nil {
		return nil, err
	}
	return pbToUser(resp)
}

// DeleteTenantUser deletes a user.
func (a *Adapter) DeleteTenantUser(ctx context.Context, tenantID, userID string) error {
	_, err := a.client.DeleteTenantUser(a.withAuth(ctx), &pb.DeleteTenantUserRequest{
		TenantId: tenantID,
		UserId:   userID,
	})
	return err
}

// ListTenantUsers lists all users for a tenant.
func (a *Adapter) ListTenantUsers(ctx context.Context, tenantID string, req *db.ListUsersRequest) (*db.ListUsersResponse, error) {
	resp, err := a.client.ListTenantUsers(a.withAuth(ctx), &pb.ListTenantUsersRequest{
		TenantId: tenantID,
		Page:     int32(req.Page),
		PageSize: int32(req.PageSize),
	})
	if err != nil {
		return nil, err
	}

	users := make([]*db.User, len(resp.Users))
	for i, u := range resp.Users {
		converted, cErr := pbToUser(u)
		if cErr != nil {
			return nil, cErr
		}
		users[i] = converted
	}

	return &db.ListUsersResponse{
		Users:   users,
		Total:   int(resp.Total),
		HasMore: resp.HasMore,
	}, nil
}

// Certificate Operations

// ListCertificates lists certificates with optional filtering.
func (a *Adapter) ListCertificates(ctx context.Context, req *admin.ListCertificatesRequest) ([]*admin.CertificateInfo, *admin.Pagination, error) {
	resp, err := a.client.ListCertificates(a.withAuth(ctx), &pb.ListCertificatesRequest{
		Page:    int32(req.Page),
		PerPage: int32(req.PerPage),
		Status:  req.Status,
	})
	if err != nil {
		return nil, nil, err
	}

	certs := make([]*admin.CertificateInfo, len(resp.Certificates))
	for i, c := range resp.Certificates {
		certs[i] = pbToCertificateInfo(c)
	}

	return certs, pbToPagination(resp.Pagination), nil
}

// GetCertificate retrieves a certificate by serial number.
func (a *Adapter) GetCertificate(ctx context.Context, serial string) (*admin.CertificateInfo, error) {
	resp, err := a.client.GetCertificate(a.withAuth(ctx), &pb.GetCertificateRequest{
		Serial: serial,
	})
	if err != nil {
		return nil, err
	}
	return pbToCertificateInfo(resp), nil
}

// RevokeCertificate revokes a certificate.
func (a *Adapter) RevokeCertificate(ctx context.Context, serial, reason string) error {
	_, err := a.client.RevokeCertificate(a.withAuth(ctx), &pb.RevokeCertificateRequest{
		Serial: serial,
		Reason: reason,
	})
	return err
}

// Account Operations

// ListAccounts lists ACME accounts with optional filtering.
func (a *Adapter) ListAccounts(ctx context.Context, req *admin.ListAccountsRequest) ([]*admin.AccountInfo, *admin.Pagination, error) {
	resp, err := a.client.ListAccounts(a.withAuth(ctx), &pb.ListAccountsRequest{
		Page:    int32(req.Page),
		PerPage: int32(req.PerPage),
		Status:  req.Status,
	})
	if err != nil {
		return nil, nil, err
	}

	accounts := make([]*admin.AccountInfo, len(resp.Accounts))
	for i, acc := range resp.Accounts {
		accounts[i] = pbToAccountInfo(acc)
	}

	return accounts, pbToPagination(resp.Pagination), nil
}

// GetAccount retrieves an ACME account by ID.
func (a *Adapter) GetAccount(ctx context.Context, accountID uint64) (*admin.AccountInfo, error) {
	resp, err := a.client.GetAccount(a.withAuth(ctx), &pb.GetAccountRequest{
		AccountId: accountID,
	})
	if err != nil {
		return nil, err
	}
	return pbToAccountInfo(resp), nil
}

// DisableAccount disables an ACME account.
func (a *Adapter) DisableAccount(ctx context.Context, accountID uint64) error {
	_, err := a.client.DisableAccount(a.withAuth(ctx), &pb.DisableAccountRequest{
		AccountId: accountID,
	})
	return err
}

// Status Operations

// GetStatus returns the CA status.
func (a *Adapter) GetStatus(ctx context.Context) (*admin.CAStatus, error) {
	resp, err := a.client.GetStatus(a.withAuth(ctx), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	status := &admin.CAStatus{
		Identity:      resp.Identity,
		Initialized:   resp.Initialized,
		Version:       resp.Version,
		KeyAlgorithm:  resp.KeyAlgorithm,
		SignatureAlgo: resp.SignatureAlgo,
		RootCA:        resp.RootCa,
	}
	if resp.StartedAt != nil {
		status.StartedAt = resp.StartedAt.AsTime()
	}
	if resp.IntermediateCa != "" {
		status.IntermediateCA = resp.IntermediateCa
	}

	return status, nil
}

// GetStats returns CA statistics.
func (a *Adapter) GetStats(ctx context.Context) (*admin.CAStats, error) {
	resp, err := a.client.GetStats(a.withAuth(ctx), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}

	return &admin.CAStats{
		TotalCertificates:   int(resp.TotalCertificates),
		ValidCertificates:   int(resp.ValidCertificates),
		RevokedCertificates: int(resp.RevokedCertificates),
		ExpiredCertificates: int(resp.ExpiredCertificates),
		TotalAccounts:       int(resp.TotalAccounts),
		ActiveAccounts:      int(resp.ActiveAccounts),
		TotalOrders:         int(resp.TotalOrders),
		PendingOrders:       int(resp.PendingOrders),
		CompletedOrders:     int(resp.CompletedOrders),
	}, nil
}

// Order Operations

// ListOrders lists orders with optional filtering.
func (a *Adapter) ListOrders(_ context.Context, _ *admin.ListOrdersRequest) ([]*admin.OrderInfo, *admin.Pagination, error) {
	return nil, nil, admin.ErrRESTOnly
}

// GetOrder retrieves an order by ID.
func (a *Adapter) GetOrder(_ context.Context, _ uint64, _ uint64) (*admin.OrderInfo, error) {
	return nil, admin.ErrRESTOnly
}

// Tenant CA Operations

// UpdateTenantStatus updates a tenant's status.
func (a *Adapter) UpdateTenantStatus(_ context.Context, _ string, _ string) error {
	return admin.TenantStatusUnsupported()
}

// CreateTenantRootCA creates a root CA for a tenant.
func (a *Adapter) CreateTenantRootCA(_ context.Context, _ string, _ *admin.CreateTenantRootCARequest) (*admin.TenantRootCAInfo, error) {
	return nil, admin.ErrRESTOnly
}

// GetTenantCAStatus retrieves the CA status for a tenant.
func (a *Adapter) GetTenantCAStatus(_ context.Context, _ string) (*admin.TenantCAStatusInfo, error) {
	return nil, admin.ErrRESTOnly
}

// CreateTenantIntermediateCA creates an intermediate CA for a tenant.
func (a *Adapter) CreateTenantIntermediateCA(_ context.Context, _ string, _ *admin.CreateTenantIntermediateCARequest) (*admin.TenantIntCAInfo, error) {
	return nil, admin.ErrRESTOnly
}

// ListTenantIntermediateCAs lists all intermediate CAs for a tenant.
func (a *Adapter) ListTenantIntermediateCAs(_ context.Context, _ string) ([]*admin.TenantIntCAInfo, error) {
	return nil, admin.ErrRESTOnly
}

// GetTenantIntermediateCA retrieves a specific intermediate CA.
func (a *Adapter) GetTenantIntermediateCA(_ context.Context, _ string, _ string) (*admin.TenantIntCAInfo, error) {
	return nil, admin.ErrRESTOnly
}

// UpdateTenantIntermediateCAStatus updates an intermediate CA's status.
func (a *Adapter) UpdateTenantIntermediateCAStatus(_ context.Context, _ string, _ string, _ string) error {
	return admin.ErrRESTOnly
}

// Verify interface compliance.
var _ api.AdminAdapter = (*Adapter)(nil)

// Conversion helpers

func pbToRole(r *pb.Role) *db.Role {
	if r == nil {
		return nil
	}
	return &db.Role{
		ID:          r.Id,
		Name:        r.Name,
		TenantID:    r.TenantId,
		Permissions: r.Permissions,
		System:      r.System,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func pbToUser(u *pb.User) (*db.User, error) {
	if u == nil {
		return nil, nil
	}
	var id uint64
	if u.Id != "" {
		parsed, err := strconv.ParseUint(u.Id, 10, 64)
		if err != nil {
			return nil, caerrors.NewValidationError("user_id", "not a uint64", u.Id)
		}
		id = parsed
	}
	lifecycle := qrdbsdk.LifecycleActive
	if !u.Enabled {
		lifecycle = qrdbsdk.LifecycleDisabled
	}
	return &db.User{
		ID:        id,
		Username:  u.Username,
		TenantID:  u.TenantId,
		RoleIDs:   u.RoleIds,
		Lifecycle: string(lifecycle),
		System:    u.System,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}, nil
}

func pbToTenantInfo(t *pb.TenantInfo) *admin.TenantInfo {
	if t == nil {
		return nil
	}
	info := &admin.TenantInfo{
		ID:        t.Id,
		Name:      t.Name,
		Status:    t.Status,
		CreatedBy: t.CreatedBy,
	}
	if t.CreatedAt != nil {
		info.CreatedAt = t.CreatedAt.AsTime()
	}
	if t.UpdatedAt != nil {
		info.UpdatedAt = t.UpdatedAt.AsTime()
	}
	if t.Settings != nil {
		info.Settings = pbToTenantSettings(t.Settings)
	}
	if t.RootCa != nil {
		info.RootCA = pbToTenantRootCAInfo(t.RootCa)
	}
	if len(t.IntermediateCas) > 0 {
		info.IntermediateCAs = make([]*admin.TenantIntCAInfo, len(t.IntermediateCas))
		for i, ca := range t.IntermediateCas {
			info.IntermediateCAs[i] = pbToTenantIntCAInfo(ca)
		}
	}
	info.DefaultIntermediateCAID = t.DefaultIntermediateCaId
	return info
}

func pbToPagination(p *pb.Pagination) *admin.Pagination {
	if p == nil {
		return nil
	}
	return &admin.Pagination{
		Page:    int(p.Page),
		PerPage: int(p.PerPage),
		Total:   int(p.Total),
	}
}

func pbToEABInfo(e *pb.EABInfo) *admin.EABInfo {
	if e == nil {
		return nil
	}
	info := &admin.EABInfo{
		ID:                e.Id,
		TenantID:          e.TenantId,
		Purpose:           e.Purpose,
		Status:            e.Status,
		Contact:           e.Contact,
		AccountID:         e.AccountId,
		ExternalAccountID: e.ExternalAccountId,
		CreatedBy:         e.CreatedBy,
	}
	if e.CreatedAt != nil {
		info.CreatedAt = e.CreatedAt.AsTime()
	}
	if e.ExpiresAt != nil {
		expiresAt := e.ExpiresAt.AsTime()
		info.ExpiresAt = &expiresAt
	}
	if e.UsedAt != nil {
		usedAt := e.UsedAt.AsTime()
		info.UsedAt = &usedAt
	}
	if e.DeviceInfo != nil {
		info.DeviceInfo = pbToDeviceInfo(e.DeviceInfo)
	}
	return info
}

func pbToCertificateInfo(c *pb.CertificateInfo) *admin.CertificateInfo {
	if c == nil {
		return nil
	}
	info := &admin.CertificateInfo{
		SerialNumber: c.SerialNumber,
		Subject:      c.Subject,
		Issuer:       c.Issuer,
		Status:       c.Status,
		CertURL:      c.CertUrl,
	}
	if c.NotBefore != nil {
		info.NotBefore = c.NotBefore.AsTime()
	}
	if c.NotAfter != nil {
		info.NotAfter = c.NotAfter.AsTime()
	}
	if c.IssuedAt != nil {
		info.IssuedAt = c.IssuedAt.AsTime()
	}
	return info
}

func pbToAccountInfo(a *pb.AccountInfo) *admin.AccountInfo {
	if a == nil {
		return nil
	}
	info := &admin.AccountInfo{
		ID:                   admin.FlexUint64(a.Id),
		Status:               a.Status,
		Contact:              a.Contact,
		TermsOfServiceAgreed: a.TermsOfServiceAgreed,
		OrdersURL:            a.OrdersUrl,
		OrderCount:           int(a.OrderCount),
	}
	if a.CreatedAt != nil {
		info.CreatedAt = a.CreatedAt.AsTime()
	}
	return info
}

func pbToTenantSettings(s *pb.TenantSettings) *admin.TenantSettingsInfo {
	if s == nil {
		return nil
	}
	return &admin.TenantSettingsInfo{
		MaxCertificates:         int(s.MaxCertificates),
		MaxAccounts:             int(s.MaxAccounts),
		AllowedKeyAlgorithms:    s.AllowedKeyAlgorithms,
		AllowedChallengeTypes:   s.AllowedChallengeTypes,
		CertificateValidityDays: int(s.CertificateValidityDays),
		RequireEAB:              s.RequireEab,
		AllowEndorse01:          s.AllowEndorse_01,
		AllowEnroll01:           s.AllowEnroll_01,
	}
}

func tenantSettingsToPb(s *admin.TenantSettingsInfo) *pb.TenantSettings {
	if s == nil {
		return nil
	}
	return &pb.TenantSettings{
		MaxCertificates:         int32(s.MaxCertificates),
		MaxAccounts:             int32(s.MaxAccounts),
		AllowedKeyAlgorithms:    s.AllowedKeyAlgorithms,
		AllowedChallengeTypes:   s.AllowedChallengeTypes,
		CertificateValidityDays: int32(s.CertificateValidityDays),
		RequireEab:              s.RequireEAB,
		AllowEndorse_01:         s.AllowEndorse01,
		AllowEnroll_01:          s.AllowEnroll01,
	}
}

func pbToTenantRootCAInfo(ca *pb.TenantRootCAInfo) *admin.TenantRootCAInfo {
	if ca == nil {
		return nil
	}
	info := &admin.TenantRootCAInfo{
		CommonName:   ca.CommonName,
		SerialNumber: ca.SerialNumber,
		KeyAlgorithm: ca.KeyAlgorithm,
		Status:       ca.Status,
	}
	if ca.NotBefore != nil {
		info.NotBefore = ca.NotBefore.AsTime()
	}
	if ca.NotAfter != nil {
		info.NotAfter = ca.NotAfter.AsTime()
	}
	if ca.CreatedAt != nil {
		info.CreatedAt = ca.CreatedAt.AsTime()
	}
	return info
}

func pbToTenantIntCAInfo(ca *pb.TenantIntermediateCAInfo) *admin.TenantIntCAInfo {
	if ca == nil {
		return nil
	}
	info := &admin.TenantIntCAInfo{
		ID:           ca.Id,
		CommonName:   ca.CommonName,
		SerialNumber: ca.SerialNumber,
		ParentType:   ca.ParentType,
		Purpose:      ca.Purpose,
		KeyAlgorithm: ca.KeyAlgorithm,
		Status:       ca.Status,
	}
	if ca.NotBefore != nil {
		info.NotBefore = ca.NotBefore.AsTime()
	}
	if ca.NotAfter != nil {
		info.NotAfter = ca.NotAfter.AsTime()
	}
	if ca.CreatedAt != nil {
		info.CreatedAt = ca.CreatedAt.AsTime()
	}
	if ca.UpdatedAt != nil {
		info.UpdatedAt = ca.UpdatedAt.AsTime()
	}
	return info
}

func pbToDeviceInfo(d *pb.EABDeviceInfo) *admin.EABDeviceInfoDTO {
	if d == nil {
		return nil
	}
	return &admin.EABDeviceInfoDTO{
		DeviceID:           d.DeviceId,
		Manufacturer:       d.Manufacturer,
		Model:              d.Model,
		EKPublicKeyHash:    d.EkPublicKeyHash,
		TPMManufacturer:    d.TpmManufacturer,
		TPMFirmwareVersion: d.TpmFirmwareVersion,
		Metadata:           d.Metadata,
	}
}

func deviceInfoToPb(d *admin.EABDeviceInfoDTO) *pb.EABDeviceInfo {
	if d == nil {
		return nil
	}
	return &pb.EABDeviceInfo{
		DeviceId:           d.DeviceID,
		Manufacturer:       d.Manufacturer,
		Model:              d.Model,
		EkPublicKeyHash:    d.EKPublicKeyHash,
		TpmManufacturer:    d.TPMManufacturer,
		TpmFirmwareVersion: d.TPMFirmwareVersion,
		Metadata:           d.Metadata,
	}
}
