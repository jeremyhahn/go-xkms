// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package server

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	adminv1 "github.com/jeremyhahn/go-xkms/api/proto/admin/v1"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
)

// adminServiceServer implements the gRPC AdminServiceServer interface.
type adminServiceServer struct {
	adminv1.UnimplementedAdminServiceServer
	adminService  admin.Service
	tenantService admin.TenantService
	logger        *slog.Logger
}

// NewAdminServiceServer creates a new gRPC AdminServiceServer.
func NewAdminServiceServer(
	adminService admin.Service,
	tenantService admin.TenantService,
	logger *slog.Logger,
) adminv1.AdminServiceServer {
	return &adminServiceServer{
		adminService:  adminService,
		tenantService: tenantService,
		logger:        logger,
	}
}

// Tenant operations

func (s *adminServiceServer) CreateTenant(ctx context.Context, req *adminv1.CreateTenantRequest) (*adminv1.TenantInfo, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	// Auto-generate ID if not provided
	tenantID := req.Id
	if tenantID == "" {
		tenantID = fmt.Sprintf("tenant-%d", time.Now().UnixNano())
	}

	adminReq := admin.CreateTenantRequest{
		ID:   tenantID,
		Name: req.Name,
	}
	if req.Settings != nil {
		adminReq.Settings = convertProtoSettingsToAdmin(req.Settings)
	}

	tenant, err := s.tenantService.CreateTenant(ctx, adminReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return convertAdminTenantToProto(tenant), nil
}

func (s *adminServiceServer) GetTenant(ctx context.Context, req *adminv1.GetTenantRequest) (*adminv1.TenantInfo, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	tenant, err := s.tenantService.GetTenant(ctx, req.TenantId)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return convertAdminTenantToProto(tenant), nil
}

func (s *adminServiceServer) UpdateTenant(ctx context.Context, req *adminv1.UpdateTenantRequest) (*adminv1.TenantInfo, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	adminReq := admin.UpdateTenantRequest{
		Name: req.Name,
	}
	if req.Settings != nil {
		adminReq.Settings = convertProtoSettingsToAdminInfo(req.Settings)
	}

	tenant, err := s.tenantService.UpdateTenant(ctx, req.TenantId, adminReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return convertAdminTenantToProto(tenant), nil
}

func (s *adminServiceServer) DeleteTenant(ctx context.Context, req *adminv1.DeleteTenantRequest) (*emptypb.Empty, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	if err := s.tenantService.DeleteTenant(ctx, req.TenantId); err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return &emptypb.Empty{}, nil
}

func (s *adminServiceServer) ListTenants(ctx context.Context, req *adminv1.ListTenantsRequest) (*adminv1.ListTenantsResponse, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	adminReq := admin.ListTenantsRequest{
		Page:    int(req.Page),
		PerPage: int(req.PerPage),
		Status:  req.Status,
	}

	tenants, pagination, err := s.tenantService.ListTenants(ctx, adminReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	protoTenants := make([]*adminv1.TenantInfo, len(tenants))
	for i, t := range tenants {
		protoTenants[i] = convertAdminTenantToProto(t)
	}

	return &adminv1.ListTenantsResponse{
		Tenants:    protoTenants,
		Pagination: convertAdminPaginationToProto(pagination),
	}, nil
}

// EAB operations

func (s *adminServiceServer) CreateEAB(ctx context.Context, req *adminv1.CreateEABRequest) (*adminv1.CreateEABResponse, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	adminReq := admin.CreateEABRequest{
		Purpose:           req.Purpose,
		ExpiresInDays:     int(req.ExpiresInDays),
		Contact:           req.Contact,
		ExternalAccountID: req.ExternalAccountId,
	}
	if req.DeviceInfo != nil {
		adminReq.DeviceInfo = convertProtoDeviceInfoToAdmin(req.DeviceInfo)
	}

	eab, err := s.tenantService.CreateTenantEAB(ctx, req.TenantId, adminReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	resp := &adminv1.CreateEABResponse{
		Id:        eab.ID,
		MacKey:    eab.MACKey,
		Algorithm: eab.Algorithm,
	}
	if eab.ExpiresAt != nil && !eab.ExpiresAt.IsZero() {
		resp.ExpiresAt = timestamppb.New(*eab.ExpiresAt)
	}

	return resp, nil
}

func (s *adminServiceServer) GetEAB(ctx context.Context, req *adminv1.GetEABRequest) (*adminv1.EABInfo, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	eab, err := s.tenantService.GetTenantEAB(ctx, req.TenantId, req.Kid)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return convertAdminEABToProto(eab), nil
}

func (s *adminServiceServer) DeleteEAB(ctx context.Context, req *adminv1.DeleteEABRequest) (*emptypb.Empty, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	if err := s.tenantService.DeleteTenantEAB(ctx, req.TenantId, req.Kid); err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return &emptypb.Empty{}, nil
}

func (s *adminServiceServer) ListEABs(ctx context.Context, req *adminv1.ListEABsRequest) (*adminv1.ListEABsResponse, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	adminReq := admin.ListEABRequest{
		Page:    int(req.Page),
		PerPage: int(req.PerPage),
		Status:  req.Status,
		Purpose: req.Purpose,
	}

	eabs, pagination, err := s.tenantService.ListTenantEABs(ctx, req.TenantId, adminReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	protoEABs := make([]*adminv1.EABInfo, len(eabs))
	for i, e := range eabs {
		protoEABs[i] = convertAdminEABToProto(e)
	}

	return &adminv1.ListEABsResponse{
		Eabs:       protoEABs,
		Pagination: convertAdminPaginationToProto(pagination),
	}, nil
}

// Role operations (RBAC) - delegate to tenantService

func (s *adminServiceServer) CreateTenantRole(ctx context.Context, req *adminv1.CreateTenantRoleRequest) (*adminv1.Role, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	dbReq := &db.CreateRoleRequest{
		Name:        req.Name,
		TenantID:    req.TenantId,
		Permissions: req.Permissions,
	}

	role, err := s.tenantService.CreateTenantRole(ctx, req.TenantId, dbReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return convertDBRoleToProto(role), nil
}

func (s *adminServiceServer) GetTenantRole(ctx context.Context, req *adminv1.GetTenantRoleRequest) (*adminv1.Role, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	role, err := s.tenantService.GetTenantRole(ctx, req.TenantId, req.RoleId)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return convertDBRoleToProto(role), nil
}

func (s *adminServiceServer) UpdateTenantRole(ctx context.Context, req *adminv1.UpdateTenantRoleRequest) (*adminv1.Role, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	dbReq := &db.UpdateRoleRequest{
		ID:          req.RoleId,
		Name:        req.Name,
		Permissions: req.Permissions,
	}

	role, err := s.tenantService.UpdateTenantRole(ctx, req.TenantId, dbReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return convertDBRoleToProto(role), nil
}

func (s *adminServiceServer) DeleteTenantRole(ctx context.Context, req *adminv1.DeleteTenantRoleRequest) (*emptypb.Empty, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	if err := s.tenantService.DeleteTenantRole(ctx, req.TenantId, req.RoleId); err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return &emptypb.Empty{}, nil
}

func (s *adminServiceServer) ListTenantRoles(ctx context.Context, req *adminv1.ListTenantRolesRequest) (*adminv1.ListTenantRolesResponse, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	dbReq := &db.ListRolesRequest{
		TenantID: req.TenantId,
		Page:     int(req.Page),
		PageSize: int(req.PageSize),
	}

	resp, err := s.tenantService.ListTenantRoles(ctx, req.TenantId, dbReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	protoRoles := make([]*adminv1.Role, len(resp.Roles))
	for i, r := range resp.Roles {
		protoRoles[i] = convertDBRoleToProto(r)
	}

	return &adminv1.ListTenantRolesResponse{
		Roles:   protoRoles,
		Total:   int32(resp.Total),
		HasMore: resp.HasMore,
	}, nil
}

// User operations (RBAC) - delegate to tenantService

func (s *adminServiceServer) CreateTenantUser(ctx context.Context, req *adminv1.CreateTenantUserRequest) (*adminv1.User, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	dbReq := &db.CreateUserRequest{
		Username: req.Username,
		TenantID: req.TenantId,
		RoleIDs:  req.RoleIds,
	}

	user, err := s.tenantService.CreateTenantUser(ctx, req.TenantId, dbReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return convertDBUserToProto(user), nil
}

func (s *adminServiceServer) GetTenantUser(ctx context.Context, req *adminv1.GetTenantUserRequest) (*adminv1.User, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	user, err := s.tenantService.GetTenantUser(ctx, req.TenantId, req.UserId)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return convertDBUserToProto(user), nil
}

func (s *adminServiceServer) UpdateTenantUser(ctx context.Context, req *adminv1.UpdateTenantUserRequest) (*adminv1.User, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	dbReq := &db.UpdateUserRequest{
		ID:       req.UserId,
		Username: req.Username,
		RoleIDs:  req.RoleIds,
	}

	user, err := s.tenantService.UpdateTenantUser(ctx, req.TenantId, dbReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return convertDBUserToProto(user), nil
}

func (s *adminServiceServer) DeleteTenantUser(ctx context.Context, req *adminv1.DeleteTenantUserRequest) (*emptypb.Empty, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	if err := s.tenantService.DeleteTenantUser(ctx, req.TenantId, req.UserId); err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return &emptypb.Empty{}, nil
}

func (s *adminServiceServer) ListTenantUsers(ctx context.Context, req *adminv1.ListTenantUsersRequest) (*adminv1.ListTenantUsersResponse, error) {
	if s.tenantService == nil {
		return nil, status.Error(codes.Unimplemented, "tenant service not available")
	}

	dbReq := &db.ListUsersRequest{
		TenantID: req.TenantId,
		Page:     int(req.Page),
		PageSize: int(req.PageSize),
	}

	resp, err := s.tenantService.ListTenantUsers(ctx, req.TenantId, dbReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	protoUsers := make([]*adminv1.User, len(resp.Users))
	for i, u := range resp.Users {
		protoUsers[i] = convertDBUserToProto(u)
	}

	return &adminv1.ListTenantUsersResponse{
		Users:   protoUsers,
		Total:   int32(resp.Total),
		HasMore: resp.HasMore,
	}, nil
}

// Account operations

func (s *adminServiceServer) ListAccounts(ctx context.Context, req *adminv1.ListAccountsRequest) (*adminv1.ListAccountsResponse, error) {
	adminReq := admin.ListAccountsRequest{
		Page:    int(req.Page),
		PerPage: int(req.PerPage),
		Status:  req.Status,
	}

	accounts, pagination, err := s.adminService.ListAccounts(ctx, adminReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	protoAccounts := make([]*adminv1.AccountInfo, len(accounts))
	for i, a := range accounts {
		protoAccounts[i] = convertAdminAccountToProto(a)
	}

	return &adminv1.ListAccountsResponse{
		Accounts:   protoAccounts,
		Pagination: convertAdminPaginationToProto(pagination),
	}, nil
}

func (s *adminServiceServer) GetAccount(ctx context.Context, req *adminv1.GetAccountRequest) (*adminv1.AccountInfo, error) {
	account, err := s.adminService.GetAccount(ctx, req.AccountId)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return convertAdminAccountToProto(account), nil
}

func (s *adminServiceServer) DisableAccount(ctx context.Context, req *adminv1.DisableAccountRequest) (*emptypb.Empty, error) {
	if err := s.adminService.DisableAccount(ctx, req.AccountId); err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return &emptypb.Empty{}, nil
}

// Certificate operations

func (s *adminServiceServer) ListCertificates(ctx context.Context, req *adminv1.ListCertificatesRequest) (*adminv1.ListCertificatesResponse, error) {
	adminReq := admin.ListCertificatesRequest{
		Page:        int(req.Page),
		PerPage:     int(req.PerPage),
		Status:      req.Status,
		Subject:     req.Subject,
		ExpiresDays: int(req.ExpiresDays),
	}

	certs, pagination, err := s.adminService.ListCertificates(ctx, adminReq)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	protoCerts := make([]*adminv1.CertificateInfo, len(certs))
	for i, c := range certs {
		protoCerts[i] = convertAdminCertToProto(c)
	}

	return &adminv1.ListCertificatesResponse{
		Certificates: protoCerts,
		Pagination:   convertAdminPaginationToProto(pagination),
	}, nil
}

func (s *adminServiceServer) GetCertificate(ctx context.Context, req *adminv1.GetCertificateRequest) (*adminv1.CertificateInfo, error) {
	cert, err := s.adminService.GetCertificate(ctx, req.Serial)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return convertAdminCertToProto(cert), nil
}

func (s *adminServiceServer) RevokeCertificate(ctx context.Context, req *adminv1.RevokeCertificateRequest) (*emptypb.Empty, error) {
	if err := s.adminService.RevokeCertificate(ctx, req.Serial, req.Reason); err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return &emptypb.Empty{}, nil
}

// Status operations

func (s *adminServiceServer) GetStatus(ctx context.Context, _ *emptypb.Empty) (*adminv1.CAStatus, error) {
	status, err := s.adminService.GetStatus(ctx)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	protoStatus := &adminv1.CAStatus{
		Identity:       status.Identity,
		Initialized:    status.Initialized,
		Version:        status.Version,
		KeyAlgorithm:   status.KeyAlgorithm,
		SignatureAlgo:  status.SignatureAlgo,
		RootCa:         status.RootCA,
		IntermediateCa: status.IntermediateCA,
	}
	if !status.StartedAt.IsZero() {
		protoStatus.StartedAt = timestamppb.New(status.StartedAt)
	}

	return protoStatus, nil
}

func (s *adminServiceServer) GetStats(ctx context.Context, _ *emptypb.Empty) (*adminv1.CAStats, error) {
	stats, err := s.adminService.GetStats(ctx)
	if err != nil {
		return nil, convertAdminErrorToGRPC(err)
	}

	return &adminv1.CAStats{
		TotalCertificates:   int32(stats.TotalCertificates),
		ValidCertificates:   int32(stats.ValidCertificates),
		RevokedCertificates: int32(stats.RevokedCertificates),
		ExpiredCertificates: int32(stats.ExpiredCertificates),
		TotalAccounts:       int32(stats.TotalAccounts),
		ActiveAccounts:      int32(stats.ActiveAccounts),
		TotalOrders:         int32(stats.TotalOrders),
		PendingOrders:       int32(stats.PendingOrders),
		CompletedOrders:     int32(stats.CompletedOrders),
	}, nil
}

// Conversion helpers

func convertAdminErrorToGRPC(err error) error {
	switch {
	case admin.IsNotFoundError(err):
		return status.Error(codes.NotFound, err.Error())
	case admin.IsValidationError(err):
		return status.Error(codes.InvalidArgument, err.Error())
	case admin.IsAlreadyExistsError(err):
		return status.Error(codes.AlreadyExists, err.Error())
	case admin.IsUnauthorizedError(err):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func convertDBRoleToProto(r *db.Role) *adminv1.Role {
	if r == nil {
		return nil
	}
	return &adminv1.Role{
		Id:          r.ID,
		Name:        r.Name,
		TenantId:    r.TenantID,
		Permissions: r.Permissions,
		System:      r.System,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}
}

func convertDBUserToProto(u *db.User) *adminv1.User {
	if u == nil {
		return nil
	}
	return &adminv1.User{
		Id:        u.ID,
		Username:  u.Username,
		TenantId:  u.TenantID,
		RoleIds:   u.RoleIDs,
		Enabled:   u.Enabled,
		System:    u.System,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}

func convertAdminTenantToProto(t *admin.TenantInfo) *adminv1.TenantInfo {
	if t == nil {
		return nil
	}

	info := &adminv1.TenantInfo{
		Id:                      t.ID,
		Name:                    t.Name,
		Status:                  t.Status,
		DefaultIntermediateCaId: t.DefaultIntermediateCAID,
		CreatedBy:               t.CreatedBy,
	}

	if t.RootCA != nil {
		info.RootCa = &adminv1.TenantRootCAInfo{
			CommonName:   t.RootCA.CommonName,
			SerialNumber: t.RootCA.SerialNumber,
			KeyAlgorithm: t.RootCA.KeyAlgorithm,
			Status:       t.RootCA.Status,
		}
		if !t.RootCA.NotBefore.IsZero() {
			info.RootCa.NotBefore = timestamppb.New(t.RootCA.NotBefore)
		}
		if !t.RootCA.NotAfter.IsZero() {
			info.RootCa.NotAfter = timestamppb.New(t.RootCA.NotAfter)
		}
		if !t.RootCA.CreatedAt.IsZero() {
			info.RootCa.CreatedAt = timestamppb.New(t.RootCA.CreatedAt)
		}
	}

	if len(t.IntermediateCAs) > 0 {
		info.IntermediateCas = make([]*adminv1.TenantIntermediateCAInfo, len(t.IntermediateCAs))
		for i, ica := range t.IntermediateCAs {
			info.IntermediateCas[i] = &adminv1.TenantIntermediateCAInfo{
				Id:           ica.ID,
				CommonName:   ica.CommonName,
				SerialNumber: ica.SerialNumber,
				ParentType:   ica.ParentType,
				Purpose:      ica.Purpose,
				KeyAlgorithm: ica.KeyAlgorithm,
				Status:       ica.Status,
			}
			if !ica.NotBefore.IsZero() {
				info.IntermediateCas[i].NotBefore = timestamppb.New(ica.NotBefore)
			}
			if !ica.NotAfter.IsZero() {
				info.IntermediateCas[i].NotAfter = timestamppb.New(ica.NotAfter)
			}
			if !ica.CreatedAt.IsZero() {
				info.IntermediateCas[i].CreatedAt = timestamppb.New(ica.CreatedAt)
			}
			if !ica.UpdatedAt.IsZero() {
				info.IntermediateCas[i].UpdatedAt = timestamppb.New(ica.UpdatedAt)
			}
		}
	}

	if t.Settings != nil {
		info.Settings = &adminv1.TenantSettings{
			MaxCertificates:         int32(t.Settings.MaxCertificates),
			MaxAccounts:             int32(t.Settings.MaxAccounts),
			AllowedKeyAlgorithms:    t.Settings.AllowedKeyAlgorithms,
			AllowedChallengeTypes:   t.Settings.AllowedChallengeTypes,
			CertificateValidityDays: int32(t.Settings.CertificateValidityDays),
			RequireEab:              t.Settings.RequireEAB,
			AllowEndorse_01:         t.Settings.AllowEndorse01,
			AllowEnroll_01:          t.Settings.AllowEnroll01,
		}
	}

	if !t.CreatedAt.IsZero() {
		info.CreatedAt = timestamppb.New(t.CreatedAt)
	}
	if !t.UpdatedAt.IsZero() {
		info.UpdatedAt = timestamppb.New(t.UpdatedAt)
	}

	return info
}

func convertProtoSettingsToAdmin(s *adminv1.TenantSettings) *admin.TenantSettingsInfo {
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

func convertProtoSettingsToAdminInfo(s *adminv1.TenantSettings) *admin.TenantSettingsInfo {
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

func convertProtoDeviceInfoToAdmin(d *adminv1.EABDeviceInfo) *admin.EABDeviceInfoDTO {
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

func convertAdminEABToProto(e *admin.EABInfo) *adminv1.EABInfo {
	if e == nil {
		return nil
	}

	info := &adminv1.EABInfo{
		Id:                e.ID,
		TenantId:          e.TenantID,
		Purpose:           e.Purpose,
		Status:            e.Status,
		AccountId:         e.AccountID,
		ExternalAccountId: e.ExternalAccountID,
		Contact:           e.Contact,
		CreatedBy:         e.CreatedBy,
	}

	if e.DeviceInfo != nil {
		info.DeviceInfo = &adminv1.EABDeviceInfo{
			DeviceId:           e.DeviceInfo.DeviceID,
			Manufacturer:       e.DeviceInfo.Manufacturer,
			Model:              e.DeviceInfo.Model,
			EkPublicKeyHash:    e.DeviceInfo.EKPublicKeyHash,
			TpmManufacturer:    e.DeviceInfo.TPMManufacturer,
			TpmFirmwareVersion: e.DeviceInfo.TPMFirmwareVersion,
			Metadata:           e.DeviceInfo.Metadata,
		}
	}

	if !e.CreatedAt.IsZero() {
		info.CreatedAt = timestamppb.New(e.CreatedAt)
	}
	if e.UsedAt != nil && !e.UsedAt.IsZero() {
		info.UsedAt = timestamppb.New(*e.UsedAt)
	}
	if e.ExpiresAt != nil && !e.ExpiresAt.IsZero() {
		info.ExpiresAt = timestamppb.New(*e.ExpiresAt)
	}

	return info
}

func convertAdminPaginationToProto(p *admin.Pagination) *adminv1.Pagination {
	if p == nil {
		return nil
	}
	return &adminv1.Pagination{
		Page:    int32(p.Page),
		PerPage: int32(p.PerPage),
		Total:   int32(p.Total),
	}
}

func convertAdminAccountToProto(a *admin.AccountInfo) *adminv1.AccountInfo {
	if a == nil {
		return nil
	}

	info := &adminv1.AccountInfo{
		Id:                   uint64(a.ID),
		Status:               a.Status,
		Contact:              a.Contact,
		TermsOfServiceAgreed: a.TermsOfServiceAgreed,
		OrdersUrl:            a.OrdersURL,
		OrderCount:           int32(a.OrderCount),
	}

	if !a.CreatedAt.IsZero() {
		info.CreatedAt = timestamppb.New(a.CreatedAt)
	}

	return info
}

func convertAdminCertToProto(c *admin.CertificateInfo) *adminv1.CertificateInfo {
	if c == nil {
		return nil
	}

	info := &adminv1.CertificateInfo{
		Id:           c.ID,
		SerialNumber: c.SerialNumber,
		Subject:      c.Subject,
		Issuer:       c.Issuer,
		Status:       c.Status,
		CertUrl:      c.CertURL,
	}

	if !c.NotBefore.IsZero() {
		info.NotBefore = timestamppb.New(c.NotBefore)
	}
	if !c.NotAfter.IsZero() {
		info.NotAfter = timestamppb.New(c.NotAfter)
	}
	if !c.IssuedAt.IsZero() {
		info.IssuedAt = timestamppb.New(c.IssuedAt)
	}

	return info
}
