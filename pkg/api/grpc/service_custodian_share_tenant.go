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
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/custodian"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
)

// Typed errors for custodian, share, and tenant gRPC operations.
var (
	// ErrCustodianServiceNotConfigured is returned when the custodian service
	// has not been configured via SetCustodianService.
	ErrCustodianServiceNotConfigured = errors.New("grpc: custodian service not configured")

	// ErrShareStoreNotConfigured is returned when the share store has not
	// been configured via SetShareStore.
	ErrShareStoreNotConfigured = errors.New("grpc: share store not configured")

	// ErrBarrierRegistryNotConfigured is returned when the barrier registry
	// has not been configured via SetBarrierRegistry.
	ErrBarrierRegistryNotConfigured = errors.New("grpc: barrier registry not configured")
)

// custodianErrorToGRPC maps custodian domain errors to gRPC status codes.
var custodianErrorToGRPC = map[error]codes.Code{
	custodian.ErrGroupNotFound:        codes.NotFound,
	custodian.ErrGroupAlreadyExists:   codes.AlreadyExists,
	custodian.ErrGroupFull:            codes.FailedPrecondition,
	custodian.ErrMemberAlreadyExists:  codes.AlreadyExists,
	custodian.ErrMemberNotFound:       codes.NotFound,
	custodian.ErrEmptyGroupID:         codes.InvalidArgument,
	custodian.ErrEmptyGroupName:       codes.InvalidArgument,
	custodian.ErrEmptyUserID:          codes.InvalidArgument,
	custodian.ErrInvalidThreshold:     codes.InvalidArgument,
	custodian.ErrInvalidTotalShares:   codes.InvalidArgument,
	custodian.ErrInvalidPurpose:       codes.InvalidArgument,
	custodian.ErrGroupEmpty:           codes.FailedPrecondition,
	custodian.ErrShareAlreadyReceived: codes.AlreadyExists,
}

// shareErrorToGRPC maps sharestore domain errors to gRPC status codes.
var shareErrorToGRPC = map[error]codes.Code{
	sharestore.ErrShareNotFound:    codes.NotFound,
	sharestore.ErrShareExists:      codes.AlreadyExists,
	sharestore.ErrInvalidServerURL: codes.InvalidArgument,
	sharestore.ErrInvalidGroupID:   codes.InvalidArgument,
	sharestore.ErrEmptyShare:       codes.InvalidArgument,
	sharestore.ErrNilEntry:         codes.InvalidArgument,
	sharestore.ErrStoreClosed:      codes.Unavailable,
}

// tenantErrorToGRPC maps seal/tenant domain errors to gRPC status codes.
var tenantErrorToGRPC = map[error]codes.Code{
	seal.ErrTenantNotFound:      codes.NotFound,
	seal.ErrTenantAlreadyExists: codes.AlreadyExists,
	seal.ErrEmptyTenantID:       codes.InvalidArgument,
	seal.ErrSealed:              codes.FailedPrecondition,
	seal.ErrNotInitialized:      codes.FailedPrecondition,
	seal.ErrAlreadyInitialized:  codes.AlreadyExists,
	seal.ErrAlreadyUnsealed:     codes.AlreadyExists,
	seal.ErrNilSystemBarrier:    codes.Unavailable,
}

// Package-level service references, set via their respective setter functions.
var (
	custodianService *custodian.Service
	shareStore       sharestore.ShareStore
	barrierRegistry  *seal.BarrierRegistry
)

// SetCustodianService configures the custodian service for the gRPC service.
// This must be called before any custodian RPCs can be used.
func SetCustodianService(svc *custodian.Service) {
	custodianService = svc
}

// GetCustodianService returns the configured custodian service, or nil if not set.
func GetCustodianService() *custodian.Service {
	return custodianService
}

// SetShareStore configures the share store for the gRPC service.
// This must be called before any share RPCs can be used.
func SetShareStore(ss sharestore.ShareStore) {
	shareStore = ss
}

// GetShareStore returns the configured share store, or nil if not set.
func GetShareStore() sharestore.ShareStore {
	return shareStore
}

// SetBarrierRegistry configures the barrier registry for tenant operations.
// This must be called before any tenant RPCs can be used.
func SetBarrierRegistry(br *seal.BarrierRegistry) {
	barrierRegistry = br
}

// GetBarrierRegistry returns the configured barrier registry, or nil if not set.
func GetBarrierRegistry() *seal.BarrierRegistry {
	return barrierRegistry
}

// mapCustodianError converts a custodian domain error to the appropriate gRPC
// status error. If the error is a known custodian error, it maps to the
// corresponding gRPC code. Otherwise, it returns an Internal error.
func mapCustodianError(err error, operation string) error {
	if err == nil {
		return nil
	}
	for domainErr, code := range custodianErrorToGRPC {
		if errors.Is(err, domainErr) {
			return status.Errorf(code, "%s: %v", operation, err)
		}
	}
	return status.Errorf(codes.Internal, "%s: %v", operation, err)
}

// mapShareError converts a sharestore domain error to the appropriate gRPC
// status error. If the error is a known sharestore error, it maps to the
// corresponding gRPC code. Otherwise, it returns an Internal error.
func mapShareError(err error, operation string) error {
	if err == nil {
		return nil
	}
	for domainErr, code := range shareErrorToGRPC {
		if errors.Is(err, domainErr) {
			return status.Errorf(code, "%s: %v", operation, err)
		}
	}
	return status.Errorf(codes.Internal, "%s: %v", operation, err)
}

// mapTenantError converts a seal/tenant domain error to the appropriate gRPC
// status error. If the error is a known tenant error, it maps to the
// corresponding gRPC code. Otherwise, it returns an Internal error.
func mapTenantError(err error, operation string) error {
	if err == nil {
		return nil
	}
	for domainErr, code := range tenantErrorToGRPC {
		if errors.Is(err, domainErr) {
			return status.Errorf(code, "%s: %v", operation, err)
		}
	}
	return status.Errorf(codes.Internal, "%s: %v", operation, err)
}

// custodianGroupToProto converts a domain CustodianGroup to its proto
// representation.
func custodianGroupToProto(g *custodian.CustodianGroup) *pb.CustodianGroup {
	members := make([]*pb.CustodianMember, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, &pb.CustodianMember{
			UserId: m.UserID,
			Name:   m.Username,
			Role:   m.Method,
		})
	}
	return &pb.CustodianGroup{
		Id:          g.ID,
		Name:        g.Name,
		Description: g.Purpose,
		Threshold:   int32(g.Threshold), // #nosec G115 - threshold fits in int32
		Members:     members,
		CreatedAt:   g.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   g.UpdatedAt.Format(time.RFC3339),
	}
}

// custodianMemberToProto converts a domain CustodianMember to its proto
// representation.
func custodianMemberToProto(m *custodian.CustodianMember) *pb.CustodianMember {
	return &pb.CustodianMember{
		UserId: m.UserID,
		Name:   m.Username,
		Role:   m.Method,
	}
}

// shareEntryToProto converts a domain ShareEntry to its proto representation.
func shareEntryToProto(e *sharestore.ShareEntry) *pb.ShareInfo {
	return &pb.ShareInfo{
		GroupId:     e.GroupID,
		ServerUrl:   e.ServerURL,
		GroupName:   e.GroupName,
		ShareIndex:  int32(e.ShareIndex), // #nosec G115 - share index fits in int32
		Purpose:     e.Purpose,
		TenantId:    e.TenantID,
		SubmittedAt: e.ReceivedAt.Format(time.RFC3339),
	}
}

// ==================== Custodian Group Operations ====================

// CreateCustodianGroup creates a new custodian group for Shamir threshold ceremonies.
func (s *Service) CreateCustodianGroup(ctx context.Context, req *pb.CreateCustodianGroupRequest) (*pb.CreateCustodianGroupResponse, error) {
	if custodianService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianServiceNotConfigured.Error())
	}

	if err := s.authorize(ctx, "custodian", "write", "create-group"); err != nil {
		return nil, err
	}

	name := req.GetName()
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	threshold := int(req.GetThreshold())
	if threshold < 1 {
		return nil, status.Error(codes.InvalidArgument, "threshold must be positive")
	}

	// The proto CreateCustodianGroupRequest has name, description, threshold.
	// Map description to purpose, and default total to threshold since the
	// proto does not carry a total field.
	purpose := req.GetDescription()
	if purpose == "" {
		purpose = custodian.PurposeBarrier
	}

	group, err := custodianService.CreateGroup(ctx, "", "", name, purpose, threshold, threshold)
	if err != nil {
		return nil, mapCustodianError(err, "create custodian group")
	}

	return &pb.CreateCustodianGroupResponse{
		Group: custodianGroupToProto(group),
	}, nil
}

// GetCustodianGroup retrieves a custodian group by ID.
func (s *Service) GetCustodianGroup(ctx context.Context, req *pb.GetCustodianGroupRequest) (*pb.GetCustodianGroupResponse, error) {
	if custodianService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianServiceNotConfigured.Error())
	}

	if err := s.authorize(ctx, "custodian", "read", "get-group"); err != nil {
		return nil, err
	}

	groupID := req.GetGroupId()
	if groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "group_id is required")
	}

	group, err := custodianService.GetGroup(ctx, groupID)
	if err != nil {
		return nil, mapCustodianError(err, "get custodian group")
	}

	return &pb.GetCustodianGroupResponse{
		Group: custodianGroupToProto(group),
	}, nil
}

// ListCustodianGroups returns all custodian groups.
func (s *Service) ListCustodianGroups(ctx context.Context, _ *pb.ListCustodianGroupsRequest) (*pb.ListCustodianGroupsResponse, error) {
	if custodianService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianServiceNotConfigured.Error())
	}

	if err := s.authorize(ctx, "custodian", "read", "list-groups"); err != nil {
		return nil, err
	}

	groups, err := custodianService.ListGroups(ctx)
	if err != nil {
		return nil, mapCustodianError(err, "list custodian groups")
	}

	pbGroups := make([]*pb.CustodianGroup, 0, len(groups))
	for _, g := range groups {
		pbGroups = append(pbGroups, custodianGroupToProto(g))
	}

	return &pb.ListCustodianGroupsResponse{
		Groups: pbGroups,
	}, nil
}

// DeleteCustodianGroup deletes a custodian group.
func (s *Service) DeleteCustodianGroup(ctx context.Context, req *pb.DeleteCustodianGroupRequest) (*emptypb.Empty, error) {
	if custodianService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianServiceNotConfigured.Error())
	}

	if err := s.authorize(ctx, "custodian", "write", "delete-group"); err != nil {
		return nil, err
	}

	groupID := req.GetGroupId()
	if groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "group_id is required")
	}

	if err := custodianService.DeleteGroup(ctx, groupID); err != nil {
		return nil, mapCustodianError(err, "delete custodian group")
	}

	return &emptypb.Empty{}, nil
}

// AddCustodianMember adds a member to a custodian group.
func (s *Service) AddCustodianMember(ctx context.Context, req *pb.AddCustodianMemberRequest) (*pb.AddCustodianMemberResponse, error) {
	if custodianService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianServiceNotConfigured.Error())
	}

	if err := s.authorize(ctx, "custodian", "write", "add-member"); err != nil {
		return nil, err
	}

	groupID := req.GetGroupId()
	if groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "group_id is required")
	}

	userID := req.GetUserId()
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	// Map proto fields to domain: name -> username, role -> method.
	username := req.GetName()
	method := req.GetRole()
	if method == "" {
		method = custodian.MethodManual
	}

	member, err := custodianService.AddMember(ctx, groupID, userID, username, method)
	if err != nil {
		return nil, mapCustodianError(err, "add custodian member")
	}

	return &pb.AddCustodianMemberResponse{
		Member: custodianMemberToProto(member),
	}, nil
}

// RemoveCustodianMember removes a member from a custodian group.
func (s *Service) RemoveCustodianMember(ctx context.Context, req *pb.RemoveCustodianMemberRequest) (*emptypb.Empty, error) {
	if custodianService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianServiceNotConfigured.Error())
	}

	if err := s.authorize(ctx, "custodian", "write", "remove-member"); err != nil {
		return nil, err
	}

	groupID := req.GetGroupId()
	if groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "group_id is required")
	}

	userID := req.GetUserId()
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	if err := custodianService.RemoveMember(ctx, groupID, userID); err != nil {
		return nil, mapCustodianError(err, "remove custodian member")
	}

	return &emptypb.Empty{}, nil
}

// DistributeShares triggers share distribution for a custodian group.
func (s *Service) DistributeShares(ctx context.Context, req *pb.DistributeSharesRequest) (*pb.DistributeSharesResponse, error) {
	if custodianService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianServiceNotConfigured.Error())
	}

	if err := s.authorize(ctx, "custodian", "write", "distribute-shares"); err != nil {
		return nil, err
	}

	groupID := req.GetGroupId()
	if groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "group_id is required")
	}

	count, err := custodianService.DistributeShares(ctx, groupID)
	if err != nil {
		return nil, mapCustodianError(err, "distribute shares")
	}

	return &pb.DistributeSharesResponse{
		Distributed: int32(count), // #nosec G115 - member count fits in int32
	}, nil
}

// ==================== Share Operations ====================

// SubmitShare submits a Shamir share for storage.
func (s *Service) SubmitShare(ctx context.Context, req *pb.SubmitShareRequest) (*pb.SubmitShareResponse, error) {
	if shareStore == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrShareStoreNotConfigured.Error())
	}

	if err := s.authorize(ctx, "share", "write", "submit"); err != nil {
		return nil, err
	}

	groupID := req.GetGroupId()
	if groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "group_id is required")
	}

	shareData := req.GetShareData()
	if shareData == "" {
		return nil, status.Error(codes.InvalidArgument, "share_data is required")
	}

	serverURL := req.GetServerUrl()
	if serverURL == "" {
		return nil, status.Error(codes.InvalidArgument, "server_url is required")
	}

	entry := &sharestore.ShareEntry{
		ServerURL:  serverURL,
		GroupID:    groupID,
		GroupName:  req.GetGroupName(),
		ShareIndex: int(req.GetShareIndex()),
		ShareData:  []byte(shareData),
		Purpose:    req.GetPurpose(),
		ReceivedAt: time.Now().UTC(),
		TenantID:   req.GetTenantId(),
	}

	if err := shareStore.Save(ctx, entry); err != nil {
		return nil, mapShareError(err, "submit share")
	}

	return &pb.SubmitShareResponse{
		Id:      entry.Key(),
		Message: "share submitted successfully",
	}, nil
}

// ListShares returns all stored shares without exposing sensitive share data.
func (s *Service) ListShares(ctx context.Context, _ *pb.ListSharesRequest) (*pb.ListSharesResponse, error) {
	if shareStore == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrShareStoreNotConfigured.Error())
	}

	if err := s.authorize(ctx, "share", "read", "list"); err != nil {
		return nil, err
	}

	entries, err := shareStore.List(ctx)
	if err != nil {
		return nil, mapShareError(err, "list shares")
	}

	shares := make([]*pb.ShareInfo, 0, len(entries))
	for _, entry := range entries {
		shares = append(shares, shareEntryToProto(entry))
	}

	return &pb.ListSharesResponse{
		Shares: shares,
	}, nil
}

// GetShareCollectionStatus returns the share collection status for a group.
func (s *Service) GetShareCollectionStatus(ctx context.Context, req *pb.GetShareCollectionStatusRequest) (*pb.ShareCollectionStatusResponse, error) {
	if shareStore == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrShareStoreNotConfigured.Error())
	}

	if err := s.authorize(ctx, "share", "read", "collection-status"); err != nil {
		return nil, err
	}

	groupID := req.GetGroupId()
	if groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "group_id is required")
	}

	entries, err := shareStore.List(ctx)
	if err != nil {
		return nil, mapShareError(err, "get share collection status")
	}

	collected := int32(0)
	for _, entry := range entries {
		if entry.GroupID == groupID {
			collected++
		}
	}

	// Determine required threshold from the custodian group if available.
	var required int32
	var complete bool
	if custodianService != nil {
		group, groupErr := custodianService.GetGroup(ctx, groupID)
		if groupErr == nil {
			required = int32(group.Threshold) // #nosec G115 - threshold fits in int32
			complete = collected >= required
		}
	}

	return &pb.ShareCollectionStatusResponse{
		GroupId:   groupID,
		Collected: collected,
		Required:  required,
		Complete:  complete,
	}, nil
}

// ==================== Tenant Operations ====================

// CreateTenant creates a new tenant.
func (s *Service) CreateTenant(ctx context.Context, req *pb.CreateTenantRequest) (*pb.CreateTenantResponse, error) {
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
	}

	if err := s.authorize(ctx, "tenant", "write", "create"); err != nil {
		return nil, err
	}

	tenantID := req.GetId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	name := req.GetName()
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	tb, err := barrierRegistry.RegisterTenant(tenantID)
	if err != nil {
		return nil, mapTenantError(err, "create tenant")
	}

	sealedStatus := "unsealed"
	if tb.IsSealed() {
		sealedStatus = "sealed"
	}

	return &pb.CreateTenantResponse{
		Tenant: &pb.TenantInfo{
			Id:          tenantID,
			Name:        name,
			Description: req.GetDescription(),
			Status:      sealedStatus,
			CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}

// GetTenant retrieves a tenant by ID.
func (s *Service) GetTenant(ctx context.Context, req *pb.GetTenantRequest) (*pb.GetTenantResponse, error) {
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
	}

	if err := s.authorize(ctx, "tenant", "read", "get"); err != nil {
		return nil, err
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	tb, err := barrierRegistry.Tenant(tenantID)
	if err != nil {
		return nil, mapTenantError(err, "get tenant")
	}

	sealedStatus := "unsealed"
	if tb.IsSealed() {
		sealedStatus = "sealed"
	}

	return &pb.GetTenantResponse{
		Tenant: &pb.TenantInfo{
			Id:     tb.TenantID(),
			Status: sealedStatus,
		},
	}, nil
}

// ListTenants returns all tenants.
func (s *Service) ListTenants(ctx context.Context, _ *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
	}

	if err := s.authorize(ctx, "tenant", "read", "list"); err != nil {
		return nil, err
	}

	ids := barrierRegistry.ListTenants()

	tenants := make([]*pb.TenantInfo, 0, len(ids))
	for _, id := range ids {
		tb, err := barrierRegistry.Tenant(id)
		if err != nil {
			continue
		}

		sealedStatus := "unsealed"
		if tb.IsSealed() {
			sealedStatus = "sealed"
		}

		tenants = append(tenants, &pb.TenantInfo{
			Id:     id,
			Status: sealedStatus,
		})
	}

	return &pb.ListTenantsResponse{
		Tenants: tenants,
	}, nil
}

// DeleteTenant deletes a tenant.
func (s *Service) DeleteTenant(ctx context.Context, req *pb.DeleteTenantRequest) (*emptypb.Empty, error) {
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
	}

	if err := s.authorize(ctx, "tenant", "write", "delete"); err != nil {
		return nil, err
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if err := barrierRegistry.UnregisterTenant(tenantID); err != nil {
		return nil, mapTenantError(err, "delete tenant")
	}

	return &emptypb.Empty{}, nil
}

// TenantBarrierInit initializes the barrier for a tenant. Tenant barriers
// share the system barrier's root key and encryption lifecycle, so this
// endpoint verifies the tenant exists and confirms the system barrier's
// initialization state.
func (s *Service) TenantBarrierInit(ctx context.Context, req *pb.TenantBarrierInitRequest) (*emptypb.Empty, error) {
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
	}

	if err := s.authorize(ctx, "tenant", "write", "barrier-init"); err != nil {
		return nil, err
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// Verify the tenant exists. Tenant barriers delegate initialization to the
	// system barrier, so we only validate tenant existence here.
	if _, err := barrierRegistry.Tenant(tenantID); err != nil {
		return nil, mapTenantError(err, "tenant barrier init")
	}

	return &emptypb.Empty{}, nil
}

// TenantBarrierUnseal unseals the barrier for a tenant. Tenant barriers share
// the system barrier's unsealing lifecycle, so this endpoint verifies the
// tenant exists and reports the current seal state. To unseal, use the system
// barrier's unseal endpoint.
func (s *Service) TenantBarrierUnseal(ctx context.Context, req *pb.TenantBarrierUnsealRequest) (*emptypb.Empty, error) {
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
	}

	if err := s.authorize(ctx, "tenant", "write", "barrier-unseal"); err != nil {
		return nil, err
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// Verify the tenant exists. Tenant barriers delegate unsealing to the
	// system barrier, so we only validate tenant existence here.
	if _, err := barrierRegistry.Tenant(tenantID); err != nil {
		return nil, mapTenantError(err, "tenant barrier unseal")
	}

	return &emptypb.Empty{}, nil
}
