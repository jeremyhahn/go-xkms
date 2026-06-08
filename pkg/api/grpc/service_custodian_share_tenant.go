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
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// Typed errors for custodian, share, and tenant gRPC operations.
var (
	// ErrCustodianClientNotConfigured is returned when the custodian group
	// client has not been configured via SetCustodianClient.
	ErrCustodianClientNotConfigured = errors.New("grpc: custodian group client not configured")

	// ErrShareClientNotConfigured is returned when the share client has not
	// been configured via SetShareClient.
	ErrShareClientNotConfigured = errors.New("grpc: share client not configured")

	// ErrBarrierRegistryNotConfigured is returned when the barrier registry
	// has not been configured via SetBarrierRegistry.
	ErrBarrierRegistryNotConfigured = errors.New("grpc: barrier registry not configured")
)

// Default custodian field values applied when the gRPC request omits them.
// The proto CreateCustodianGroupRequest has no purpose field and the
// AddCustodianMemberRequest role may be empty.
const (
	defaultCustodianPurpose = "barrier"
	defaultCustodianMethod  = "manual"
)

// custodianErrorToGRPC maps custodian domain errors to gRPC status codes.
var custodianErrorToGRPC = map[error]codes.Code{
	qrdbsdk.ErrCeremonyGroupNotFound:       codes.NotFound,
	qrdbsdk.ErrCeremonyMemberNotFound:      codes.NotFound,
	qrdbsdk.ErrCeremonyUserNotFound:        codes.NotFound,
	qrdbsdk.ErrCeremonyGroupAlreadyExists:  codes.AlreadyExists,
	qrdbsdk.ErrCeremonyMemberAlreadyExists: codes.AlreadyExists,
	qrdbsdk.ErrCeremonyGroupFull:           codes.FailedPrecondition,
	qrdbsdk.ErrCeremonyInsufficientMembers: codes.FailedPrecondition,
	qrdbsdk.ErrCeremonyEmptyGroupID:        codes.InvalidArgument,
	qrdbsdk.ErrCeremonyEmptyGroupName:      codes.InvalidArgument,
	qrdbsdk.ErrCeremonyInvalidThreshold:    codes.InvalidArgument,
	qrdbsdk.ErrCeremonyInvalidTotal:        codes.InvalidArgument,
}

// shareErrorToGRPC maps share domain errors (surfaced by the embedded go-qrdb
// node's share client) to gRPC status codes.
var shareErrorToGRPC = map[error]codes.Code{
	qrdbsdk.ErrCeremonyShareNotFound: codes.NotFound,
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

	// Two-phase tenant barrier (§3.6) servicer errors.
	xkms.ErrTenantPassphraseRequired: codes.InvalidArgument,
	xkms.ErrTenantSharesRequired:     codes.InvalidArgument,
	xkms.ErrTenantStrategyConflict:   codes.FailedPrecondition,
}

// Package-level service references, set via their respective setter functions.
var (
	custodianClient qrdbtransport.CustodianGroupClient
	shareClient     qrdbtransport.ShareClient
	barrierRegistry *seal.BarrierRegistry
)

// SetCustodianClient configures the custodian group client for the gRPC
// service. Custodian state is owned by the embedded go-qrdb node; the gRPC
// handlers convert proto messages to the node's transport types and pass the
// calls through. This must be called before any custodian RPCs can be used.
func SetCustodianClient(c qrdbtransport.CustodianGroupClient) {
	custodianClient = c
}

// GetCustodianClient returns the configured custodian group client, or nil if
// not set.
func GetCustodianClient() qrdbtransport.CustodianGroupClient {
	return custodianClient
}

// SetShareClient configures the share client for the gRPC service. Share state
// is owned by the embedded go-qrdb node; the gRPC handlers convert proto
// messages to the node's transport types and pass the calls through. This must
// be called before any share RPCs can be used.
func SetShareClient(c qrdbtransport.ShareClient) {
	shareClient = c
}

// GetShareClient returns the configured share client, or nil if not set.
func GetShareClient() qrdbtransport.ShareClient {
	return shareClient
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

// custodianGroupToProto converts a qrdb-transport CustodianGroupInfo to its
// proto representation.
func custodianGroupToProto(g *qrdbtransport.CustodianGroupInfo) *pb.CustodianGroup {
	members := make([]*pb.CustodianMember, 0, len(g.Members))
	for i := range g.Members {
		members = append(members, custodianMemberToProto(&g.Members[i]))
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

// custodianMemberToProto converts a qrdb-transport CustodianMemberInfo to its
// proto representation.
func custodianMemberToProto(m *qrdbtransport.CustodianMemberInfo) *pb.CustodianMember {
	return &pb.CustodianMember{
		UserId: m.UserID,
		Name:   m.Username,
		Role:   m.Method,
	}
}

// shareInfoToProto converts a qrdb-transport ShareInfo to its proto
// representation.
func shareInfoToProto(info *qrdbtransport.ShareInfo) *pb.ShareInfo {
	return &pb.ShareInfo{
		GroupId:     info.GroupID,
		ServerUrl:   info.ServerURL,
		GroupName:   info.GroupName,
		ShareIndex:  int32(info.ShareIndex), // #nosec G115 - share index fits in int32
		Purpose:     info.Purpose,
		TenantId:    info.TenantID,
		SubmittedAt: info.ReceivedAt.Format(time.RFC3339),
	}
}

// ==================== Custodian Group Operations ====================

// CreateCustodianGroup creates a new custodian group for Shamir threshold ceremonies.
func (s *Service) CreateCustodianGroup(ctx context.Context, req *pb.CreateCustodianGroupRequest) (*pb.CreateCustodianGroupResponse, error) {
	if custodianClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, "ceremony", "enroll_custodian", "create-group"); err != nil {
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
		purpose = defaultCustodianPurpose
	}

	resp, err := custodianClient.CreateCustodianGroup(ctx, &qrdbtransport.CreateCustodianGroupRequest{
		Name:      name,
		Purpose:   purpose,
		Threshold: threshold,
		Total:     threshold,
	})
	if err != nil {
		return nil, mapCustodianError(err, "create custodian group")
	}

	return &pb.CreateCustodianGroupResponse{
		Group: custodianGroupToProto(&resp.Group),
	}, nil
}

// GetCustodianGroup retrieves a custodian group by ID.
func (s *Service) GetCustodianGroup(ctx context.Context, req *pb.GetCustodianGroupRequest) (*pb.GetCustodianGroupResponse, error) {
	if custodianClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, "ceremony", "status", "get-group"); err != nil {
		return nil, err
	}

	groupID := req.GetGroupId()
	if groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "group_id is required")
	}

	resp, err := custodianClient.GetCustodianGroup(ctx, groupID)
	if err != nil {
		return nil, mapCustodianError(err, "get custodian group")
	}

	return &pb.GetCustodianGroupResponse{
		Group: custodianGroupToProto(&resp.Group),
	}, nil
}

// ListCustodianGroups returns all custodian groups.
func (s *Service) ListCustodianGroups(ctx context.Context, _ *pb.ListCustodianGroupsRequest) (*pb.ListCustodianGroupsResponse, error) {
	if custodianClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, "ceremony", "status", "list-groups"); err != nil {
		return nil, err
	}

	resp, err := custodianClient.ListCustodianGroups(ctx)
	if err != nil {
		return nil, mapCustodianError(err, "list custodian groups")
	}

	pbGroups := make([]*pb.CustodianGroup, 0, len(resp.Groups))
	for i := range resp.Groups {
		pbGroups = append(pbGroups, custodianGroupToProto(&resp.Groups[i]))
	}

	return &pb.ListCustodianGroupsResponse{
		Groups: pbGroups,
	}, nil
}

// DeleteCustodianGroup deletes a custodian group.
func (s *Service) DeleteCustodianGroup(ctx context.Context, req *pb.DeleteCustodianGroupRequest) (*emptypb.Empty, error) {
	if custodianClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, "ceremony", "revoke_custodian", "delete-group"); err != nil {
		return nil, err
	}

	groupID := req.GetGroupId()
	if groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "group_id is required")
	}

	if err := custodianClient.DeleteCustodianGroup(ctx, groupID); err != nil {
		return nil, mapCustodianError(err, "delete custodian group")
	}

	return &emptypb.Empty{}, nil
}

// AddCustodianMember adds a member to a custodian group.
func (s *Service) AddCustodianMember(ctx context.Context, req *pb.AddCustodianMemberRequest) (*pb.AddCustodianMemberResponse, error) {
	if custodianClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, "ceremony", "enroll_custodian", "add-member"); err != nil {
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
		method = defaultCustodianMethod
	}

	resp, err := custodianClient.AddCustodianMember(ctx, &qrdbtransport.AddCustodianMemberRequest{
		GroupID:  groupID,
		UserID:   userID,
		Username: username,
		Method:   method,
	})
	if err != nil {
		return nil, mapCustodianError(err, "add custodian member")
	}

	return &pb.AddCustodianMemberResponse{
		Member: custodianMemberToProto(&resp.Member),
	}, nil
}

// RemoveCustodianMember removes a member from a custodian group.
func (s *Service) RemoveCustodianMember(ctx context.Context, req *pb.RemoveCustodianMemberRequest) (*emptypb.Empty, error) {
	if custodianClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, "ceremony", "revoke_custodian", "remove-member"); err != nil {
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

	if err := custodianClient.RemoveCustodianMember(ctx, &qrdbtransport.RemoveCustodianMemberRequest{
		GroupID: groupID,
		UserID:  userID,
	}); err != nil {
		return nil, mapCustodianError(err, "remove custodian member")
	}

	return &emptypb.Empty{}, nil
}

// DistributeShares triggers share distribution for a custodian group.
func (s *Service) DistributeShares(ctx context.Context, req *pb.DistributeSharesRequest) (*pb.DistributeSharesResponse, error) {
	if custodianClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrCustodianClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, "ceremony", "claim_share_begin", "distribute-shares"); err != nil {
		return nil, err
	}

	groupID := req.GetGroupId()
	if groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "group_id is required")
	}

	resp, err := custodianClient.DistributeShares(ctx, &qrdbtransport.DistributeSharesRequest{
		GroupID: groupID,
	})
	if err != nil {
		return nil, mapCustodianError(err, "distribute shares")
	}

	return &pb.DistributeSharesResponse{
		Distributed: int32(resp.Distributed), // #nosec G115 - member count fits in int32
	}, nil
}

// ==================== Share Operations ====================

// SubmitShare submits a Shamir share for storage. The request is passed through
// to the embedded go-qrdb node's share client.
func (s *Service) SubmitShare(ctx context.Context, req *pb.SubmitShareRequest) (*pb.SubmitShareResponse, error) {
	if shareClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrShareClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, "barrier", "unseal-share", "submit"); err != nil {
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

	shareIndex := int(req.GetShareIndex())
	if _, err := shareClient.SubmitShare(ctx, &qrdbtransport.SubmitShareRequest{
		ServerURL:  serverURL,
		GroupID:    groupID,
		GroupName:  req.GetGroupName(),
		ShareIndex: shareIndex,
		ShareData:  []byte(shareData),
		Purpose:    req.GetPurpose(),
		TenantID:   req.GetTenantId(),
	}); err != nil {
		return nil, mapShareError(err, "submit share")
	}

	return &pb.SubmitShareResponse{
		Id:      fmt.Sprintf("%s/%s/%d", serverURL, groupID, shareIndex),
		Message: "share submitted successfully",
	}, nil
}

// ListShares returns all stored shares without exposing sensitive share data.
// The request is passed through to the embedded go-qrdb node's share client.
func (s *Service) ListShares(ctx context.Context, _ *pb.ListSharesRequest) (*pb.ListSharesResponse, error) {
	if shareClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrShareClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, "ceremony", "status", "list"); err != nil {
		return nil, err
	}

	resp, err := shareClient.ListShares(ctx)
	if err != nil {
		return nil, mapShareError(err, "list shares")
	}

	shares := make([]*pb.ShareInfo, 0, len(resp.Shares))
	for i := range resp.Shares {
		shares = append(shares, shareInfoToProto(&resp.Shares[i]))
	}

	return &pb.ListSharesResponse{
		Shares: shares,
	}, nil
}

// GetShareCollectionStatus returns the share collection status for a group. The
// request is passed through to the embedded go-qrdb node's share client, which
// reports threshold progress for the group.
func (s *Service) GetShareCollectionStatus(ctx context.Context, req *pb.GetShareCollectionStatusRequest) (*pb.ShareCollectionStatusResponse, error) {
	if shareClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrShareClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, "ceremony", "status", "collection-status"); err != nil {
		return nil, err
	}

	groupID := req.GetGroupId()
	if groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "group_id is required")
	}

	collectionStatus, err := shareClient.GetShareCollectionStatus(ctx, groupID)
	if err != nil {
		return nil, mapShareError(err, "get share collection status")
	}

	return &pb.ShareCollectionStatusResponse{
		GroupId:   collectionStatus.GroupID,
		Collected: int32(collectionStatus.Collected), // #nosec G115 - collected count fits in int32
		Required:  int32(collectionStatus.Threshold), // #nosec G115 - threshold fits in int32
		Complete:  collectionStatus.Ready,
	}, nil
}

// ==================== Tenant Operations ====================

// CreateTenant creates a new tenant.
func (s *Service) CreateTenant(ctx context.Context, req *pb.CreateTenantRequest) (*pb.CreateTenantResponse, error) {
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
	}

	if err := s.authorize(ctx, "tenants", "create", "create"); err != nil {
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

	if err := s.authorize(ctx, "tenants", "read", "get"); err != nil {
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

	if err := s.authorize(ctx, "tenants", "list", "list"); err != nil {
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

	if err := s.authorize(ctx, "tenants", "delete", "delete"); err != nil {
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

// TenantBarrierInit initializes the per-tenant barrier (Phase 2 of the §3.6
// two-phase model). The tenant admin's passphrase is taken verbatim from the
// request secret; the server never generates a tenant secret. The work is
// delegated to the XKMSService servicer so the security invariant lives in
// exactly one place.
func (s *Service) TenantBarrierInit(ctx context.Context, req *pb.TenantBarrierInitRequest) (*emptypb.Empty, error) {
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
	}

	if err := s.authorize(ctx, "tenant_barrier", "init", "barrier-init"); err != nil {
		return nil, err
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	svc, err := xkms.Get()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	if err := svc.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID:   tenantID,
		Passphrase: req.GetSecret(),
		Strategy:   req.GetStrategy(),
		Threshold:  int(req.GetThreshold()),
		Shares:     int(req.GetShares()),
	}); err != nil {
		return nil, mapTenantError(err, "tenant barrier init")
	}

	return &emptypb.Empty{}, nil
}

// TenantBarrierUnseal unseals the per-tenant barrier using the caller-supplied
// recovery material (secret for passphrase strategies, share_values for
// shamir). The server holds no tenant secret and delegates to the servicer.
func (s *Service) TenantBarrierUnseal(ctx context.Context, req *pb.TenantBarrierUnsealRequest) (*emptypb.Empty, error) {
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
	}

	if err := s.authorize(ctx, "tenant_barrier", "unseal", "barrier-unseal"); err != nil {
		return nil, err
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	svc, err := xkms.Get()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}

	unsealReq := &transport.TenantBarrierUnsealRequest{
		TenantID: tenantID,
		Key:      []byte(req.GetSecret()),
	}
	// A single Shamir recovery share, when provided, takes precedence.
	if shares := req.GetShareValues(); len(shares) > 0 {
		unsealReq.Share = []byte(shares[0])
	}

	if err := svc.TenantBarrierUnseal(ctx, unsealReq); err != nil {
		return nil, mapTenantError(err, "tenant barrier unseal")
	}

	return &emptypb.Empty{}, nil
}
