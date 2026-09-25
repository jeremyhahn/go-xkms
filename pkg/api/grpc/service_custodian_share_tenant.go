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

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
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

// mapCustodianError converts a custodian domain error to the appropriate
// gRPC status error, classifying it through apierrors.CustodianSentinelClasses
// -- the table go-xkms#773 made this package share with pkg/api/mcp's mirror
// of this function, following the go-xkms#912 precedent set for PIV and
// barrier. If the error is a known custodian error, it maps to the
// corresponding gRPC code. Otherwise, it returns an Internal error.
func mapCustodianError(err error, operation string) error {
	if err == nil {
		return nil
	}
	if class, ok := apierrors.ClassOf(apierrors.CustodianSentinelClasses, err); ok {
		return status.Errorf(grpcCodeForClass(class), "%s: %v", operation, err)
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
	// go-qrdb tenant entitlement / barrier-mode / quota denials → precise gRPC
	// codes instead of a generic Internal, so operators see the actual denial.
	var entErr *qrdbsdk.EntitlementError
	switch {
	case errors.As(err, &entErr):
		// Plan does not entitle the requested isolation/barrier mode or feature.
		return status.Errorf(codes.PermissionDenied, "%s: %v", operation, err)
	case errors.Is(err, qrdbsdk.ErrSharedBarrierImmutable):
		// A shared-barrier tenant's barrier mode cannot be changed in place.
		return status.Errorf(codes.FailedPrecondition, "%s: %v", operation, err)
	case qrdbsdk.IsQuotaExceeded(err):
		// Resource quota for the tenant's plan is exhausted.
		return status.Errorf(codes.ResourceExhausted, "%s: %v", operation, err)
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

	if err := s.authorize(ctx, auth.ResourceCeremony, auth.ActionEnrollCustodian, "create-group"); err != nil {
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

	if err := s.authorize(ctx, auth.ResourceCeremony, auth.ActionStatus, "get-group"); err != nil {
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

	if err := s.authorize(ctx, auth.ResourceCeremony, auth.ActionStatus, "list-groups"); err != nil {
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

	if err := s.authorize(ctx, auth.ResourceCeremony, auth.ActionRevokeCustodian, "delete-group"); err != nil {
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

	if err := s.authorize(ctx, auth.ResourceCeremony, auth.ActionEnrollCustodian, "add-member"); err != nil {
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

	if err := s.authorize(ctx, auth.ResourceCeremony, auth.ActionRevokeCustodian, "remove-member"); err != nil {
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

	if err := s.authorize(ctx, auth.ResourceCeremony, auth.ActionClaimShareBegin, "distribute-shares"); err != nil {
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

	if err := s.authorize(ctx, auth.ResourceBarrier, auth.ActionUnsealShare, "submit"); err != nil {
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

	if err := s.authorize(ctx, auth.ResourceCeremony, auth.ActionStatus, "list"); err != nil {
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

// GetShare returns a single stored share addressed by (server_url, group_id,
// share_index). Sensitive share material is never included in the response.
// The request is passed through to the embedded go-qrdb node's share client.
func (s *Service) GetShare(ctx context.Context, req *pb.GetShareRequest) (*pb.ShareInfo, error) {
	if shareClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrShareClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, auth.ResourceCeremony, auth.ActionStatus, "get"); err != nil {
		return nil, err
	}

	serverURL, groupID, shareIndex, err := shareCoordinates(req.GetServerUrl(), req.GetGroupId(), req.GetShareIndex())
	if err != nil {
		return nil, err
	}

	info, err := shareClient.GetShare(ctx, serverURL, groupID, shareIndex)
	if err != nil {
		return nil, mapShareError(err, "get share")
	}

	return shareInfoToProto(info), nil
}

// DeleteShare removes a single stored share addressed by (server_url,
// group_id, share_index). The request is passed through to the embedded
// go-qrdb node's share client.
func (s *Service) DeleteShare(ctx context.Context, req *pb.DeleteShareRequest) (*emptypb.Empty, error) {
	if shareClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrShareClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, auth.ResourceBarrier, auth.ActionUnsealShare, "delete"); err != nil {
		return nil, err
	}

	serverURL, groupID, shareIndex, err := shareCoordinates(req.GetServerUrl(), req.GetGroupId(), req.GetShareIndex())
	if err != nil {
		return nil, err
	}

	if err := shareClient.DeleteShare(ctx, serverURL, groupID, shareIndex); err != nil {
		return nil, mapShareError(err, "delete share")
	}

	return &emptypb.Empty{}, nil
}

// shareCoordinates validates the triple that addresses a single share.
func shareCoordinates(serverURL, groupID string, shareIndex int32) (string, string, int, error) {
	if serverURL == "" {
		return "", "", 0, status.Error(codes.InvalidArgument, "server_url is required")
	}
	if groupID == "" {
		return "", "", 0, status.Error(codes.InvalidArgument, "group_id is required")
	}
	return serverURL, groupID, int(shareIndex), nil
}

// GetShareCollectionStatus returns the share collection status for a group. The
// request is passed through to the embedded go-qrdb node's share client, which
// reports threshold progress for the group.
func (s *Service) GetShareCollectionStatus(ctx context.Context, req *pb.GetShareCollectionStatusRequest) (*pb.ShareCollectionStatusResponse, error) {
	if shareClient == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrShareClientNotConfigured.Error())
	}

	if err := s.authorize(ctx, auth.ResourceCeremony, auth.ActionStatus, "collection-status"); err != nil {
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

// CreateTenant creates a new tenant. It delegates to the XKMSService servicer
// so the requested isolation mode and the system-managed auto-unseal
// key-management mode are entitlement-gated and the per-tenant barrier is
// sealed by the composed hardware strategies (the security and isolation
// invariants live in exactly one place).
func (s *Service) CreateTenant(ctx context.Context, req *pb.CreateTenantRequest) (*pb.CreateTenantResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionCreate, "create"); err != nil {
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

	if svc := s.xkmsService; svc != nil {
		createResp, err := svc.CreateTenant(ctx, &transport.CreateTenantRequest{
			ID:                tenantID,
			Name:              name,
			IsolationType:     transport.TenantIsolationType(req.GetIsolationType()),
			BarrierAutoUnseal: req.GetBarrierAutoUnseal(),
		})
		if err != nil {
			return nil, mapTenantError(err, "create tenant")
		}
		return &pb.CreateTenantResponse{
			Tenant: &pb.TenantInfo{
				Id:            createResp.Tenant.ID,
				Name:          createResp.Tenant.Name,
				Description:   req.GetDescription(),
				Status:        s.tenantSealedStatus(tenantID),
				IsolationType: string(createResp.Tenant.IsolationType),
				CreatedAt:     time.Now().UTC().Format(time.RFC3339),
			},
		}, nil
	}

	// Legacy path: no XKMS service wired (only seen in isolated unit tests).
	// Register the sealed tenant shell directly in the barrier registry.
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
	}
	tb, err := barrierRegistry.RegisterTenant(tenantID)
	if err != nil {
		return nil, mapTenantError(err, "create tenant")
	}
	return &pb.CreateTenantResponse{
		Tenant: &pb.TenantInfo{
			Id:          tenantID,
			Name:        name,
			Description: req.GetDescription(),
			Status:      sealedStatusString(tb.IsSealed()),
			CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}

// sealedStatusString maps a sealed boolean to the gRPC status string.
func sealedStatusString(sealed bool) string {
	if sealed {
		return "sealed"
	}
	return "unsealed"
}

// tenantSealedStatus reports the live sealed state of a tenant's barrier as the
// gRPC status string. Prefix-isolated tenants have no dedicated barrier and are
// reported "unsealed"; a dedicated-isolation tenant reports its barrier state.
func (s *Service) tenantSealedStatus(tenantID string) string {
	if barrierRegistry == nil {
		return "unsealed"
	}
	tb, err := barrierRegistry.Tenant(tenantID)
	if err != nil {
		return "unsealed"
	}
	if tb.IsSealed() {
		return "sealed"
	}
	return "unsealed"
}

// GetTenant retrieves a tenant by ID, delegating to the XKMSService servicer so
// the isolation metadata surfaces alongside the live sealed state.
func (s *Service) GetTenant(ctx context.Context, req *pb.GetTenantRequest) (*pb.GetTenantResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionRead, "get"); err != nil {
		return nil, err
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if svc := s.xkmsService; svc != nil {
		getResp, err := svc.GetTenant(ctx, tenantID)
		if err != nil {
			return nil, mapTenantError(err, "get tenant")
		}
		return &pb.GetTenantResponse{
			Tenant: &pb.TenantInfo{
				Id:            getResp.Tenant.ID,
				Name:          getResp.Tenant.Name,
				Status:        s.tenantSealedStatus(tenantID),
				IsolationType: string(getResp.Tenant.IsolationType),
			},
		}, nil
	}

	// Legacy path: no XKMS service wired.
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
	}
	tb, err := barrierRegistry.Tenant(tenantID)
	if err != nil {
		return nil, mapTenantError(err, "get tenant")
	}
	return &pb.GetTenantResponse{
		Tenant: &pb.TenantInfo{
			Id:     tb.TenantID(),
			Status: sealedStatusString(tb.IsSealed()),
		},
	}, nil
}

// ListTenants returns all tenants, delegating to the XKMSService servicer.
func (s *Service) ListTenants(ctx context.Context, _ *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionList, "list"); err != nil {
		return nil, err
	}

	if svc := s.xkmsService; svc != nil {
		listResp, err := svc.ListTenants(ctx)
		if err != nil {
			return nil, mapTenantError(err, "list tenants")
		}
		tenants := make([]*pb.TenantInfo, 0, len(listResp.Tenants))
		for i := range listResp.Tenants {
			t := &listResp.Tenants[i]
			tenants = append(tenants, &pb.TenantInfo{
				Id:            t.ID,
				Name:          t.Name,
				Status:        s.tenantSealedStatus(t.ID),
				IsolationType: string(t.IsolationType),
			})
		}
		return &pb.ListTenantsResponse{Tenants: tenants}, nil
	}

	// Legacy path: no XKMS service wired.
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
	}
	ids := barrierRegistry.ListTenants()
	tenants := make([]*pb.TenantInfo, 0, len(ids))
	for _, id := range ids {
		tb, err := barrierRegistry.Tenant(id)
		if err != nil {
			continue
		}
		tenants = append(tenants, &pb.TenantInfo{
			Id:     id,
			Status: sealedStatusString(tb.IsSealed()),
		})
	}
	return &pb.ListTenantsResponse{Tenants: tenants}, nil
}

// DeleteTenant deletes a tenant, delegating to the XKMSService servicer.
func (s *Service) DeleteTenant(ctx context.Context, req *pb.DeleteTenantRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionDelete, "delete"); err != nil {
		return nil, err
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if svc := s.xkmsService; svc != nil {
		if err := svc.DeleteTenant(ctx, tenantID); err != nil {
			return nil, mapTenantError(err, "delete tenant")
		}
		return &emptypb.Empty{}, nil
	}

	// Legacy path: no XKMS service wired.
	if barrierRegistry == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBarrierRegistryNotConfigured.Error())
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

	if err := s.authorize(ctx, auth.ResourceTenantBarrier, auth.ActionInit, "barrier-init"); err != nil {
		return nil, err
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	if err := svc.TenantBarrierInit(ctx, &transport.TenantBarrierInitRequest{
		TenantID:   tenantID,
		Passphrase: []byte(req.GetSecret()),
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

	if err := s.authorize(ctx, auth.ResourceTenantBarrier, auth.ActionUnseal, "barrier-unseal"); err != nil {
		return nil, err
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	svc := s.xkmsService
	if svc == nil {
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

// TenantBarrierStatus reports the current state of a per-tenant barrier,
// delegating to the XKMSService servicer.
func (s *Service) TenantBarrierStatus(ctx context.Context, req *pb.TenantBarrierStatusRequest) (*pb.TenantBarrierStatusResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenantBarrier, auth.ActionStatus, "barrier-status"); err != nil {
		return nil, err
	}
	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	st, err := svc.TenantBarrierStatus(ctx, tenantID)
	if err != nil {
		return nil, mapTenantError(err, "tenant barrier status")
	}
	return &pb.TenantBarrierStatusResponse{
		TenantId:        st.TenantID,
		Sealed:          st.Sealed,
		Initialized:     st.Initialized,
		Strategy:        st.Strategy,
		HardwareBacked:  st.HardwareBacked,
		ShamirThreshold: int32(st.ShamirThreshold), // #nosec G115 - threshold fits in int32
		ShamirTotal:     int32(st.ShamirTotal),     // #nosec G115 - total fits in int32
	}, nil
}

// UpdateTenantEntitlements updates a tenant's feature entitlements, delegating
// to the XKMSService servicer.
func (s *Service) UpdateTenantEntitlements(ctx context.Context, req *pb.UpdateTenantEntitlementsRequest) (*pb.UpdateTenantEntitlementsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionUpdate, "update-entitlements"); err != nil {
		return nil, err
	}
	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := svc.UpdateTenantEntitlements(ctx, &transport.UpdateTenantEntitlementsRequest{
		TenantID:     tenantID,
		Entitlements: pbToTransportEntitlements(req.GetEntitlements()),
	})
	if err != nil {
		return nil, mapTenantError(err, "update tenant entitlements")
	}
	return &pb.UpdateTenantEntitlementsResponse{Tenant: transportToPBTenantInfo(&resp.Tenant)}, nil
}

// UpdateTenantQuotas updates a tenant's resource quotas, delegating to the
// XKMSService servicer.
func (s *Service) UpdateTenantQuotas(ctx context.Context, req *pb.UpdateTenantQuotasRequest) (*pb.UpdateTenantQuotasResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionUpdate, "update-quotas"); err != nil {
		return nil, err
	}
	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}
	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
	resp, err := svc.UpdateTenantQuotas(ctx, &transport.UpdateTenantQuotasRequest{
		TenantID: tenantID,
		Quotas:   pbToTransportQuotas(req.GetQuotas()),
	})
	if err != nil {
		return nil, mapTenantError(err, "update tenant quotas")
	}
	return &pb.UpdateTenantQuotasResponse{Tenant: transportToPBTenantInfo(&resp.Tenant)}, nil
}

// pbToTransportEntitlements maps a proto entitlement message onto the wire DTO.
func pbToTransportEntitlements(e *pb.TenantEntitlements) transport.TenantEntitlements {
	if e == nil {
		return transport.TenantEntitlements{}
	}
	return transport.TenantEntitlements{
		AllowedIsolationModes:     e.GetAllowedIsolationModes(),
		AllowDedicatedRaft:        e.GetAllowDedicatedRaft(),
		AllowVolumeStorage:        e.GetAllowVolumeStorage(),
		AllowSystemManagedBarrier: e.GetAllowSystemManagedBarrier(),
	}
}

// pbToTransportQuotas maps a proto quota message onto the wire DTO.
func pbToTransportQuotas(q *pb.TenantQuotas) transport.TenantQuotas {
	if q == nil {
		return transport.TenantQuotas{}
	}
	return transport.TenantQuotas{
		MaxDatabases:         q.GetMaxDatabases(),
		MaxRaftGroups:        q.GetMaxRaftGroups(),
		MaxReplicasPerGroup:  q.GetMaxReplicasPerGroup(),
		MaxTotalReplicas:     q.GetMaxTotalReplicas(),
		MaxCollections:       q.GetMaxCollections(),
		MaxKeys:              q.GetMaxKeys(),
		MaxStorageBytes:      q.GetMaxStorageBytes(),
		MaxDatabaseSizeBytes: q.GetMaxDatabaseSizeBytes(),
		MaxUsers:             q.GetMaxUsers(),
		MaxRoles:             q.GetMaxRoles(),
		MaxCertificates:      q.GetMaxCertificates(),
		MaxBackups:           q.GetMaxBackups(),
		MaxVectorDims:        q.GetMaxVectorDims(),
		MaxTSMetrics:         q.GetMaxTsMetrics(),
	}
}

// transportToPBTenantInfo maps the wire tenant DTO onto its proto form,
// including quotas and entitlements.
func transportToPBTenantInfo(info *transport.TenantInfo) *pb.TenantInfo {
	if info == nil {
		return &pb.TenantInfo{}
	}
	out := &pb.TenantInfo{
		Id:            info.ID,
		Name:          info.Name,
		IsolationType: string(info.IsolationType),
		CreatedAt:     info.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:     info.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if info.Quotas != nil {
		out.Quotas = &pb.TenantQuotas{
			MaxDatabases:         info.Quotas.MaxDatabases,
			MaxRaftGroups:        info.Quotas.MaxRaftGroups,
			MaxReplicasPerGroup:  info.Quotas.MaxReplicasPerGroup,
			MaxTotalReplicas:     info.Quotas.MaxTotalReplicas,
			MaxCollections:       info.Quotas.MaxCollections,
			MaxKeys:              info.Quotas.MaxKeys,
			MaxStorageBytes:      info.Quotas.MaxStorageBytes,
			MaxDatabaseSizeBytes: info.Quotas.MaxDatabaseSizeBytes,
			MaxUsers:             info.Quotas.MaxUsers,
			MaxRoles:             info.Quotas.MaxRoles,
			MaxCertificates:      info.Quotas.MaxCertificates,
			MaxBackups:           info.Quotas.MaxBackups,
			MaxVectorDims:        info.Quotas.MaxVectorDims,
			MaxTsMetrics:         info.Quotas.MaxTSMetrics,
		}
	}
	if info.Entitlements != nil {
		out.Entitlements = &pb.TenantEntitlements{
			AllowedIsolationModes:     info.Entitlements.AllowedIsolationModes,
			AllowDedicatedRaft:        info.Entitlements.AllowDedicatedRaft,
			AllowVolumeStorage:        info.Entitlements.AllowVolumeStorage,
			AllowSystemManagedBarrier: info.Entitlements.AllowSystemManagedBarrier,
		}
	}
	return out
}
