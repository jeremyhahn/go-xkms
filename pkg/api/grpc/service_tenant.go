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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ErrBarrierRegistryNotConfigured is returned when the barrier registry has
// not been configured via SetBarrierRegistry.
var ErrBarrierRegistryNotConfigured = errors.New("grpc: barrier registry not configured")

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

	// The composed go-qrdb TenantService reports an unknown tenant with its
	// own sentinel, and XKMSService's tenant binding refuses a foreign tenant
	// with an error that unwraps to it (xkms.TenantBindingError); both are
	// NotFound so a foreign tenant reads exactly like a missing one.
	qrdbsdk.ErrTenantMissing: codes.NotFound,
}

// barrierRegistry is the registry tenant operations resolve through.
var barrierRegistry *seal.BarrierRegistry

// SetBarrierRegistry configures the barrier registry for tenant operations.
// This must be called before any tenant RPCs can be used.
func SetBarrierRegistry(br *seal.BarrierRegistry) {
	barrierRegistry = br
}

// GetBarrierRegistry returns the configured barrier registry, or nil if not set.
func GetBarrierRegistry() *seal.BarrierRegistry {
	return barrierRegistry
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
	tb, err := barrierRegistry.RegisterTenantDefault(tenantID)
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
// the isolation metadata surfaces alongside the live sealed state. The
// servicer owns the tenant binding: a tenant-scoped caller naming another
// tenant gets NotFound, exactly as for a nonexistent tenant.
func (s *Service) GetTenant(ctx context.Context, req *pb.GetTenantRequest) (*pb.GetTenantResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionRead, "get"); err != nil {
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

// ListTenants returns the tenants the caller may see, delegating to the
// XKMSService servicer, which confines a tenant-scoped caller to its own
// tenant.
func (s *Service) ListTenants(ctx context.Context, _ *pb.ListTenantsRequest) (*pb.ListTenantsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionList, "list"); err != nil {
		return nil, err
	}

	svc := s.xkmsService
	if svc == nil {
		return nil, status.Error(codes.Unavailable, "xkms service not initialized")
	}
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

// DeleteTenant deletes a tenant, delegating to the XKMSService servicer. The
// servicer owns the tenant binding: a tenant-scoped caller naming another
// tenant gets NotFound, exactly as for a nonexistent tenant.
func (s *Service) DeleteTenant(ctx context.Context, req *pb.DeleteTenantRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionDelete, "delete"); err != nil {
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
	if err := svc.DeleteTenant(ctx, tenantID); err != nil {
		return nil, mapTenantError(err, "delete tenant")
	}
	return &emptypb.Empty{}, nil
}

// UpdateTenantEntitlements updates a tenant's feature entitlements, delegating
// to the XKMSService servicer. It requires tenants:set_entitlements, and the
// servicer admits only a cross-tenant identity (a tenant-scoped caller gets
// NotFound, even for its own tenant).
func (s *Service) UpdateTenantEntitlements(ctx context.Context, req *pb.UpdateTenantEntitlementsRequest) (*pb.UpdateTenantEntitlementsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionSetEntitlements, "update-entitlements"); err != nil {
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
// XKMSService servicer. It requires tenants:set_quotas, and the servicer
// admits only a cross-tenant identity (a tenant-scoped caller gets NotFound,
// even for its own tenant).
func (s *Service) UpdateTenantQuotas(ctx context.Context, req *pb.UpdateTenantQuotasRequest) (*pb.UpdateTenantQuotasResponse, error) {
	if err := s.authorize(ctx, auth.ResourceTenants, auth.ActionSetQuotas, "update-quotas"); err != nil {
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
