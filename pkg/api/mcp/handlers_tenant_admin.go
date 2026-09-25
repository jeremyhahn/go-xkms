// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package mcp

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
)

// tenantAdminSuccess is the uniform success envelope for a tenant mutation
// that returns no other payload.
var tenantAdminSuccess = map[string]interface{}{"success": true}

// TenantIDParams selects a tenant by ID.
type TenantIDParams struct {
	TenantID string `json:"tenant_id"`
}

// tenantIDParam decodes and validates a TenantIDParams from req.
func tenantIDParam(req *JSONRPCRequest) (string, error) {
	var params TenantIDParams
	if err := decodeParams(req, &params); err != nil {
		return "", err
	}
	if params.TenantID == "" {
		return "", &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "tenant_id is required"}}
	}
	return params.TenantID, nil
}

// tenantAdminAccessDenied reports whether identity is a tenant-scoped
// identity naming a tenant other than tenantID. It mirrors REST's
// isCrossTenantAccess (pkg/api/rest/handlers_tenant.go): a nil identity or
// one scoped to the reserved system tenant (auth.IsCrossTenant) may address
// every tenant; a genuinely tenant-scoped identity may only address its own.
func tenantAdminAccessDenied(identity *auth.Identity, tenantID string) bool {
	if auth.IsCrossTenant(identity) || tenantID == "" {
		return false
	}
	return identity.TenantID != tenantID
}

// refuseCrossTenantAdmin returns the anti-enumeration refusal REST issues
// (seal.ErrTenantNotFound) when the caller is tenant-scoped to a tenant other
// than tenantID, and nil otherwise. Reporting the identical error a genuine
// miss produces -- rather than a distinct "forbidden" -- keeps a cross-tenant
// probe indistinguishable from a nonexistent tenant ID, exactly as REST's
// GetTenantHandler/DeleteTenantHandler/TenantBarrier*Handler comment records.
func refuseCrossTenantAdmin(ctx context.Context, tid string) error {
	if tenantAdminAccessDenied(auth.GetIdentity(ctx), tid) {
		return mapTenantError(seal.ErrTenantNotFound, "tenant admin")
	}
	return nil
}

// handleCreateTenant handles the xkms.createTenant method: provisions a
// sealed tenant shell (Phase 1 of the two-phase tenant barrier model).
// Delegates entirely to the xkms service layer (XKMSService.CreateTenant).
// REST's CreateTenantHandler applies no cross-tenant restriction (a new
// tenant cannot yet be "owned" by anyone), and neither does this handler.
func (s *Server) handleCreateTenant(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.CreateTenantRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.ID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "id is required"}}
	}
	if params.Name == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "name is required"}}
	}

	resp, err := s.xkmsService.CreateTenant(ctx, &params)
	if err != nil {
		return nil, mapTenantError(err, "create tenant")
	}

	return resp, nil
}

// handleGetTenant handles the xkms.getTenant method: retrieves a single
// tenant's metadata by ID. A tenant-scoped caller naming another tenant
// receives the same refusal a nonexistent tenant ID would, matching REST's
// GetTenantHandler anti-enumeration behavior.
func (s *Server) handleGetTenant(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	tid, err := tenantIDParam(req)
	if err != nil {
		return nil, err
	}
	if err := refuseCrossTenantAdmin(ctx, tid); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.GetTenant(ctx, tid)
	if err != nil {
		return nil, mapTenantError(err, "get tenant")
	}

	return resp, nil
}

// handleListTenants handles the xkms.listTenants method: returns every
// tenant a system-scoped caller may see, or only the caller's own tenant for
// a tenant-scoped identity, matching REST's ListTenantsHandler filter. Takes
// no params.
func (s *Server) handleListTenants(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	resp, err := s.xkmsService.ListTenants(ctx)
	if err != nil {
		return nil, mapTenantError(err, "list tenants")
	}

	identity := auth.GetIdentity(ctx)
	if identity != nil && !auth.IsCrossTenant(identity) {
		filtered := make([]transport.TenantInfo, 0, len(resp.Tenants))
		for _, t := range resp.Tenants {
			if t.ID == identity.TenantID {
				filtered = append(filtered, t)
			}
		}
		resp.Tenants = filtered
	}

	return resp, nil
}

// handleDeleteTenant handles the xkms.deleteTenant method: removes a tenant.
// A tenant-scoped caller naming another tenant receives the same refusal a
// nonexistent tenant ID would, matching REST's DeleteTenantHandler.
func (s *Server) handleDeleteTenant(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	tid, err := tenantIDParam(req)
	if err != nil {
		return nil, err
	}
	if err := refuseCrossTenantAdmin(ctx, tid); err != nil {
		return nil, err
	}

	if err := s.xkmsService.DeleteTenant(ctx, tid); err != nil {
		return nil, mapTenantError(err, "delete tenant")
	}

	return tenantAdminSuccess, nil
}

// handleTenantBarrierInit handles the xkms.tenantBarrierInit method:
// initializes a tenant's own barrier (Phase 2 of the two-phase model) with
// the tenant admin's own caller-supplied credentials -- the server never
// generates a tenant secret. A tenant-scoped caller naming another tenant
// receives the same refusal a nonexistent tenant ID would, matching REST's
// TenantBarrierInitHandler. On success it reports the resulting barrier
// status, exactly as the REST handler does.
func (s *Server) handleTenantBarrierInit(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.TenantBarrierInitRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.TenantID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "tenant_id is required"}}
	}
	if err := refuseCrossTenantAdmin(ctx, params.TenantID); err != nil {
		return nil, err
	}

	if err := s.xkmsService.TenantBarrierInit(ctx, &params); err != nil {
		return nil, mapTenantError(err, "tenant barrier init")
	}

	resp, err := s.xkmsService.TenantBarrierStatus(ctx, params.TenantID)
	if err != nil {
		return nil, mapTenantError(err, "tenant barrier status")
	}

	return resp, nil
}

// handleTenantBarrierUnseal handles the xkms.tenantBarrierUnseal method:
// unseals a tenant's own barrier using caller-supplied recovery material.
// A tenant-scoped caller naming another tenant receives the same refusal a
// nonexistent tenant ID would, matching REST's TenantBarrierUnsealHandler.
// On success it reports the resulting barrier status, exactly as the REST
// handler does.
func (s *Server) handleTenantBarrierUnseal(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.TenantBarrierUnsealRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.TenantID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "tenant_id is required"}}
	}
	if err := refuseCrossTenantAdmin(ctx, params.TenantID); err != nil {
		return nil, err
	}

	if err := s.xkmsService.TenantBarrierUnseal(ctx, &params); err != nil {
		return nil, mapTenantError(err, "tenant barrier unseal")
	}

	resp, err := s.xkmsService.TenantBarrierStatus(ctx, params.TenantID)
	if err != nil {
		return nil, mapTenantError(err, "tenant barrier status")
	}

	return resp, nil
}

// handleTenantBarrierStatus handles the xkms.tenantBarrierStatus method:
// reports a tenant's own barrier status (sealed/initialized, active
// strategy, hardware-backing, Shamir quorum). A tenant-scoped caller naming
// another tenant receives the same refusal a nonexistent tenant ID would,
// matching REST's TenantBarrierStatusHandler.
func (s *Server) handleTenantBarrierStatus(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	tid, err := tenantIDParam(req)
	if err != nil {
		return nil, err
	}
	if err := refuseCrossTenantAdmin(ctx, tid); err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.TenantBarrierStatus(ctx, tid)
	if err != nil {
		return nil, mapTenantError(err, "tenant barrier status")
	}

	return resp, nil
}

// handleUpdateTenantEntitlements handles the xkms.updateTenantEntitlements
// method: updates which isolation tiers and dedicated-storage features a
// tenant's plan permits. REST's UpdateTenantEntitlementsHandler applies no
// cross-tenant restriction of its own -- entitlement management is a
// platform-admin operation gated by RBAC alone -- and neither does this
// handler.
func (s *Server) handleUpdateTenantEntitlements(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.UpdateTenantEntitlementsRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.TenantID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "tenant_id is required"}}
	}

	resp, err := s.xkmsService.UpdateTenantEntitlements(ctx, &params)
	if err != nil {
		return nil, mapTenantError(err, "update tenant entitlements")
	}

	return resp, nil
}

// handleUpdateTenantQuotas handles the xkms.updateTenantQuotas method:
// updates a tenant's resource quotas. REST's UpdateTenantQuotasHandler
// applies no cross-tenant restriction of its own -- quota management is a
// platform-admin operation gated by RBAC alone -- and neither does this
// handler.
func (s *Server) handleUpdateTenantQuotas(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.UpdateTenantQuotasRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if params.TenantID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "tenant_id is required"}}
	}

	resp, err := s.xkmsService.UpdateTenantQuotas(ctx, &params)
	if err != nil {
		return nil, mapTenantError(err, "update tenant quotas")
	}

	return resp, nil
}
