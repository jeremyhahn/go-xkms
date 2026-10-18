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

package xkms

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
)

// Compile-time check that XKMSService serves the TPM policy API.
var _ transport.TPMPolicyServicer = (*XKMSService)(nil)

// SetTPMPolicyService wires the TPM policy service (pkg/tpmpolicy) the
// TPMPolicy* methods delegate to.
func (s *XKMSService) SetTPMPolicyService(p *tpmpolicy.Service) { s.tpmPolicies.store(p) }

// TPMPolicyService returns the wired TPM policy service, or nil.
func (s *XKMSService) TPMPolicyService() *tpmpolicy.Service { return s.tpmPolicies.load() }

// tenantPolicies resolves the target tenant of op and returns its TPM
// policy operations. The binding is checked first, so a refused caller
// learns nothing about the node's configuration.
func (s *XKMSService) tenantPolicies(ctx context.Context, op, requested string) (*TenantTPMPolicies, error) {
	tenant, err := ownTenant(ctx, op, requested)
	if err != nil {
		return nil, err
	}
	return NewTenantTPMPolicies(s.tpmPolicies.load(), tenant)
}

// tenantTPMService resolves the policy service for the tenant TPM mode and vTPM
// operations, which only a system caller may perform on any tenant.
func (s *XKMSService) tenantTPMService(ctx context.Context, op, tenantID string) (*tpmpolicy.Service, error) {
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}
	if !qrdbsdk.IdentityIsSystemTenant(auth.GetIdentity(ctx)) {
		return nil, refuseTenant(ctx, op, tenantID)
	}
	svc := s.tpmPolicies.load()
	if svc == nil {
		return nil, ErrNotConfigured
	}
	return svc, nil
}

// TPMPolicyCreate creates a named TPM policy over the live PCR values of the
// target tenant's TPM.
func (s *XKMSService) TPMPolicyCreate(ctx context.Context, req *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := s.tenantPolicies(ctx, "tpm policy create", req.TenantID)
	if err != nil {
		return nil, err
	}
	return p.TPMPolicyCreate(ctx, req)
}

// TPMPolicyGet returns a named TPM policy of the target tenant.
func (s *XKMSService) TPMPolicyGet(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := s.tenantPolicies(ctx, "tpm policy get", req.TenantID)
	if err != nil {
		return nil, err
	}
	return p.TPMPolicyGet(ctx, req)
}

// TPMPolicyList returns the target tenant's named TPM policies.
func (s *XKMSService) TPMPolicyList(ctx context.Context, req *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := s.tenantPolicies(ctx, "tpm policy list", req.TenantID)
	if err != nil {
		return nil, err
	}
	return p.TPMPolicyList(ctx, req)
}

// TPMPolicyUpdate re-captures a policy's PCR values, or updates one branch
// from signed reference values, and re-approves it at the scope's next
// epoch. No object is re-keyed.
func (s *XKMSService) TPMPolicyUpdate(ctx context.Context, req *transport.TPMPolicyUpdateRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := s.tenantPolicies(ctx, "tpm policy update", req.TenantID)
	if err != nil {
		return nil, err
	}
	return p.TPMPolicyUpdate(ctx, req)
}

// TPMPolicyRevoke withdraws a policy's approval; its objects answer only to
// their password branch until it is updated.
func (s *XKMSService) TPMPolicyRevoke(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := s.tenantPolicies(ctx, "tpm policy revoke", req.TenantID)
	if err != nil {
		return nil, err
	}
	return p.TPMPolicyRevoke(ctx, req)
}

// TPMPolicyVerify compares a policy's captured PCR values with the live ones
// and reports whether its approval is current.
func (s *XKMSService) TPMPolicyVerify(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := s.tenantPolicies(ctx, "tpm policy verify", req.TenantID)
	if err != nil {
		return nil, err
	}
	return p.TPMPolicyVerify(ctx, req)
}

// TPMPolicyDelete deletes a policy and its NV index. It is refused with
// *tpmpolicy.PolicyInUseError, listing them, while objects use the policy.
func (s *XKMSService) TPMPolicyDelete(ctx context.Context, req *transport.TPMPolicyDeleteRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	p, err := s.tenantPolicies(ctx, "tpm policy delete", req.TenantID)
	if err != nil {
		return err
	}
	return p.TPMPolicyDelete(ctx, req)
}

// TPMPolicyObjects lists the objects assigned to a policy of the target
// tenant.
func (s *XKMSService) TPMPolicyObjects(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := s.tenantPolicies(ctx, "tpm policy objects", req.TenantID)
	if err != nil {
		return nil, err
	}
	return p.TPMPolicyObjects(ctx, req)
}

// TPMPolicySetAutoUnseal sets or clears a policy's auto-unseal mark and
// returns the policy as stored.
func (s *XKMSService) TPMPolicySetAutoUnseal(ctx context.Context, req *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := s.tenantPolicies(ctx, "tpm policy auto-unseal", req.TenantID)
	if err != nil {
		return nil, err
	}
	return p.TPMPolicySetAutoUnseal(ctx, req)
}

// TPMPolicySetDescription replaces a policy's description.
func (s *XKMSService) TPMPolicySetDescription(ctx context.Context, req *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := s.tenantPolicies(ctx, "tpm policy set description", req.TenantID)
	if err != nil {
		return nil, err
	}
	return p.TPMPolicySetDescription(ctx, req)
}

// TPMObjectPolicy returns the policy the target tenant's TPM key or sealed
// object was created under. The object is resolved in the caller's tenant
// only, so another tenant's object is not found.
func (s *XKMSService) TPMObjectPolicy(ctx context.Context, req *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := s.tenantPolicies(ctx, "tpm object policy", req.TenantID)
	if err != nil {
		return nil, err
	}
	return p.TPMObjectPolicy(ctx, req)
}

// TPMPolicyRotateAuthority replaces the target tenant's policy authority:
// every policy index is rewritten to name the new authority and every
// current approval is re-signed by it. No object is re-keyed.
func (s *XKMSService) TPMPolicyRotateAuthority(ctx context.Context, req *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := s.tenantPolicies(ctx, "tpm authority rotate", req.TenantID)
	if err != nil {
		return nil, err
	}
	return p.TPMPolicyRotateAuthority(ctx, req)
}

// GetTenantTPMMode returns a tenant's TPM mode. System scope only.
func (s *XKMSService) GetTenantTPMMode(ctx context.Context, tenantID string) (*transport.TenantTPMModeResponse, error) {
	svc, err := s.tenantTPMService(ctx, "get tenant tpm mode", tenantID)
	if err != nil {
		return nil, err
	}
	mode, err := svc.Mode(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return &transport.TenantTPMModeResponse{TenantID: tenantID, Mode: string(mode)}, nil
}

// SetTenantTPMMode changes a tenant's TPM mode. System scope only; it is
// refused while the tenant's scope holds objects or policies.
func (s *XKMSService) SetTenantTPMMode(ctx context.Context, req *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	svc, err := s.tenantTPMService(ctx, "set tenant tpm mode", req.TenantID)
	if err != nil {
		return nil, err
	}
	mode, err := tpmpolicy.ParseMode(req.Mode)
	if err != nil {
		return nil, err
	}
	if err := svc.SetMode(ctx, req.TenantID, mode, req.OwnerAuth); err != nil {
		return nil, err
	}
	return &transport.TenantTPMModeResponse{TenantID: req.TenantID, Mode: string(mode)}, nil
}

// TenantVTPMStatus reports a tenant's virtual TPM. System scope only.
func (s *XKMSService) TenantVTPMStatus(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	svc, err := s.tenantTPMService(ctx, "tenant vtpm status", tenantID)
	if err != nil {
		return nil, err
	}
	return vtpmStatusToTransport(tenantID, svc.VTPMStatus(tenantID)), nil
}

// TenantVTPMStart starts a vtpm-mode tenant's virtual TPM. System scope
// only.
func (s *XKMSService) TenantVTPMStart(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	svc, err := s.tenantTPMService(ctx, "tenant vtpm start", tenantID)
	if err != nil {
		return nil, err
	}
	if err := svc.StartVTPM(ctx, tenantID); err != nil {
		return nil, err
	}
	return vtpmStatusToTransport(tenantID, svc.VTPMStatus(tenantID)), nil
}

// TenantVTPMStop stops a vtpm-mode tenant's virtual TPM, which saves its
// state. System scope only.
func (s *XKMSService) TenantVTPMStop(ctx context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	svc, err := s.tenantTPMService(ctx, "tenant vtpm stop", tenantID)
	if err != nil {
		return nil, err
	}
	if err := svc.StopVTPM(ctx, tenantID); err != nil {
		return nil, err
	}
	return vtpmStatusToTransport(tenantID, svc.VTPMStatus(tenantID)), nil
}

// vtpmStatusToTransport converts a vTPM supervisor status to its API form.
func vtpmStatusToTransport(tenant string, st vtpm.Status) *transport.TenantVTPMStatusResponse {
	return &transport.TenantVTPMStatusResponse{
		TenantID: tenant,
		Running:  st.Running,
		PID:      st.PID,
		Socket:   st.Socket,
		Restarts: st.Restarts,
	}
}
