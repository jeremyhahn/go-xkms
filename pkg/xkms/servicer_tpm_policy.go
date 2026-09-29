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
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
)

// Compile-time check that XKMSService serves the TPM policy API.
var _ transport.TPMPolicyServicer = (*XKMSService)(nil)

// InvalidTPMObjectKindError reports a TPM object kind other than "key" or
// "sealed".
type InvalidTPMObjectKindError struct {
	Kind string
}

// Error implements the error interface.
func (e *InvalidTPMObjectKindError) Error() string {
	return fmt.Sprintf("keystore: invalid TPM object kind %q (want %s or %s)", e.Kind, transport.TPMObjectKindKey, transport.TPMObjectKindSealed)
}

// objectKinds maps the API's object kinds to the policy service's.
var objectKinds = map[string]tpmpolicy.ObjectKind{
	"":                            tpmpolicy.ObjectKey,
	transport.TPMObjectKindKey:    tpmpolicy.ObjectKey,
	transport.TPMObjectKindSealed: tpmpolicy.ObjectSealed,
}

// SetTPMPolicyService wires the TPM policy service (pkg/tpmpolicy) the
// TPMPolicy* methods delegate to.
func (s *XKMSService) SetTPMPolicyService(p *tpmpolicy.Service) { s.tpmPolicies.store(p) }

// TPMPolicyService returns the wired TPM policy service, or nil.
func (s *XKMSService) TPMPolicyService() *tpmpolicy.Service { return s.tpmPolicies.load() }

// tpmPolicyTarget resolves the tenant a TPM policy operation acts on. A
// cross-tenant (system) caller acts on requested, "" being the system scope.
// A tenant-scoped caller acts on its own tenant: requested may be empty or
// name that tenant, and naming another is refused with *TenantBindingError.
func tpmPolicyTarget(ctx context.Context, op, requested string) (string, error) {
	identity := auth.GetIdentity(ctx)
	if auth.IsCrossTenant(identity) {
		return requested, nil
	}
	if requested == "" {
		return identity.TenantID, nil
	}
	if err := bindTenantTarget(ctx, op, requested); err != nil {
		return "", err
	}
	return requested, nil
}

// tpmPolicyService resolves the target tenant of op and returns the wired
// policy service. The binding is checked first, so a refused caller learns
// nothing about the node's configuration.
func (s *XKMSService) tpmPolicyService(ctx context.Context, op, requested string) (*tpmpolicy.Service, string, error) {
	tenant, err := tpmPolicyTarget(ctx, op, requested)
	if err != nil {
		return nil, "", err
	}
	svc := s.tpmPolicies.load()
	if svc == nil {
		return nil, "", ErrNotConfigured
	}
	return svc, tenant, nil
}

// tenantTPMService is tpmPolicyService for the tenant TPM mode and vTPM
// operations, which only a system caller may perform on any tenant.
func (s *XKMSService) tenantTPMService(ctx context.Context, op, tenantID string) (*tpmpolicy.Service, error) {
	if tenantID == "" {
		return nil, ErrTenantIDRequired
	}
	if err := requirePlatformScope(ctx, op, tenantID); err != nil {
		return nil, err
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
	svc, tenant, err := s.tpmPolicyService(ctx, "tpm policy create", req.TenantID)
	if err != nil {
		return nil, err
	}
	p, err := svc.CreatePolicy(ctx, tenant, tpmpolicy.CreatePolicyRequest{
		Name:       req.Name,
		Bank:       req.Bank,
		PCRs:       req.PCRs,
		AutoUnseal: req.AutoUnseal,
		OwnerAuth:  req.OwnerAuth,
	})
	if err != nil {
		return nil, err
	}
	return tpmPolicyToTransport(tenant, p), nil
}

// TPMPolicyGet returns a named TPM policy of the target tenant.
func (s *XKMSService) TPMPolicyGet(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return s.tpmPolicyOp(ctx, "tpm policy get", req, (*tpmpolicy.Service).Policy)
}

// TPMPolicyUpdate re-captures a policy's PCR values and re-approves it at the
// scope's next epoch. No object is re-keyed.
func (s *XKMSService) TPMPolicyUpdate(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return s.tpmPolicyOp(ctx, "tpm policy update", req, (*tpmpolicy.Service).UpdatePolicy)
}

// TPMPolicyRevoke withdraws a policy's approval; its objects answer only to
// their password branch until it is updated.
func (s *XKMSService) TPMPolicyRevoke(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return s.tpmPolicyOp(ctx, "tpm policy revoke", req, (*tpmpolicy.Service).RevokePolicy)
}

// tpmPolicyOp runs op, a policy service operation that returns one policy,
// on the policy req names.
func (s *XKMSService) tpmPolicyOp(ctx context.Context, name string, req *transport.TPMPolicyRequest,
	op func(*tpmpolicy.Service, context.Context, string, string) (*tpmpolicy.Policy, error)) (*transport.TPMPolicy, error) {

	if req == nil {
		return nil, ErrNilRequest
	}
	svc, tenant, err := s.tpmPolicyService(ctx, name, req.TenantID)
	if err != nil {
		return nil, err
	}
	p, err := op(svc, ctx, tenant, req.Name)
	if err != nil {
		return nil, err
	}
	return tpmPolicyToTransport(tenant, p), nil
}

// TPMPolicyList returns the target tenant's named TPM policies.
func (s *XKMSService) TPMPolicyList(ctx context.Context, req *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	svc, tenant, err := s.tpmPolicyService(ctx, "tpm policy list", req.TenantID)
	if err != nil {
		return nil, err
	}
	policies, err := svc.ListPolicies(ctx, tenant)
	if err != nil {
		return nil, err
	}
	resp := &transport.TPMPolicyListResponse{Policies: make([]transport.TPMPolicy, 0, len(policies))}
	for _, p := range policies {
		resp.Policies = append(resp.Policies, *tpmPolicyToTransport(tenant, p))
	}
	return resp, nil
}

// TPMPolicyVerify compares a policy's captured PCR values with the live ones
// and reports whether its approval is current.
func (s *XKMSService) TPMPolicyVerify(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	svc, tenant, err := s.tpmPolicyService(ctx, "tpm policy verify", req.TenantID)
	if err != nil {
		return nil, err
	}
	v, err := svc.VerifyPolicy(ctx, tenant, req.Name)
	if err != nil {
		return nil, err
	}
	return &transport.TPMPolicyVerifyResponse{
		Name:       v.Policy,
		Match:      v.Match,
		Mismatched: v.Mismatched,
		Approved:   v.Approved,
	}, nil
}

// TPMPolicyDelete deletes a policy and its NV index. It is refused with
// *tpmpolicy.PolicyInUseError, listing them, while objects use the policy.
func (s *XKMSService) TPMPolicyDelete(ctx context.Context, req *transport.TPMPolicyDeleteRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	svc, tenant, err := s.tpmPolicyService(ctx, "tpm policy delete", req.TenantID)
	if err != nil {
		return err
	}
	return svc.DeletePolicy(ctx, tenant, req.Name, req.OwnerAuth)
}

// TPMPolicyObjects lists the objects assigned to a policy of the target
// tenant.
func (s *XKMSService) TPMPolicyObjects(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	svc, tenant, err := s.tpmPolicyService(ctx, "tpm policy objects", req.TenantID)
	if err != nil {
		return nil, err
	}
	objects, err := svc.ObjectsOf(ctx, tenant, req.Name)
	if err != nil {
		return nil, err
	}
	if objects == nil {
		objects = []string{}
	}
	return &transport.TPMPolicyObjectsResponse{Name: req.Name, Objects: objects}, nil
}

// TPMPolicySetAutoUnseal sets or clears a policy's auto-unseal mark and
// returns the policy as stored.
func (s *XKMSService) TPMPolicySetAutoUnseal(ctx context.Context, req *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	svc, tenant, err := s.tpmPolicyService(ctx, "tpm policy auto-unseal", req.TenantID)
	if err != nil {
		return nil, err
	}
	if err := svc.SetAutoUnseal(ctx, tenant, req.Name, req.Enabled); err != nil {
		return nil, err
	}
	p, err := svc.Policy(ctx, tenant, req.Name)
	if err != nil {
		return nil, err
	}
	return tpmPolicyToTransport(tenant, p), nil
}

// TPMObjectPolicy returns the policy the target tenant's TPM key or sealed
// object was created under. The object is resolved in the caller's tenant
// only, so another tenant's object is not found.
func (s *XKMSService) TPMObjectPolicy(ctx context.Context, req *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	kind, ok := objectKinds[req.Kind]
	if !ok {
		return nil, &InvalidTPMObjectKindError{Kind: req.Kind}
	}
	parsed, err := ParseKeyIDToAttributes(req.KeyID)
	if err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}
	svc, tenant, err := s.tpmPolicyService(ctx, "tpm object policy", req.TenantID)
	if err != nil {
		return nil, err
	}
	a, err := svc.PolicyOf(ctx, tenant, kind, parsed.CN)
	if err != nil {
		return nil, err
	}
	return &transport.TPMObjectPolicyResponse{
		ObjectID:   a.ObjectID,
		Kind:       string(a.Kind),
		Policy:     a.Policy,
		AuthPolicy: hex.EncodeToString(a.AuthPolicy),
		CreatedAt:  formatTPMTime(a.CreatedAt),
	}, nil
}

// TPMPolicyRotateAuthority replaces the target tenant's policy authority:
// every policy index is rewritten to name the new authority and every
// current approval is re-signed by it. No object is re-keyed.
func (s *XKMSService) TPMPolicyRotateAuthority(ctx context.Context, req *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	svc, tenant, err := s.tpmPolicyService(ctx, "tpm authority rotate", req.TenantID)
	if err != nil {
		return nil, err
	}
	scope, err := svc.RotateAuthority(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return &transport.TPMAuthorityRotateResponse{
		TenantID:      tenant,
		Generation:    scope.Authority.Generation,
		AuthorityName: hex.EncodeToString(scope.Authority.Name),
		Epoch:         scope.Epoch,
	}, nil
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

// tpmPolicyToTransport converts a stored policy of tenant to its API form.
func tpmPolicyToTransport(tenant string, p *tpmpolicy.Policy) *transport.TPMPolicy {
	values := make(map[uint]string, len(p.PCRValues))
	for pcr, value := range p.PCRValues {
		values[pcr] = hex.EncodeToString(value)
	}
	out := &transport.TPMPolicy{
		Name:       p.Name,
		TenantID:   tenant,
		Bank:       p.Bank,
		PCRs:       p.PCRs,
		PCRValues:  values,
		PCRDigest:  hex.EncodeToString(p.PCRDigest),
		Index:      p.Index,
		AutoUnseal: p.AutoUnseal,
		CreatedAt:  formatTPMTime(p.CreatedAt),
		UpdatedAt:  formatTPMTime(p.UpdatedAt),
	}
	if p.Approval != nil {
		out.Approved = true
		out.Epoch = p.Approval.Epoch
		out.AuthorityGeneration = p.Approval.AuthorityGeneration
	}
	return out
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

// formatTPMTime formats a registry timestamp as RFC 3339 in UTC; the zero
// time is empty.
func formatTPMTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
