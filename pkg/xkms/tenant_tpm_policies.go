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
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
)

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

// ParseTPMObjectKind returns the policy service's object kind for an API
// object kind: "key" (or "") or "sealed". Any other kind is refused with
// *InvalidTPMObjectKindError.
func ParseTPMObjectKind(kind string) (tpmpolicy.ObjectKind, error) {
	objectKind, ok := objectKinds[kind]
	if !ok {
		return "", &InvalidTPMObjectKindError{Kind: kind}
	}
	return objectKind, nil
}

// TenantTPMPolicies serves the tenant-level TPM policy operations of
// transport.TPMPolicyService for one fixed tenant over a *tpmpolicy.Service,
// converting to and from the API types. It is the single conversion between
// the policy service and the API: XKMSService binds the caller's tenant and
// delegates to it, and a process that owns its TPM (xKey's local mode) uses
// it directly for the system scope.
//
// The tenant is fixed at construction, so every request's TenantID is
// ignored: authorizing the tenant is the caller's job.
type TenantTPMPolicies struct {
	svc    *tpmpolicy.Service
	tenant string
}

// NewTenantTPMPolicies returns the TPM policy operations of tenant ("" is
// the system scope) over svc. A nil svc is refused with ErrNotConfigured.
func NewTenantTPMPolicies(svc *tpmpolicy.Service, tenant string) (*TenantTPMPolicies, error) {
	if svc == nil {
		return nil, ErrNotConfigured
	}
	return &TenantTPMPolicies{svc: svc, tenant: tenant}, nil
}

// TPMPolicyCreate creates a named TPM policy of the request's branches,
// capturing the values of its pcr conditions from the tenant's TPM.
func (t *TenantTPMPolicies) TPMPolicyCreate(ctx context.Context, req *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	branches, err := tpmBranchesFromTransport(req.Branches)
	if err != nil {
		return nil, err
	}
	p, err := t.svc.CreatePolicy(ctx, t.tenant, tpmpolicy.CreatePolicyRequest{
		Name:        req.Name,
		Description: req.Description,
		Branches:    branches,
		AutoUnseal:  req.AutoUnseal,
		OwnerAuth:   req.OwnerAuth,
	})
	if err != nil {
		return nil, err
	}
	return tpmPolicyToTransport(t.tenant, p), nil
}

// TPMPolicyGet returns a named TPM policy of the tenant.
func (t *TenantTPMPolicies) TPMPolicyGet(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return t.policyOp(ctx, req, (*tpmpolicy.Service).Policy)
}

// TPMPolicyUpdate re-captures a policy's PCR values and re-approves it at the
// scope's next epoch. No object is re-keyed.
func (t *TenantTPMPolicies) TPMPolicyUpdate(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return t.policyOp(ctx, req, (*tpmpolicy.Service).UpdatePolicy)
}

// TPMPolicyRevoke withdraws a policy's approval; its objects answer only to
// their password branch until it is updated.
func (t *TenantTPMPolicies) TPMPolicyRevoke(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	return t.policyOp(ctx, req, (*tpmpolicy.Service).RevokePolicy)
}

// policyOp runs op, a policy service operation that returns one policy, on
// the policy req names.
func (t *TenantTPMPolicies) policyOp(ctx context.Context, req *transport.TPMPolicyRequest,
	op func(*tpmpolicy.Service, context.Context, string, string) (*tpmpolicy.Policy, error)) (*transport.TPMPolicy, error) {

	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := op(t.svc, ctx, t.tenant, req.Name)
	if err != nil {
		return nil, err
	}
	return tpmPolicyToTransport(t.tenant, p), nil
}

// TPMPolicyList returns the tenant's named TPM policies, sorted by name.
func (t *TenantTPMPolicies) TPMPolicyList(ctx context.Context, req *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	policies, err := t.svc.ListPolicies(ctx, t.tenant)
	if err != nil {
		return nil, err
	}
	resp := &transport.TPMPolicyListResponse{Policies: make([]transport.TPMPolicy, 0, len(policies))}
	for _, p := range policies {
		resp.Policies = append(resp.Policies, *tpmPolicyToTransport(t.tenant, p))
	}
	return resp, nil
}

// TPMPolicyVerify compares a policy's captured PCR values with the live ones
// and reports, branch by branch, whether each matches and holds a current
// approval.
func (t *TenantTPMPolicies) TPMPolicyVerify(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	v, err := t.svc.VerifyPolicy(ctx, t.tenant, req.Name)
	if err != nil {
		return nil, err
	}
	resp := &transport.TPMPolicyVerifyResponse{
		Name:     v.Policy,
		Match:    v.Match,
		Approved: v.Approved,
		Branches: make([]transport.TPMPolicyBranchVerification, len(v.Branches)),
	}
	for i, b := range v.Branches {
		resp.Branches[i] = transport.TPMPolicyBranchVerification{Match: b.Match, Mismatched: b.Mismatched, Approved: b.Approved}
	}
	return resp, nil
}

// TPMPolicyDelete deletes a policy and its NV index. It is refused with
// *tpmpolicy.PolicyInUseError, listing them, while objects use the policy.
func (t *TenantTPMPolicies) TPMPolicyDelete(ctx context.Context, req *transport.TPMPolicyDeleteRequest) error {
	if req == nil {
		return ErrNilRequest
	}
	return t.svc.DeletePolicy(ctx, t.tenant, req.Name, req.OwnerAuth)
}

// TPMPolicyObjects lists the objects assigned to a policy of the tenant; an
// unused policy lists none.
func (t *TenantTPMPolicies) TPMPolicyObjects(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	objects, err := t.svc.ObjectsOf(ctx, t.tenant, req.Name)
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
func (t *TenantTPMPolicies) TPMPolicySetAutoUnseal(ctx context.Context, req *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	if err := t.svc.SetAutoUnseal(ctx, t.tenant, req.Name, req.Enabled); err != nil {
		return nil, err
	}
	p, err := t.svc.Policy(ctx, t.tenant, req.Name)
	if err != nil {
		return nil, err
	}
	return tpmPolicyToTransport(t.tenant, p), nil
}

// TPMPolicySetDescription replaces a policy's description and returns the
// policy as stored.
func (t *TenantTPMPolicies) TPMPolicySetDescription(ctx context.Context, req *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	p, err := t.svc.SetDescription(ctx, t.tenant, req.Name, req.Description)
	if err != nil {
		return nil, err
	}
	return tpmPolicyToTransport(t.tenant, p), nil
}

// TPMObjectPolicy returns the policy the tenant's TPM key or sealed object
// was created under. KeyID is a key ID or a bare object name; it is resolved
// in the tenant only, so another tenant's object is not found.
func (t *TenantTPMPolicies) TPMObjectPolicy(ctx context.Context, req *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	kind, err := ParseTPMObjectKind(req.Kind)
	if err != nil {
		return nil, err
	}
	parsed, err := ParseKeyIDToAttributes(req.KeyID)
	if err != nil {
		return nil, &ErrKeyIDParse{Err: err}
	}
	a, err := t.svc.PolicyOf(ctx, t.tenant, kind, parsed.CN)
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

// TPMPolicyRotateAuthority replaces the tenant's policy authority: every
// policy index is rewritten to name the new authority and every current
// approval is re-signed by it. No object is re-keyed.
func (t *TenantTPMPolicies) TPMPolicyRotateAuthority(ctx context.Context, req *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}
	scope, err := t.svc.RotateAuthority(ctx, t.tenant)
	if err != nil {
		return nil, err
	}
	return &transport.TPMAuthorityRotateResponse{
		TenantID:      t.tenant,
		Generation:    scope.Authority.Generation,
		AuthorityName: hex.EncodeToString(scope.Authority.Name),
		Epoch:         scope.Epoch,
	}, nil
}

// tpmPolicyToTransport converts a stored policy of tenant to its API form.
// Approvals are signed for every branch at once, so the first approval's
// epoch and authority generation are the policy's.
func tpmPolicyToTransport(tenant string, p *tpmpolicy.Policy) *transport.TPMPolicy {
	out := &transport.TPMPolicy{
		Name:        p.Name,
		TenantID:    tenant,
		Description: p.Description,
		Branches:    make([]transport.TPMPolicyBranch, len(p.Branches)),
		Index:       p.Index,
		Approved:    len(p.Branches) > 0,
		AutoUnseal:  p.AutoUnseal,
		CreatedAt:   formatTPMTime(p.CreatedAt),
		UpdatedAt:   formatTPMTime(p.UpdatedAt),
	}
	for i, b := range p.Branches {
		approved := i < len(p.Approvals) && p.Approvals[i] != nil
		out.Branches[i] = tpmBranchToTransport(b, approved)
		out.Approved = out.Approved && approved
	}
	if out.Approved {
		out.Epoch = p.Approvals[0].Epoch
		out.AuthorityGeneration = p.Approvals[0].AuthorityGeneration
	}
	return out
}

// tpmBranchToTransport converts a stored branch to its API form.
func tpmBranchToTransport(b tpmpolicy.Branch, approved bool) transport.TPMPolicyBranch {
	out := transport.TPMPolicyBranch{Conditions: make([]transport.TPMPolicyCondition, len(b.Conditions)), Approved: approved}
	for i, c := range b.Conditions {
		out.Conditions[i] = transport.TPMPolicyCondition{
			Type:       string(c.Type),
			Bank:       c.Bank,
			PCRs:       c.PCRs,
			PCRDigest:  hex.EncodeToString(c.PCRDigest),
			Localities: c.Localities,
		}
		if len(c.PCRValues) > 0 {
			values := make(map[uint]string, len(c.PCRValues))
			for pcr, value := range c.PCRValues {
				values[pcr] = hex.EncodeToString(value)
			}
			out.Conditions[i].PCRValues = values
		}
	}
	return out
}

// tpmBranchesFromTransport converts requested branches to the policy
// service's form. PCR values are captured from the TPM, never supplied: a
// condition carrying any is refused with tpmpolicy.ErrPCRValuesSupplied.
// The service validates everything else.
func tpmBranchesFromTransport(branches []transport.TPMPolicyBranch) ([]tpmpolicy.Branch, error) {
	out := make([]tpmpolicy.Branch, len(branches))
	for i, b := range branches {
		conditions := make([]tpmpolicy.Condition, len(b.Conditions))
		for j, c := range b.Conditions {
			if len(c.PCRValues) > 0 || c.PCRDigest != "" {
				return nil, tpmpolicy.ErrPCRValuesSupplied
			}
			conditions[j] = tpmpolicy.Condition{
				Type:       tpmpolicy.ConditionType(c.Type),
				Bank:       c.Bank,
				PCRs:       c.PCRs,
				Localities: c.Localities,
			}
		}
		out[i] = tpmpolicy.Branch{Conditions: conditions}
	}
	return out, nil
}

// formatTPMTime formats a registry timestamp as RFC 3339 in UTC; the zero
// time is empty.
func formatTPMTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
