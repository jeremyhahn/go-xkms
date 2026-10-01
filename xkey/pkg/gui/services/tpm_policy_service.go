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

package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/localtpm"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// TPM policy service errors.
var (
	// ErrTPMPolicyUnavailable indicates there is neither a local TPM policy
	// service (no TPM, or the data directory is not open yet) nor a
	// connected server.
	ErrTPMPolicyUnavailable = errors.New("tpm_policy: no TPM policy service available (no local TPM and no connected server)")

	// ErrTPMPolicyNameRequired indicates an empty policy name.
	ErrTPMPolicyNameRequired = errors.New("tpm_policy: policy name is required")

	// ErrTPMPolicyBuiltin indicates an operation the built-in platform policy
	// does not support: it cannot be created, updated, revoked, verified,
	// deleted or marked for auto-unseal.
	ErrTPMPolicyBuiltin = errors.New("tpm_policy: the built-in platform policy cannot be changed")

	// ErrTPMPolicyKeyIDRequired indicates an empty key ID.
	ErrTPMPolicyKeyIDRequired = errors.New("tpm_policy: key ID is required")

	// ErrTPMPolicyKeyIDInvalid indicates a key ID that cannot be parsed.
	ErrTPMPolicyKeyIDInvalid = errors.New("tpm_policy: invalid key ID")
)

// TPM policy service modes: where the operations run.
const (
	// TPMPolicyModeLocal runs them in-process over xKey's own TPM.
	TPMPolicyModeLocal = "local"

	// TPMPolicyModeServer runs them on the connected xkmsd.
	TPMPolicyModeServer = "server"

	// TPMPolicyModeUnavailable means neither is available.
	TPMPolicyModeUnavailable = "unavailable"
)

// tpmPolicyBackend is where the TPM policy operations run: the in-process
// service over xKey's own TPM (LocalTPMPolicies) or a connected xkmsd (any
// transport.Client). Both speak the SDK's TPM policy API types.
type tpmPolicyBackend interface {
	TPMPolicyCreate(ctx context.Context, req *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error)
	TPMPolicyGet(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error)
	TPMPolicyList(ctx context.Context, req *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error)
	TPMPolicyUpdate(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error)
	TPMPolicyRevoke(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error)
	TPMPolicyVerify(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error)
	TPMPolicyDelete(ctx context.Context, req *transport.TPMPolicyDeleteRequest) error
	TPMPolicyObjects(ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error)
	TPMPolicySetAutoUnseal(ctx context.Context, req *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error)
	TPMPolicySetDescription(ctx context.Context, req *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error)
	TPMObjectPolicy(ctx context.Context, req *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error)
	TPMPolicyRotateAuthority(ctx context.Context, req *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error)
}

// Compile-time check that a connected server serves every operation.
var _ tpmPolicyBackend = (transport.TPMPolicyService)(nil)

// TPMPolicyInfo describes a TPM policy for the GUI and CLI.
type TPMPolicyInfo struct {
	// Name is the policy's name; "platform" for the built-in policy.
	Name string `json:"name"`

	// Builtin marks the built-in platform policy (the platform PCR or the
	// object's password), which always exists and cannot be changed.
	Builtin bool `json:"builtin"`

	// Description is the policy's free-text description.
	Description string `json:"description,omitempty"`

	// Branches are the policy's branches, tried in order: each an AND of
	// pcr, auth_value and locality conditions, with the values its pcr
	// conditions captured from the TPM. The built-in policy has none.
	Branches []transport.TPMPolicyBranch `json:"branches,omitempty"`

	// Index is the policy's NV index.
	Index uint32 `json:"index,omitempty"`

	// Approved reports whether the policy's approval is in force (false
	// after a revoke until the next update); Epoch and AuthorityGeneration
	// identify the approval.
	Approved            bool   `json:"approved"`
	Epoch               uint64 `json:"epoch,omitempty"`
	AuthorityGeneration uint64 `json:"authority_generation,omitempty"`

	// AutoUnseal marks the policy barrier auto-unseal uses.
	AutoUnseal bool `json:"auto_unseal"`

	// ObjectCount is the number of keys and sealed objects assigned to the
	// policy.
	ObjectCount int `json:"object_count"`

	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// TPMPolicyVerification compares a policy's captured PCR values with the
// live ones, branch by branch. It is advisory: the TPM itself enforces the
// policy on use.
type TPMPolicyVerification struct {
	Name     string                                  `json:"name"`
	Match    bool                                    `json:"match"`
	Approved bool                                    `json:"approved"`
	Branches []transport.TPMPolicyBranchVerification `json:"branches"`
}

// TPMObjectPolicyInfo reports the policy a TPM object was created under.
type TPMObjectPolicyInfo struct {
	ObjectID   string `json:"object_id"`
	Kind       string `json:"kind"`
	Policy     string `json:"policy"`
	AuthPolicy string `json:"auth_policy,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
}

// TPMAuthorityInfo describes the policy authority a rotation installed.
type TPMAuthorityInfo struct {
	Generation    uint64 `json:"generation"`
	AuthorityName string `json:"authority_name"`
	Epoch         uint64 `json:"epoch"`
}

// TPMPolicyStatus reports where TPM policy operations run.
type TPMPolicyStatus struct {
	// Available reports whether any operation can run.
	Available bool `json:"available"`

	// Mode is TPMPolicyModeLocal, TPMPolicyModeServer or
	// TPMPolicyModeUnavailable.
	Mode string `json:"mode"`

	// Scope is the TPM scope the operations act on: "system" locally, the
	// connection's tenant (as the server resolves it) in server mode.
	Scope string `json:"scope"`
}

// TPMPolicyService manages named TPM policies for the GUI and the CLI: an
// OR of branches of pcr (values captured live from the TPM), auth_value and
// locality conditions, approved by the scope's TPM-resident authority, that
// keys and sealed objects reference by name. The operations run on a connected xkmsd when there is one, and
// otherwise in-process over xKey's own TPM.
type TPMPolicyService struct {
	ctx    context.Context
	log    *slog.Logger
	local  atomic.Pointer[localtpm.Policies]
	client atomic.Pointer[transport.TPMPolicyService]
}

// NewTPMPolicyService returns a TPMPolicyService with neither backend set.
func NewTPMPolicyService() *TPMPolicyService {
	return &TPMPolicyService{
		log: slog.Default().With("component", "tpm_policy_service"),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *TPMPolicyService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetLocal sets the in-process service over xKey's own TPM; nil clears it.
// Compile-time check that the local service serves the same operations as a
// connected xkmsd.
var _ tpmPolicyBackend = (*localtpm.Policies)(nil)

func (s *TPMPolicyService) SetLocal(l *localtpm.Policies) {
	s.local.Store(l)
}

// Local returns the in-process service, or nil.
func (s *TPMPolicyService) Local() *localtpm.Policies {
	return s.local.Load()
}

// SetClient sets the connected xkmsd the operations run on -- any
// transport.Client serves the TPM policy API; nil clears it, returning the
// service to local mode.
func (s *TPMPolicyService) SetClient(c transport.TPMPolicyService) {
	if c == nil {
		s.client.Store(nil)
		return
	}
	s.client.Store(&c)
}

// context returns the service context, or context.Background before
// startup.
func (s *TPMPolicyService) context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// backend returns where operations run now and its mode: the connected
// server first, then the local TPM.
func (s *TPMPolicyService) backend() (tpmPolicyBackend, string, error) {
	if c := s.client.Load(); c != nil {
		return *c, TPMPolicyModeServer, nil
	}
	if l := s.local.Load(); l != nil {
		return l, TPMPolicyModeLocal, nil
	}
	return nil, TPMPolicyModeUnavailable, ErrTPMPolicyUnavailable
}

// recoverPanic converts a panic in a Wails-bound method into an error.
func (s *TPMPolicyService) recoverPanic(method string, retErr *error) {
	if r := recover(); r != nil {
		s.log.Error("panic in "+method, "recover", r)
		*retErr = &MessageError{Msg: fmt.Sprintf("tpm_policy_service: panic in %s: %v", method, r)}
	}
}

// GetStatus reports where TPM policy operations run.
func (s *TPMPolicyService) GetStatus() *TPMPolicyStatus {
	_, mode, err := s.backend()
	status := &TPMPolicyStatus{Available: err == nil, Mode: mode}
	if mode == TPMPolicyModeLocal {
		status.Scope = "system"
	}
	return status
}

// requireName validates a policy name that must name a policy the caller
// may change.
func requireName(name string) error {
	switch strings.TrimSpace(name) {
	case "":
		return ErrTPMPolicyNameRequired
	case xkms.TPMPolicyPlatform:
		return ErrTPMPolicyBuiltin
	}
	return nil
}

// CreatePolicy creates a named policy of branches, capturing the values of
// its pcr conditions from the TPM, and returns it. description is free
// text; autoUnseal marks it as the policy barrier auto-unseal uses;
// ownerAuth authorizes defining its NV index when the TPM's owner hierarchy
// has a password. transport.TPMPolicyPCRBranch builds the common one-branch
// policy over a PCR selection.
func (s *TPMPolicyService) CreatePolicy(name, description string, branches []transport.TPMPolicyBranch, autoUnseal bool, ownerAuth string) (retVal *TPMPolicyInfo, retErr error) {
	defer s.recoverPanic("CreatePolicy", &retErr)
	if err := requireName(name); err != nil {
		return nil, err
	}
	b, _, err := s.backend()
	if err != nil {
		return nil, err
	}
	p, err := b.TPMPolicyCreate(s.context(), &transport.TPMPolicyCreateRequest{
		Name:        strings.TrimSpace(name),
		Description: description,
		Branches:    branches,
		AutoUnseal:  autoUnseal,
		OwnerAuth:   ownerAuthBytes(ownerAuth),
	})
	if err != nil {
		return nil, err
	}
	return policyInfo(p, 0), nil
}

// SetDescription replaces the policy's description; an empty one clears
// it.
func (s *TPMPolicyService) SetDescription(name, description string) (retVal *TPMPolicyInfo, retErr error) {
	defer s.recoverPanic("SetDescription", &retErr)
	return s.changePolicy(name, func(b tpmPolicyBackend, ctx context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
		return b.TPMPolicySetDescription(ctx, &transport.TPMPolicyDescriptionRequest{Name: req.Name, Description: description})
	})
}

// ListPolicies returns the built-in platform policy followed by the named
// policies, each with the number of objects assigned to it.
func (s *TPMPolicyService) ListPolicies() (retVal []TPMPolicyInfo, retErr error) {
	defer s.recoverPanic("ListPolicies", &retErr)
	b, _, err := s.backend()
	if err != nil {
		return nil, err
	}
	ctx := s.context()
	resp, err := b.TPMPolicyList(ctx, &transport.TPMPolicyListRequest{})
	if err != nil {
		return nil, err
	}
	platformCount, err := objectCount(ctx, b, xkms.TPMPolicyPlatform)
	if err != nil {
		return nil, err
	}
	out := make([]TPMPolicyInfo, 0, len(resp.Policies)+1)
	out = append(out, TPMPolicyInfo{Name: xkms.TPMPolicyPlatform, Builtin: true, Approved: true, ObjectCount: platformCount})
	for i := range resp.Policies {
		count, err := objectCount(ctx, b, resp.Policies[i].Name)
		if err != nil {
			return nil, err
		}
		out = append(out, *policyInfo(&resp.Policies[i], count))
	}
	return out, nil
}

// GetPolicy returns the named policy with its object count.
func (s *TPMPolicyService) GetPolicy(name string) (retVal *TPMPolicyInfo, retErr error) {
	defer s.recoverPanic("GetPolicy", &retErr)
	if err := requireName(name); err != nil {
		return nil, err
	}
	b, _, err := s.backend()
	if err != nil {
		return nil, err
	}
	ctx := s.context()
	p, err := b.TPMPolicyGet(ctx, &transport.TPMPolicyRequest{Name: name})
	if err != nil {
		return nil, err
	}
	count, err := objectCount(ctx, b, name)
	if err != nil {
		return nil, err
	}
	return policyInfo(p, count), nil
}

// UpdatePolicy re-captures the policy's PCR values from the TPM and
// re-approves it. No object is re-keyed; a revoked policy is approved again.
func (s *TPMPolicyService) UpdatePolicy(name string) (retVal *TPMPolicyInfo, retErr error) {
	defer s.recoverPanic("UpdatePolicy", &retErr)
	return s.changePolicy(name, tpmPolicyBackend.TPMPolicyUpdate)
}

// RevokePolicy withdraws the policy's approval: its objects answer only to
// their password until the policy is updated.
func (s *TPMPolicyService) RevokePolicy(name string) (retVal *TPMPolicyInfo, retErr error) {
	defer s.recoverPanic("RevokePolicy", &retErr)
	return s.changePolicy(name, tpmPolicyBackend.TPMPolicyRevoke)
}

// changePolicy runs op, an operation that returns the changed policy, on
// the named policy.
func (s *TPMPolicyService) changePolicy(name string,
	op func(tpmPolicyBackend, context.Context, *transport.TPMPolicyRequest) (*transport.TPMPolicy, error)) (*TPMPolicyInfo, error) {

	if err := requireName(name); err != nil {
		return nil, err
	}
	b, _, err := s.backend()
	if err != nil {
		return nil, err
	}
	ctx := s.context()
	p, err := op(b, ctx, &transport.TPMPolicyRequest{Name: name})
	if err != nil {
		return nil, err
	}
	count, err := objectCount(ctx, b, name)
	if err != nil {
		return nil, err
	}
	return policyInfo(p, count), nil
}

// VerifyPolicy compares the policy's captured PCR values with the live ones
// and reports, branch by branch, whether each matches and holds a current
// approval.
func (s *TPMPolicyService) VerifyPolicy(name string) (retVal *TPMPolicyVerification, retErr error) {
	defer s.recoverPanic("VerifyPolicy", &retErr)
	if err := requireName(name); err != nil {
		return nil, err
	}
	b, _, err := s.backend()
	if err != nil {
		return nil, err
	}
	v, err := b.TPMPolicyVerify(s.context(), &transport.TPMPolicyRequest{Name: name})
	if err != nil {
		return nil, err
	}
	branches := v.Branches
	if branches == nil {
		branches = []transport.TPMPolicyBranchVerification{}
	}
	return &TPMPolicyVerification{Name: v.Name, Match: v.Match, Approved: v.Approved, Branches: branches}, nil
}

// DeletePolicy deletes the policy and its NV index. It is refused, listing
// them, while keys or sealed objects are assigned to the policy. ownerAuth
// authorizes the TPM's owner hierarchy when it has a password.
func (s *TPMPolicyService) DeletePolicy(name, ownerAuth string) (retErr error) {
	defer s.recoverPanic("DeletePolicy", &retErr)
	if err := requireName(name); err != nil {
		return err
	}
	b, _, err := s.backend()
	if err != nil {
		return err
	}
	return b.TPMPolicyDelete(s.context(), &transport.TPMPolicyDeleteRequest{Name: name, OwnerAuth: ownerAuthBytes(ownerAuth)})
}

// PolicyObjects lists the "<kind>/<name>" IDs of the keys and sealed
// objects assigned to the policy ("platform" for the built-in one).
func (s *TPMPolicyService) PolicyObjects(name string) (retVal []string, retErr error) {
	defer s.recoverPanic("PolicyObjects", &retErr)
	if strings.TrimSpace(name) == "" {
		return nil, ErrTPMPolicyNameRequired
	}
	b, _, err := s.backend()
	if err != nil {
		return nil, err
	}
	resp, err := b.TPMPolicyObjects(s.context(), &transport.TPMPolicyRequest{Name: name})
	if err != nil {
		return nil, err
	}
	if resp.Objects == nil {
		return []string{}, nil
	}
	return resp.Objects, nil
}

// KeyPolicy returns the policy the TPM key keyID (a key ID or bare key name)
// was created under.
func (s *TPMPolicyService) KeyPolicy(keyID string) (retVal *TPMObjectPolicyInfo, retErr error) {
	defer s.recoverPanic("KeyPolicy", &retErr)
	if strings.TrimSpace(keyID) == "" {
		return nil, ErrTPMPolicyKeyIDRequired
	}
	b, _, err := s.backend()
	if err != nil {
		return nil, err
	}
	a, err := b.TPMObjectPolicy(s.context(), &transport.TPMObjectPolicyRequest{KeyID: keyID, Kind: xkms.TPMObjectKindKey})
	if err != nil {
		return nil, err
	}
	return &TPMObjectPolicyInfo{
		ObjectID:   a.ObjectID,
		Kind:       a.Kind,
		Policy:     a.Policy,
		AuthPolicy: a.AuthPolicy,
		CreatedAt:  a.CreatedAt,
	}, nil
}

// SetAutoUnseal sets or clears the policy's auto-unseal mark. Setting it
// clears it from every other policy of the scope.
//
// The mark only designates the policy. xKey's own barrier auto-unseals
// through BarrierAutoUnsealService, which also seals the barrier credential
// under the policy; use it to enable auto-unseal of xKey's barrier.
func (s *TPMPolicyService) SetAutoUnseal(name string, on bool) (retVal *TPMPolicyInfo, retErr error) {
	defer s.recoverPanic("SetAutoUnseal", &retErr)
	if err := requireName(name); err != nil {
		return nil, err
	}
	b, _, err := s.backend()
	if err != nil {
		return nil, err
	}
	ctx := s.context()
	p, err := b.TPMPolicySetAutoUnseal(ctx, &transport.TPMPolicyAutoUnsealRequest{Name: name, Enabled: on})
	if err != nil {
		return nil, err
	}
	count, err := objectCount(ctx, b, name)
	if err != nil {
		return nil, err
	}
	return policyInfo(p, count), nil
}

// RotateAuthority replaces the scope's policy authority: every policy is
// re-approved by the new one and the old one stops authorizing anything. No
// object is re-keyed.
func (s *TPMPolicyService) RotateAuthority() (retVal *TPMAuthorityInfo, retErr error) {
	defer s.recoverPanic("RotateAuthority", &retErr)
	b, _, err := s.backend()
	if err != nil {
		return nil, err
	}
	resp, err := b.TPMPolicyRotateAuthority(s.context(), &transport.TPMAuthorityRotateRequest{})
	if err != nil {
		return nil, err
	}
	return &TPMAuthorityInfo{Generation: resp.Generation, AuthorityName: resp.AuthorityName, Epoch: resp.Epoch}, nil
}

// assignLocal records that the object of kind ("key" or "sealed") named
// name, created on xKey's own TPM, is bound to policy ("" is the platform
// policy). Callers use it only for objects they created through xKey's
// embedded backends; a connected server records its own objects. Without a
// local service (no TPM) no local TPM object can exist, so there is nothing
// to record.
func (s *TPMPolicyService) assignLocal(ctx context.Context, kind, name, policy string) error {
	l := s.local.Load()
	if l == nil {
		return nil
	}
	return l.Assign(ctx, kind, name, policy)
}

// unassignLocal removes the assignment of the local object of kind named
// name.
func (s *TPMPolicyService) unassignLocal(ctx context.Context, kind, name string) error {
	l := s.local.Load()
	if l == nil {
		return nil
	}
	return l.Unassign(ctx, kind, name)
}

// deleteLocalObject removes the local sealed object name and its
// assignment.
func (s *TPMPolicyService) deleteLocalObject(ctx context.Context, name string) error {
	l := s.local.Load()
	if l == nil {
		return nil
	}
	return l.DeleteObject(ctx, name)
}

// objectCount returns the number of objects assigned to the named policy.
func objectCount(ctx context.Context, b tpmPolicyBackend, name string) (int, error) {
	resp, err := b.TPMPolicyObjects(ctx, &transport.TPMPolicyRequest{Name: name})
	if err != nil {
		return 0, err
	}
	return len(resp.Objects), nil
}

// ownerAuthBytes returns the owner-hierarchy password, or nil for none.
func ownerAuthBytes(ownerAuth string) []byte {
	if ownerAuth == "" {
		return nil
	}
	return []byte(ownerAuth)
}

// policyInfo converts an API policy to its GUI form.
func policyInfo(p *transport.TPMPolicy, objects int) *TPMPolicyInfo {
	return &TPMPolicyInfo{
		Name:                p.Name,
		Description:         p.Description,
		Branches:            p.Branches,
		Index:               p.Index,
		Approved:            p.Approved,
		Epoch:               p.Epoch,
		AuthorityGeneration: p.AuthorityGeneration,
		AutoUnseal:          p.AutoUnseal,
		ObjectCount:         objects,
		CreatedAt:           p.CreatedAt,
		UpdatedAt:           p.UpdatedAt,
	}
}

// objectName returns the object name a key ID or bare name refers to.
func objectName(keyID string) (string, error) {
	if keyID == "" {
		return "", ErrTPMPolicyKeyIDRequired
	}
	attrs, err := xkms.ServiceParseKeyIDToAttributes(keyID)
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrTPMPolicyKeyIDInvalid, Cause: err}
	}
	return attrs.CN, nil
}
