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

// Package tpmpolicyfake is an in-memory stand-in for a connected xkmsd's TPM
// policy API (transport.TPMPolicyService), for xKey's tests. It keeps the
// server's observable rules -- names are unique, the built-in platform policy
// cannot change, values are captured from the "live" PCRs, a policy with
// assigned objects cannot be deleted, at most one policy carries the
// auto-unseal mark -- without a TPM. Test doubles that must satisfy
// transport.Client embed Fake to serve these methods.
package tpmpolicyfake

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// Fake request errors.
var (
	// ErrNameRequired is returned for a request without a policy name.
	ErrNameRequired = errors.New("tpmpolicyfake: policy name is required")

	// ErrNoBranches is returned for a policy without a branch.
	ErrNoBranches = errors.New("tpmpolicyfake: a policy must have at least one branch")

	// ErrNoPCRs is returned for a pcr condition that selects no PCR.
	ErrNoPCRs = errors.New("tpmpolicyfake: a pcr condition must select at least one PCR")

	// ErrKeyIDRequired is returned for an object request without a key ID.
	ErrKeyIDRequired = errors.New("tpmpolicyfake: key ID is required")
)

// Compile-time check that Fake serves the whole TPM policy API.
var _ transport.TPMPolicyService = (*Fake)(nil)

// Fake is an in-memory TPM policy API. The zero value is ready to use and
// has no policies; every live PCR reads as zero until SetPCR changes it.
type Fake struct {
	mu         sync.Mutex
	policies   map[string]map[string]*transport.TPMPolicy // scope -> name -> policy
	objects    map[string]map[string]string               // scope -> object ID -> policy
	pcrs       map[uint]string                            // live PCR values, hex
	modes      map[string]string                          // tenant -> TPM mode
	epoch      uint64
	generation uint64
}

// scope returns the scope name of tenant: "system" for "".
func scope(tenant string) string {
	return xkms.TPMPolicyScopeName(tenant)
}

// init creates the maps on first use. The caller holds f.mu.
func (f *Fake) init() {
	if f.policies == nil {
		f.policies = make(map[string]map[string]*transport.TPMPolicy)
		f.objects = make(map[string]map[string]string)
		f.pcrs = make(map[uint]string)
		f.modes = make(map[string]string)
		f.generation = 1
	}
}

// SetPCR sets the live value of pcr, which the next create or update
// captures and verify compares against.
func (f *Fake) SetPCR(pcr uint, value []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	f.pcrs[pcr] = hex.EncodeToString(value)
}

// Assign records that the object of kind ("key" or "sealed") named name in
// tenant's scope was created under policy ("" is the platform policy), as
// the server does when it creates the object.
func (f *Fake) Assign(tenant, kind, name, policy string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	if policy == "" {
		policy = xkms.TPMPolicyPlatform
	}
	sc := scope(tenant)
	if f.objects[sc] == nil {
		f.objects[sc] = make(map[string]string)
	}
	f.objects[sc][kind+"/"+name] = policy
}

// policy returns tenant's named policy. The caller holds f.mu.
func (f *Fake) policy(tenant, name string) (*transport.TPMPolicy, error) {
	switch name {
	case "":
		return nil, ErrNameRequired
	case xkms.TPMPolicyPlatform:
		return nil, xkms.ErrTPMPolicyReserved
	}
	p, ok := f.policies[scope(tenant)][name]
	if !ok {
		return nil, xkms.ErrTPMPolicyNotFound
	}
	return p, nil
}

// capture sets the values of p's pcr conditions to the live PCRs. The
// caller holds f.mu.
func (f *Fake) capture(p *transport.TPMPolicy) {
	for i := range p.Branches {
		for j := range p.Branches[i].Conditions {
			c := &p.Branches[i].Conditions[j]
			if c.Type != transport.TPMPolicyConditionPCR {
				continue
			}
			c.PCRValues = make(map[uint]string, len(c.PCRs))
			for _, pcr := range c.PCRs {
				c.PCRValues[pcr] = f.pcrs[pcr]
			}
		}
	}
}

// approve sets the approval of p and of every branch of it.
func approve(p *transport.TPMPolicy, approved bool) {
	p.Approved = approved
	for i := range p.Branches {
		p.Branches[i].Approved = approved
	}
}

// bump moves the scope's counter to its next epoch and re-approves every
// approved policy at it. The caller holds f.mu.
func (f *Fake) bump(tenant string) {
	f.epoch++
	for _, p := range f.policies[scope(tenant)] {
		if p.Approved {
			p.Epoch = f.epoch
		}
	}
}

// copyOf returns a copy of p, so callers cannot change the fake's state.
func copyOf(p *transport.TPMPolicy) *transport.TPMPolicy {
	out := *p
	out.Branches = copyBranches(p.Branches)
	return &out
}

// copyBranches returns a deep copy of branches.
func copyBranches(branches []transport.TPMPolicyBranch) []transport.TPMPolicyBranch {
	out := make([]transport.TPMPolicyBranch, len(branches))
	for i, b := range branches {
		out[i] = transport.TPMPolicyBranch{Conditions: make([]transport.TPMPolicyCondition, len(b.Conditions)), Approved: b.Approved}
		for j, c := range b.Conditions {
			c.PCRs = append([]uint(nil), c.PCRs...)
			c.Localities = append([]uint(nil), c.Localities...)
			if c.PCRValues != nil {
				values := make(map[uint]string, len(c.PCRValues))
				for k, v := range c.PCRValues {
					values[k] = v
				}
				c.PCRValues = values
			}
			out[i].Conditions[j] = c
		}
	}
	return out
}

// validateBranches refuses a request without a branch, or with a pcr
// condition that selects no PCR.
func validateBranches(branches []transport.TPMPolicyBranch) error {
	if len(branches) == 0 {
		return ErrNoBranches
	}
	for _, b := range branches {
		for _, c := range b.Conditions {
			if c.Type == transport.TPMPolicyConditionPCR && len(c.PCRs) == 0 {
				return ErrNoPCRs
			}
		}
	}
	return nil
}

// TPMPolicyCreate creates a named policy of the request's branches over the
// live PCR values.
func (f *Fake) TPMPolicyCreate(_ context.Context, req *transport.TPMPolicyCreateRequest) (*transport.TPMPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	switch req.Name {
	case "":
		return nil, ErrNameRequired
	case xkms.TPMPolicyPlatform:
		return nil, xkms.ErrTPMPolicyReserved
	}
	if err := validateBranches(req.Branches); err != nil {
		return nil, err
	}
	sc := scope(req.TenantID)
	if _, exists := f.policies[sc][req.Name]; exists {
		return nil, xkms.ErrTPMPolicyExists
	}
	if f.policies[sc] == nil {
		f.policies[sc] = make(map[string]*transport.TPMPolicy)
	}
	p := &transport.TPMPolicy{
		Name:                req.Name,
		TenantID:            req.TenantID,
		Description:         req.Description,
		Branches:            copyBranches(req.Branches),
		Index:               uint32(0x01500000 + len(f.policies[sc])),
		Epoch:               f.epoch,
		AuthorityGeneration: f.generation,
		CreatedAt:           "2026-01-01T00:00:00Z",
	}
	approve(p, true)
	f.capture(p)
	f.policies[sc][req.Name] = p
	if req.AutoUnseal {
		f.markAutoUnseal(sc, req.Name)
	}
	return copyOf(p), nil
}

// TPMPolicyGet returns a named policy.
func (f *Fake) TPMPolicyGet(_ context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	p, err := f.policy(req.TenantID, req.Name)
	if err != nil {
		return nil, err
	}
	return copyOf(p), nil
}

// TPMPolicyList returns the tenant's policies, sorted by name.
func (f *Fake) TPMPolicyList(_ context.Context, req *transport.TPMPolicyListRequest) (*transport.TPMPolicyListResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	resp := &transport.TPMPolicyListResponse{Policies: []transport.TPMPolicy{}}
	for _, p := range f.policies[scope(req.TenantID)] {
		resp.Policies = append(resp.Policies, *copyOf(p))
	}
	sort.Slice(resp.Policies, func(i, j int) bool { return resp.Policies[i].Name < resp.Policies[j].Name })
	return resp, nil
}

// TPMPolicyUpdate re-captures a policy's values and re-approves it.
func (f *Fake) TPMPolicyUpdate(_ context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	p, err := f.policy(req.TenantID, req.Name)
	if err != nil {
		return nil, err
	}
	f.capture(p)
	approve(p, true)
	p.AuthorityGeneration = f.generation
	p.UpdatedAt = "2026-01-02T00:00:00Z"
	f.bump(req.TenantID)
	return copyOf(p), nil
}

// TPMPolicyRevoke withdraws a policy's approval.
func (f *Fake) TPMPolicyRevoke(_ context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	p, err := f.policy(req.TenantID, req.Name)
	if err != nil {
		return nil, err
	}
	if p.Approved {
		approve(p, false)
		p.Epoch = 0
		p.AuthorityGeneration = 0
		f.bump(req.TenantID)
	}
	return copyOf(p), nil
}

// TPMPolicyVerify compares a policy's captured values with the live ones.
func (f *Fake) TPMPolicyVerify(_ context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyVerifyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	p, err := f.policy(req.TenantID, req.Name)
	if err != nil {
		return nil, err
	}
	approved := p.Approved && p.Epoch == f.epoch
	resp := &transport.TPMPolicyVerifyResponse{Name: p.Name, Match: true, Approved: approved}
	for _, b := range p.Branches {
		v := transport.TPMPolicyBranchVerification{Approved: approved}
		for _, c := range b.Conditions {
			for _, pcr := range c.PCRs {
				if c.PCRValues[pcr] != f.pcrs[pcr] {
					v.Mismatched = append(v.Mismatched, pcr)
				}
			}
		}
		v.Match = len(v.Mismatched) == 0
		resp.Match = resp.Match && v.Match
		resp.Branches = append(resp.Branches, v)
	}
	return resp, nil
}

// TPMPolicyDelete deletes a policy no object is assigned to; otherwise it
// refuses with *xkms.TPMPolicyInUseError listing the objects.
func (f *Fake) TPMPolicyDelete(_ context.Context, req *transport.TPMPolicyDeleteRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	if _, err := f.policy(req.TenantID, req.Name); err != nil {
		return err
	}
	sc := scope(req.TenantID)
	if objects := f.objectsOf(sc, req.Name); len(objects) > 0 {
		return &xkms.TPMPolicyInUseError{Policy: req.Name, Objects: objects}
	}
	delete(f.policies[sc], req.Name)
	return nil
}

// objectsOf returns the sorted IDs of the objects assigned to policy. The
// caller holds f.mu.
func (f *Fake) objectsOf(sc, policy string) []string {
	objects := []string{}
	for id, p := range f.objects[sc] {
		if p == policy {
			objects = append(objects, id)
		}
	}
	sort.Strings(objects)
	return objects
}

// TPMPolicyObjects lists the objects assigned to a policy ("platform"
// included).
func (f *Fake) TPMPolicyObjects(_ context.Context, req *transport.TPMPolicyRequest) (*transport.TPMPolicyObjectsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	if req.Name == "" {
		return nil, ErrNameRequired
	}
	if req.Name != xkms.TPMPolicyPlatform {
		if _, err := f.policy(req.TenantID, req.Name); err != nil {
			return nil, err
		}
	}
	return &transport.TPMPolicyObjectsResponse{Name: req.Name, Objects: f.objectsOf(scope(req.TenantID), req.Name)}, nil
}

// markAutoUnseal gives name the auto-unseal mark and clears it from every
// other policy of the scope. The caller holds f.mu.
func (f *Fake) markAutoUnseal(sc, name string) {
	for other, p := range f.policies[sc] {
		p.AutoUnseal = other == name
	}
}

// TPMPolicySetAutoUnseal sets or clears a policy's auto-unseal mark.
func (f *Fake) TPMPolicySetAutoUnseal(_ context.Context, req *transport.TPMPolicyAutoUnsealRequest) (*transport.TPMPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	p, err := f.policy(req.TenantID, req.Name)
	if err != nil {
		return nil, err
	}
	if req.Enabled {
		f.markAutoUnseal(scope(req.TenantID), req.Name)
	} else {
		p.AutoUnseal = false
	}
	return copyOf(p), nil
}

// TPMPolicySetDescription replaces a policy's description.
func (f *Fake) TPMPolicySetDescription(_ context.Context, req *transport.TPMPolicyDescriptionRequest) (*transport.TPMPolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	p, err := f.policy(req.TenantID, req.Name)
	if err != nil {
		return nil, err
	}
	p.Description = req.Description
	return copyOf(p), nil
}

// TPMObjectPolicy returns the policy an object was created under.
func (f *Fake) TPMObjectPolicy(_ context.Context, req *transport.TPMObjectPolicyRequest) (*transport.TPMObjectPolicyResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	if req.KeyID == "" {
		return nil, ErrKeyIDRequired
	}
	kind := req.Kind
	if kind == "" {
		kind = transport.TPMObjectKindKey
	}
	name := req.KeyID
	if i := strings.LastIndex(name, ":"); i >= 0 {
		name = name[i+1:]
	}
	id := kind + "/" + name
	policy, ok := f.objects[scope(req.TenantID)][id]
	if !ok {
		return nil, xkms.ErrTPMPolicyNotAssigned
	}
	return &transport.TPMObjectPolicyResponse{ObjectID: id, Kind: kind, Policy: policy}, nil
}

// TPMPolicyRotateAuthority installs the next authority generation and
// re-approves every approved policy with it.
func (f *Fake) TPMPolicyRotateAuthority(_ context.Context, req *transport.TPMAuthorityRotateRequest) (*transport.TPMAuthorityRotateResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	f.generation++
	for _, p := range f.policies[scope(req.TenantID)] {
		if p.Approved {
			p.AuthorityGeneration = f.generation
		}
	}
	return &transport.TPMAuthorityRotateResponse{
		TenantID:      req.TenantID,
		Generation:    f.generation,
		AuthorityName: hex.EncodeToString([]byte{0x00, 0x0b, byte(f.generation)}),
		Epoch:         f.epoch,
	}, nil
}

// GetTenantTPMMode returns a tenant's TPM mode, "shared" until set.
func (f *Fake) GetTenantTPMMode(_ context.Context, tenantID string) (*transport.TenantTPMModeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	mode, ok := f.modes[tenantID]
	if !ok {
		mode = string(xkms.TPMDefaultMode)
	}
	return &transport.TenantTPMModeResponse{TenantID: tenantID, Mode: mode}, nil
}

// SetTenantTPMMode changes a tenant's TPM mode.
func (f *Fake) SetTenantTPMMode(_ context.Context, req *transport.SetTenantTPMModeRequest) (*transport.TenantTPMModeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.init()
	mode, err := xkms.ParseTPMMode(req.Mode)
	if err != nil {
		return nil, err
	}
	f.modes[req.TenantID] = string(mode)
	return &transport.TenantTPMModeResponse{TenantID: req.TenantID, Mode: string(mode)}, nil
}

// TenantVTPMStatus reports a tenant's vTPM, which the fake never runs.
func (f *Fake) TenantVTPMStatus(_ context.Context, tenantID string) (*transport.TenantVTPMStatusResponse, error) {
	return &transport.TenantVTPMStatusResponse{TenantID: tenantID}, nil
}

// TenantVTPMStart refuses: the fake has no vTPM supervisor.
func (f *Fake) TenantVTPMStart(_ context.Context, _ string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, xkms.ErrTPMVTPMUnavailable
}

// TenantVTPMStop refuses: the fake has no vTPM supervisor.
func (f *Fake) TenantVTPMStop(_ context.Context, _ string) (*transport.TenantVTPMStatusResponse, error) {
	return nil, xkms.ErrTPMVTPMUnavailable
}
