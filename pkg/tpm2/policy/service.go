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

package policy

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

const (
	// policyHashAlg is the hash of every policy index, authorize digest and
	// approved-policy session. It must equal the name algorithm of the
	// objects bound to a policy, whatever PCR bank the policy selects, and
	// every TPM this package provisions names its objects with SHA-256.
	policyHashAlg = tpm2.TPMAlgSHA256

	// maxPCR is the highest PCR index a policy may select.
	maxPCR = 23
)

// Config configures a Service.
type Config struct {
	// Registry records scopes, policies and assignments.
	Registry *Registry

	// TPM is the physical TPM: the system scope's, and every shared-mode
	// tenant's.
	TPM *pkgtpm2.TPM2

	// PlatformSRK is the physical TPM's Platform SRK: the system scope's
	// storage parent and the parent of every shared tenant's storage key.
	PlatformSRK *types.KeyAttributes

	// Keys is the physical key store: the system scope's object blobs.
	Keys store.KeyBackend

	// TenantKeys holds every tenant's object blobs, each scoped to its
	// tenant.
	TenantKeys *store.BlobStore

	// Sealer is the physical TPM's sealer; it seals each scope's secrets
	// under the platform policy.
	Sealer types.Sealer

	// VTPM configures the per-tenant vTPM supervisor. Nil makes vtpm mode
	// unavailable (ErrVTPMUnavailable). The service is the supervisor's
	// StateKeyProvider, which is why it builds the supervisor itself.
	VTPM *vtpm.Config

	// ReferenceSigner is the reference-value signer's endorsement: the
	// pinned key or the certificate roots a signed CoRIM must verify under
	// before a branch is updated from it. Its Now is ignored; Clock is used.
	// Nil makes reference-value updates unavailable (ErrNoReferenceSigner).
	ReferenceSigner *refvalue.VerifyOptions

	// EventLog reads the physical TPM's boot event log, which predicts a
	// component-measured PCR. Nil parses the log the kernel exposes for TPM.
	EventLog func() (*evidence.EventLog, error)

	// Logger receives lifecycle events. Nil uses slog.Default().
	Logger *slog.Logger

	// Clock stamps records. Nil uses time.Now.
	Clock func() time.Time
}

// Service manages named TPM policies, the registry of which object uses
// which policy, and each tenant's TPM scope. It is the TPM's
// PolicyBindingResolver and the vTPM supervisor's StateKeyProvider.
type Service struct {
	registry    *Registry
	tpm         *pkgtpm2.TPM2
	platformSRK *types.KeyAttributes
	keys        store.KeyBackend
	tenantBlobs *store.BlobStore
	sealer      types.Sealer
	vtpm        *vtpm.Manager
	logger      *slog.Logger
	clock       func() time.Time

	referenceSigner *refvalue.VerifyOptions
	eventLog        func() (*evidence.EventLog, error)

	statesMu sync.Mutex
	states   map[string]*scopeState

	// nvMu serializes NV index allocation, so concurrent scopes never pick
	// the same free index.
	nvMu sync.Mutex

	// stateKeys caches unsealed vTPM state keys by tenant; the supervisor
	// asks for one on every (re)start.
	stateKeys sync.Map
}

var (
	_ pkgtpm2.PolicyBindingResolver = (*Service)(nil)
	_ vtpm.StateKeyProvider         = (*Service)(nil)
)

// NewService returns a Service over cfg and installs it as the physical
// TPM's policy binding resolver.
func NewService(cfg Config) (*Service, error) {
	switch {
	case cfg.Registry == nil:
		return nil, ErrNilRegistry
	case cfg.TPM == nil:
		return nil, ErrNilTPM
	case cfg.PlatformSRK == nil || cfg.PlatformSRK.TPMAttributes == nil:
		return nil, ErrNilPlatformSRK
	case cfg.Keys == nil:
		return nil, ErrNilKeys
	case cfg.TenantKeys == nil:
		return nil, ErrNilTenantKeys
	case cfg.Sealer == nil:
		return nil, ErrNilSealer
	}
	s := &Service{
		registry:    cfg.Registry,
		tpm:         cfg.TPM,
		platformSRK: cfg.PlatformSRK,
		keys:        cfg.Keys,
		tenantBlobs: cfg.TenantKeys,
		sealer:      cfg.Sealer,
		logger:      cfg.Logger,
		clock:       cfg.Clock,
		states:      make(map[string]*scopeState),

		referenceSigner: cfg.ReferenceSigner,
		eventLog:        cfg.EventLog,
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.eventLog == nil {
		s.eventLog = s.kernelEventLog
	}
	if cfg.VTPM != nil {
		manager, err := vtpm.NewManager(*cfg.VTPM, s)
		if err != nil {
			return nil, &VTPMError{Op: "configure", Err: err}
		}
		s.vtpm = manager
	}
	s.tpm.SetPolicyBindingResolver(s)
	return s, nil
}

// Close releases every open scope, stops every vTPM, and removes the service
// as the physical TPM's resolver. The Service cannot be used afterwards.
func (s *Service) Close() error {
	s.statesMu.Lock()
	states := s.states
	s.states = make(map[string]*scopeState)
	s.statesMu.Unlock()

	var errs []error
	for _, st := range states {
		st.mu.Lock()
		errs = append(errs, s.release(st))
		st.mu.Unlock()
	}
	if s.vtpm != nil {
		errs = append(errs, s.vtpm.Close())
	}
	s.tpm.SetPolicyBindingResolver(nil)
	return errors.Join(errs...)
}

// checkPolicyName refuses a name that cannot be stored and the built-in
// platform policy.
func checkPolicyName(name string) error {
	if name == PlatformPolicy {
		return ErrReservedPolicy
	}
	return validName(name)
}

// CreatePolicy creates a named policy whose pcr conditions capture the live
// PCR values of the scope's TPM: it defines and writes the policy's NV index
// to name the scope's authority, and signs the first approval of every
// branch at the scope's current epoch. With AutoUnseal, the mark moves to
// this policy.
func (s *Service) CreatePolicy(ctx context.Context, tenant string, req CreatePolicyRequest) (*Policy, error) {
	if err := checkPolicyName(req.Name); err != nil {
		return nil, err
	}
	if err := validateDescription(req.Description); err != nil {
		return nil, err
	}
	branches, err := validateBranches(req.Branches)
	if err != nil {
		return nil, err
	}
	st, unlock, err := s.lockScope(tenant)
	if err != nil {
		return nil, err
	}
	defer unlock()
	scope, err := s.loadActive(ctx, st, req.OwnerAuth)
	if err != nil {
		return nil, err
	}
	req.Branches = branches
	return s.createPolicy(ctx, st, scope, req)
}

// createPolicy creates a policy from validated req.Branches in an open
// scope. The caller holds st.mu.
func (s *Service) createPolicy(ctx context.Context, st *scopeState, scope *Scope, req CreatePolicyRequest) (_ *Policy, err error) {
	_, err = s.registry.Policy(ctx, st.name, req.Name)
	switch {
	case err == nil:
		return nil, ErrPolicyExists
	case !errors.Is(err, ErrPolicyNotFound):
		return nil, err
	}

	now := s.clock()
	p := &Policy{
		Name:        req.Name,
		Description: req.Description,
		Branches:    req.Branches,
		PolicyRef:   pkgtpm2.PolicyRef(st.name, req.Name),
		AutoUnseal:  req.AutoUnseal,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := capture(st.tpm.TPM, st.name, p); err != nil {
		return nil, err
	}

	index, err := s.defineIndex(st, func(t *pkgtpm2.TPM2, index tpm2.TPMHandle) error {
		_, err := t.DefinePolicyIndex(index, policyHashAlg, st.secrets.NVWriteAuth, st.ownerAuth(req.OwnerAuth))
		return err
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.undefineIndex(st, index, req.OwnerAuth))
		}
	}()
	p.Index = uint32(index)
	if p.IndexName, err = s.writePolicyIndex(st, p, &scope.Authority); err != nil {
		return nil, err
	}
	if p.Approvals, err = s.approve(st, scope, p, &scope.Authority, scope.Epoch); err != nil {
		return nil, err
	}
	if err := s.registry.CreatePolicy(ctx, st.name, p); err != nil {
		return nil, err
	}
	if p.AutoUnseal {
		if err := s.clearAutoUnseal(ctx, st.name, p.Name); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// writePolicyIndex writes p's NV index to name authority and returns the
// index's Name once written.
func (s *Service) writePolicyIndex(st *scopeState, p *Policy, authority *Authority) ([]byte, error) {
	digest, err := pkgtpm2.AuthorizeDigest(policyHashAlg, tpm2.TPM2BName{Buffer: authority.Name}, p.PolicyRef)
	if err != nil {
		return nil, &TPMError{Scope: st.name, Op: "authorize digest", Err: err}
	}
	name, err := st.tpm.TPM.WritePolicyIndex(tpm2.TPMHandle(p.Index), st.secrets.NVWriteAuth, digest, policyHashAlg)
	if err != nil {
		return nil, &TPMError{Scope: st.name, Op: "write policy index", Err: err}
	}
	return name.Buffer, nil
}

// approve signs, with authority, an approval of every branch of p, with
// the values it captured, at epoch of the scope's counter. The approvals are
// index-aligned with p.Branches.
func (s *Service) approve(st *scopeState, scope *Scope, p *Policy, authority *Authority, epoch uint64) ([]*Approval, error) {
	t := st.tpm.TPM
	counterName, err := t.NVIndexName(tpm2.TPMHandle(scope.Counter))
	if err != nil {
		return nil, &TPMError{Scope: st.name, Op: "read counter name", Err: err}
	}
	public := tpm2.BytesAs2B[tpm2.TPMTPublic](authority.Public)
	pub, err := public.Contents()
	if err != nil {
		return nil, &TPMError{Scope: st.name, Op: "decode policy authority", Err: err}
	}
	attrs, err := s.authorityAttrs(st, authority.CN)
	if err != nil {
		return nil, err
	}

	approvals := make([]*Approval, 0, len(p.Branches))
	for _, b := range p.Branches {
		branch, err := tpmBranch(b)
		if err != nil {
			return nil, err
		}
		approved, err := pkgtpm2.ApprovedPolicyDigest(policyHashAlg, branch, counterName, epoch)
		if err != nil {
			return nil, &TPMError{Scope: st.name, Op: "approved policy digest", Err: err}
		}
		aHash, err := pkgtpm2.ApprovalDigest(pub.NameAlg, approved, p.PolicyRef)
		if err != nil {
			return nil, &TPMError{Scope: st.name, Op: "approval digest", Err: err}
		}
		signature, err := t.SignApproval(attrs, st.tpm.Keys, aHash)
		if err != nil {
			return nil, &TPMError{Scope: st.name, Op: "sign approval", Err: err}
		}
		approvals = append(approvals, &Approval{
			Epoch:               epoch,
			AuthorityGeneration: authority.Generation,
			Signature:           tpm2.Marshal(*signature),
			ApprovedAt:          s.clock(),
		})
	}
	return approvals, nil
}

// resignAll re-signs, at epoch and with the scope's current authority, every
// branch of every policy of the scope that is approved, stores them, and
// records epoch on the scope. changed, when set, replaces the stored policy
// of its name and is approved even if it was revoked; it is returned as
// stored. A failure releases the open scope, so its next use reconciles the
// change. The caller holds st.mu.
func (s *Service) resignAll(ctx context.Context, st *scopeState, scope *Scope, epoch uint64, changed *Policy) (_ *Policy, err error) {
	defer func() {
		if err != nil {
			err = errors.Join(err, s.release(st))
		}
	}()
	policies, err := s.registry.ListPolicies(ctx, st.name)
	if err != nil {
		return nil, err
	}
	now := s.clock()
	for _, p := range policies {
		if changed != nil && p.Name == changed.Name {
			p = changed
		} else if !p.approved() {
			continue
		}
		if p.Approvals, err = s.approve(st, scope, p, &scope.Authority, epoch); err != nil {
			return nil, err
		}
		p.UpdatedAt = now
		if err := s.registry.UpdatePolicy(ctx, st.name, p); err != nil {
			return nil, err
		}
	}
	// The binding records are refreshed before the scope records epoch: until
	// it does, the counter is ahead of the scope's epoch, so a crash or a
	// failed write part-way is finished by reconcile.
	if err := s.refreshBindings(ctx, st); err != nil {
		return nil, err
	}
	scope.Epoch = epoch
	scope.UpdatedAt = now
	if err := s.registry.PutScope(ctx, scope); err != nil {
		return nil, err
	}
	return changed, nil
}

// incrementCounter moves the scope's revocation counter to its next epoch,
// which supersedes every approval signed so far.
func (s *Service) incrementCounter(st *scopeState, scope *Scope) (uint64, error) {
	epoch, err := st.tpm.TPM.IncrementCounter(tpm2.TPMHandle(scope.Counter), st.secrets.NVWriteAuth)
	if err != nil {
		return 0, &TPMError{Scope: st.name, Op: "increment counter", Err: err}
	}
	return epoch, nil
}

// lockPolicy locks tenant's open scope and loads its policy name.
func (s *Service) lockPolicy(ctx context.Context, tenant, name string) (*scopeState, *Scope, *Policy, func(), error) {
	if err := checkPolicyName(name); err != nil {
		return nil, nil, nil, nil, err
	}
	st, unlock, err := s.lockScope(tenant)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	scope, err := s.loadActive(ctx, st, nil)
	if err != nil {
		unlock()
		return nil, nil, nil, nil, err
	}
	p, err := s.registry.Policy(ctx, st.name, name)
	if err != nil {
		unlock()
		return nil, nil, nil, nil, err
	}
	return st, scope, p, unlock, nil
}

// UpdatePolicy re-captures the PCR values of every pcr condition of the
// policy from the scope's TPM, moves the scope's counter to its next epoch,
// and re-signs every branch of every policy of the scope at it: the others
// keep their values, a revoked one stays revoked, and this one is approved
// again even if it was revoked. The policy's branches never change, and no
// object is re-keyed.
func (s *Service) UpdatePolicy(ctx context.Context, tenant, name string) (*Policy, error) {
	st, scope, p, unlock, err := s.lockPolicy(ctx, tenant, name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := capture(st.tpm.TPM, st.name, p); err != nil {
		return nil, err
	}
	epoch, err := s.incrementCounter(st, scope)
	if err != nil {
		return nil, err
	}
	return s.resignAll(ctx, st, scope, epoch, p)
}

// RevokePolicy withdraws the approval of every branch of the policy: the
// scope's counter moves to its next epoch and every other policy is
// re-signed at it. The policy's objects then answer only to their outer
// password branch, when they have one, until it is updated. Revoking a
// revoked policy changes nothing.
func (s *Service) RevokePolicy(ctx context.Context, tenant, name string) (*Policy, error) {
	st, scope, p, unlock, err := s.lockPolicy(ctx, tenant, name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if !p.approved() {
		return p, nil
	}
	// The revocation is stored before the counter moves, so a crash in
	// between cannot let reconcile re-sign the revoked policy.
	p.revoke()
	p.UpdatedAt = s.clock()
	if err := s.registry.UpdatePolicy(ctx, st.name, p); err != nil {
		return nil, err
	}
	epoch, err := s.incrementCounter(st, scope)
	if err != nil {
		return nil, err
	}
	if _, err := s.resignAll(ctx, st, scope, epoch, nil); err != nil {
		return nil, err
	}
	return p, nil
}

// VerifyPolicy compares, branch by branch, the captured PCR values of the
// policy with the live ones and reports whether each branch holds an
// approval at the counter's current value. It is an advisory check; the TPM
// enforces the policy on use.
func (s *Service) VerifyPolicy(ctx context.Context, tenant, name string) (*Verification, error) {
	st, scope, p, unlock, err := s.lockPolicy(ctx, tenant, name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	counter, err := st.tpm.TPM.ReadCounter(tpm2.TPMHandle(scope.Counter))
	if err != nil {
		return nil, &TPMError{Scope: st.name, Op: "read counter", Err: err}
	}
	v := &Verification{
		Policy:   p.Name,
		Branches: make([]BranchVerification, len(p.Branches)),
		Match:    true,
		Approved: true,
	}
	for i, b := range p.Branches {
		bv, err := verifyBranch(st.tpm.TPM, st.name, b)
		if err != nil {
			return nil, err
		}
		bv.Approved = i < len(p.Approvals) && p.Approvals[i] != nil && p.Approvals[i].Epoch == counter
		v.Branches[i] = bv
		v.Match = v.Match && bv.Match
		v.Approved = v.Approved && bv.Approved
	}
	return v, nil
}

// SetDescription replaces the policy's description.
func (s *Service) SetDescription(ctx context.Context, tenant, name, description string) (*Policy, error) {
	if err := validateDescription(description); err != nil {
		return nil, err
	}
	st, _, p, unlock, err := s.lockPolicy(ctx, tenant, name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	p.Description = description
	p.UpdatedAt = s.clock()
	if err := s.registry.UpdatePolicy(ctx, st.name, p); err != nil {
		return nil, err
	}
	return p, nil
}

// DeletePolicy deletes the policy and undefines its NV index. It refuses
// with *PolicyInUseError, listing them, while objects are assigned to it.
// ownerAuth authorizes the physical TPM's owner hierarchy.
func (s *Service) DeletePolicy(ctx context.Context, tenant, name string, ownerAuth []byte) error {
	st, _, p, unlock, err := s.lockPolicy(ctx, tenant, name)
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.registry.DeletePolicy(ctx, st.name, name); err != nil {
		return err
	}
	return s.undefineIndex(st, tpm2.TPMHandle(p.Index), ownerAuth)
}

// Policy returns tenant's named policy.
func (s *Service) Policy(ctx context.Context, tenant, name string) (*Policy, error) {
	if err := checkPolicyName(name); err != nil {
		return nil, err
	}
	scope, err := s.requireTPM(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return s.registry.Policy(ctx, scope, name)
}

// ListPolicies returns tenant's named policies, sorted by name.
func (s *Service) ListPolicies(ctx context.Context, tenant string) ([]*Policy, error) {
	scope, err := s.requireTPM(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return s.registry.ListPolicies(ctx, scope)
}

// SetAutoUnseal sets or clears the policy's auto-unseal mark. Setting it
// clears it from every other policy of the scope.
func (s *Service) SetAutoUnseal(ctx context.Context, tenant, name string, on bool) error {
	st, _, p, unlock, err := s.lockPolicy(ctx, tenant, name)
	if err != nil {
		return err
	}
	defer unlock()
	p.AutoUnseal = on
	p.UpdatedAt = s.clock()
	if err := s.registry.UpdatePolicy(ctx, st.name, p); err != nil {
		return err
	}
	if !on {
		return nil
	}
	return s.clearAutoUnseal(ctx, st.name, p.Name)
}

// clearAutoUnseal clears the auto-unseal mark of every policy of scope but
// keep.
func (s *Service) clearAutoUnseal(ctx context.Context, scope, keep string) error {
	policies, err := s.registry.ListPolicies(ctx, scope)
	if err != nil {
		return err
	}
	for _, p := range policies {
		if p.Name == keep || !p.AutoUnseal {
			continue
		}
		p.AutoUnseal = false
		p.UpdatedAt = s.clock()
		if err := s.registry.UpdatePolicy(ctx, scope, p); err != nil {
			return err
		}
	}
	return nil
}

// AutoUnsealPolicy returns the policy of tenant's scope that carries the
// auto-unseal mark, or ErrPolicyNotFound when none does.
func (s *Service) AutoUnsealPolicy(ctx context.Context, tenant string) (*Policy, error) {
	policies, err := s.ListPolicies(ctx, tenant)
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		if p.AutoUnseal {
			return p, nil
		}
	}
	return nil, ErrPolicyNotFound
}

// RotateAuthority replaces the scope's policy authority with a new
// generation: every policy index is rewritten to name it and every current
// approval re-signed by it, so approvals by the old authority no longer
// authorize anything. No object is re-keyed. The rotation is recorded on the
// scope first, so a crash part-way is finished when the scope is next
// opened.
func (s *Service) RotateAuthority(ctx context.Context, tenant string) (*Scope, error) {
	st, unlock, err := s.lockScope(tenant)
	if err != nil {
		return nil, err
	}
	defer unlock()
	scope, err := s.loadActive(ctx, st, nil)
	if err != nil {
		return nil, err
	}
	next, err := s.createAuthority(st, scope.Authority.Generation+1)
	if err != nil {
		return nil, err
	}
	scope.Rotating = next
	scope.UpdatedAt = s.clock()
	if err := s.registry.PutScope(ctx, scope); err != nil {
		return nil, err
	}
	if err := s.finishRotation(ctx, st, scope); err != nil {
		return nil, err
	}
	return scope, nil
}

// finishRotation completes the rotation to scope.Rotating: it rewrites every
// policy index to name the new authority, re-signs every branch of every
// approved policy with it, records it as the scope's authority, and deletes the old one. Each
// step is safe to repeat, and a failure releases the open scope, so its next
// use finishes the rotation. The caller holds st.mu.
func (s *Service) finishRotation(ctx context.Context, st *scopeState, scope *Scope) (err error) {
	defer func() {
		if err != nil {
			err = errors.Join(err, s.release(st))
		}
	}()
	next := scope.Rotating
	policies, err := s.registry.ListPolicies(ctx, st.name)
	if err != nil {
		return err
	}
	now := s.clock()
	for _, p := range policies {
		if p.IndexName, err = s.writePolicyIndex(st, p, next); err != nil {
			return err
		}
		if p.approved() {
			if p.Approvals, err = s.approve(st, scope, p, next, scope.Epoch); err != nil {
				return err
			}
		}
		p.UpdatedAt = now
		if err := s.registry.UpdatePolicy(ctx, st.name, p); err != nil {
			return err
		}
	}
	// The binding records are refreshed while the scope still records the
	// rotation, which resolves approvals by the new authority: a crash or a
	// failed write part-way leaves the rotation for reconcile to finish.
	if err := s.refreshBindings(ctx, st); err != nil {
		return err
	}
	old := scope.Authority
	scope.Authority = *next
	scope.Rotating = nil
	scope.UpdatedAt = now
	if err := s.registry.PutScope(ctx, scope); err != nil {
		return err
	}
	s.logger.Info("tpmpolicy: rotated policy authority",
		slog.String("scope", st.name),
		slog.Uint64("generation", scope.Authority.Generation))
	return s.deleteAuthority(st, &old)
}

// PolicyIndex implements pkgtpm2.PolicyBindingResolver: the NV index objects
// bound to the named policy follow, its hash algorithm, and whether it has an
// auth_value condition.
func (s *Service) PolicyIndex(scope, name string) (pkgtpm2.PolicyIndexInfo, error) {
	if err := checkPolicyName(name); err != nil {
		return pkgtpm2.PolicyIndexInfo{}, err
	}
	p, err := s.registry.Policy(context.Background(), scope, name)
	if err != nil {
		return pkgtpm2.PolicyIndexInfo{}, err
	}
	return pkgtpm2.PolicyIndexInfo{
		Index:              tpm2.TPMHandle(p.Index),
		HashAlg:            policyHashAlg,
		AuthValueCondition: p.hasAuthValueCondition(),
	}, nil
}

// Approvals implements pkgtpm2.PolicyBindingResolver: the current approval
// of every branch of the named policy, in branch order, or ErrPolicyRevoked
// when it has none. A key used through its outer password branch never asks
// for them.
func (s *Service) Approvals(scope, name string) ([]*pkgtpm2.PolicyApproval, error) {
	if err := checkPolicyName(name); err != nil {
		return nil, err
	}
	ctx := context.Background()
	sc, err := s.registry.Scope(ctx, scope)
	if err != nil {
		return nil, err
	}
	p, err := s.registry.Policy(ctx, scope, name)
	if err != nil {
		return nil, err
	}
	if !p.approved() {
		return nil, ErrPolicyRevoked
	}
	approvals := make([]*pkgtpm2.PolicyApproval, len(p.Branches))
	for i := range p.Branches {
		if approvals[i], err = policyApproval(sc, p, i); err != nil {
			return nil, err
		}
	}
	return approvals, nil
}

// policyApproval builds the session-ready form of the stored approval of
// branch i of p.
func policyApproval(scope *Scope, p *Policy, i int) (*pkgtpm2.PolicyApproval, error) {
	approval := p.Approvals[i]
	authority, err := scope.authority(approval.AuthorityGeneration)
	if err != nil {
		return nil, err
	}
	branch, err := tpmBranch(p.Branches[i])
	if err != nil {
		return nil, err
	}
	signature, err := tpm2.Unmarshal[tpm2.TPMTSignature](approval.Signature)
	if err != nil {
		return nil, &StoreError{Op: "decode", Key: p.Name, Err: err}
	}
	return &pkgtpm2.PolicyApproval{
		HashAlg:         policyHashAlg,
		Branch:          branch,
		Counter:         tpm2.TPMHandle(scope.Counter),
		Epoch:           approval.Epoch,
		PolicyRef:       p.PolicyRef,
		AuthorityPublic: tpm2.BytesAs2B[tpm2.TPMTPublic](authority.Public),
		Signature:       *signature,
		Index:           tpm2.TPMHandle(p.Index),
	}, nil
}

// authority returns the scope's authority of generation: the current one or
// the one a rotation is moving to.
func (sc *Scope) authority(generation uint64) (*Authority, error) {
	if sc.Authority.Generation == generation {
		return &sc.Authority, nil
	}
	if sc.Rotating != nil && sc.Rotating.Generation == generation {
		return sc.Rotating, nil
	}
	return nil, &UnknownAuthorityError{Scope: sc.Tenant, Generation: generation}
}

// policyOrPlatform returns policy, or the built-in platform policy for "".
func policyOrPlatform(policy string) string {
	if policy == "" {
		return PlatformPolicy
	}
	return policy
}

// Assign records that the object of kind named name was created under
// policy ("" is the platform policy), with authPolicy its authPolicy digest.
// A named policy must exist.
func (s *Service) Assign(ctx context.Context, tenant string, kind ObjectKind, name, policy string, authPolicy []byte) error {
	scope, err := s.requireTPM(ctx, tenant)
	if err != nil {
		return err
	}
	return s.registry.Assign(ctx, scope, &Assignment{
		ObjectID:   ObjectID(kind, name),
		Kind:       kind,
		Policy:     policyOrPlatform(policy),
		AuthPolicy: authPolicy,
		CreatedAt:  s.clock(),
	})
}

// Unassign removes the object's assignment; an object with none is not an
// error.
func (s *Service) Unassign(ctx context.Context, tenant string, kind ObjectKind, name string) error {
	scope, err := s.requireTPM(ctx, tenant)
	if err != nil {
		return err
	}
	return s.registry.Unassign(ctx, scope, ObjectID(kind, name))
}

// PolicyOf returns the object's assignment, or ErrNotAssigned.
func (s *Service) PolicyOf(ctx context.Context, tenant string, kind ObjectKind, name string) (*Assignment, error) {
	scope, err := s.requireTPM(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return s.registry.PolicyOf(ctx, scope, ObjectID(kind, name))
}

// ObjectsOf returns the IDs of the objects assigned to policy ("" is the
// platform policy), sorted.
func (s *Service) ObjectsOf(ctx context.Context, tenant, policy string) ([]string, error) {
	scope, err := s.requireTPM(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return s.registry.ObjectsOf(ctx, scope, policyOrPlatform(policy))
}
