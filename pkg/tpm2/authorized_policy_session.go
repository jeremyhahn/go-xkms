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

package tpm2

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// keyAuthValue returns the key's non-empty auth value, or nil. An empty
// password is no password, for the reason CreateSession gives.
func keyAuthValue(keyAttrs *types.KeyAttributes) []byte {
	if keyAttrs.Password == nil {
		return nil
	}
	if auth := keyAttrs.Password.Bytes(); len(auth) > 0 {
		return auth
	}
	return nil
}

// namedPolicyBinding resolves the named policy keyAttrs.TPMPolicy for a new
// object whose name algorithm is nameAlg, and applies it to template: the
// authPolicy of AuthorizedObjectPolicy, and USERWITHAUTH cleared so the
// policy is the only way to use the object. The object gets the outer
// PolicyAuthValue branch only when it has a password and the policy has no
// auth_value condition: a policy that has one decides where the password
// counts. An object without a password is refused a policy with an
// auth_value condition, which an empty password would satisfy. It returns the
// binding to record beside the object's blobs, or nil when the key names no
// authorized policy.
func (tpm *TPM2) namedPolicyBinding(
	keyAttrs *types.KeyAttributes,
	template *tpm2.TPMTPublic) (*store.TPMPolicyBinding, error) {

	if !isNamedPolicy(keyAttrs.TPMPolicy) {
		return nil, nil
	}
	resolver, err := tpm.policyBindingResolver()
	if err != nil {
		return nil, err
	}
	scope := policyScope(keyAttrs)
	info, err := resolver.PolicyIndex(scope, keyAttrs.TPMPolicy)
	if err != nil {
		return nil, err
	}
	if info.HashAlg != template.NameAlg {
		return nil, &errs.Detail{
			Err:    ErrPolicyHashMismatch,
			Detail: fmt.Sprintf("policy 0x%x, object 0x%x", info.HashAlg, template.NameAlg),
		}
	}
	hasPassword := keyAuthValue(keyAttrs) != nil
	if info.AuthValueCondition && !hasPassword {
		return nil, &errs.Detail{Err: ErrPolicyAuthValueRequired, Detail: keyAttrs.TPMPolicy}
	}

	pub, indexName, err := tpm.nvPublic(info.Index)
	if err != nil {
		return nil, err
	}
	if !pub.Attributes.Written {
		return nil, &errs.Detail{Err: ErrPolicyIndexUnwritten, Detail: fmt.Sprintf("0x%08x", info.Index)}
	}

	withAuthValue := hasPassword && !info.AuthValueCondition
	authPolicy, _, err := AuthorizedObjectPolicy(info.HashAlg, indexName, withAuthValue)
	if err != nil {
		return nil, err
	}
	template.AuthPolicy = tpm2.TPM2BDigest{Buffer: authPolicy}
	template.ObjectAttributes.UserWithAuth = false

	tpm.logger.Debug("tpm: binding object to named policy",
		slog.String("cn", keyAttrs.CN),
		slog.String("scope", scope),
		slog.String("policy", keyAttrs.TPMPolicy),
		slog.String("index", fmt.Sprintf("0x%08x", info.Index)),
		slog.Bool("auth_value_branch", withAuthValue),
		slog.Bool("auth_value_condition", info.AuthValueCondition))

	return &store.TPMPolicyBinding{
		Scope:              scope,
		Policy:             keyAttrs.TPMPolicy,
		Index:              uint32(info.Index),
		HashAlg:            uint16(info.HashAlg),
		AuthValueBranch:    withAuthValue,
		AuthValueCondition: info.AuthValueCondition,
	}, nil
}

// recordPolicyBinding persists binding beside the object's blobs. Without it
// the object could not be used: nothing else says which policy to satisfy.
// backend may be nil, in which case the platform backend is used, and
// overwrite carries the caller's own overwrite policy.
func (tpm *TPM2) recordPolicyBinding(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend,
	binding *store.TPMPolicyBinding,
	overwrite bool) error {

	if backend == nil {
		backend = tpm.backend
	}
	if backend == nil {
		return ErrNoStorageBackend
	}
	record, err := binding.MarshalBinary()
	if err != nil {
		return err
	}
	return backend.Save(keyAttrs, record, store.FSEXT_TPM_POLICY, overwrite)
}

// loadPolicyBinding returns the named-policy binding recorded beside the
// object's blobs, or nil when it has none. A record that exists but cannot be
// read is an error: authorizing along a guessed path would only turn it into
// an obscure TPM failure. backend may be nil, in which case the platform
// backend is used.
func (tpm *TPM2) loadPolicyBinding(
	keyAttrs *types.KeyAttributes,
	backend store.KeyBackend) (*store.TPMPolicyBinding, error) {

	if keyAttrs == nil || keyAttrs.CN == "" {
		return nil, nil
	}
	if backend == nil {
		backend = tpm.backend
	}
	if backend == nil {
		return nil, nil
	}
	record, err := backend.Get(keyAttrs, store.FSEXT_TPM_POLICY)
	if err != nil {
		if errors.Is(err, store.ErrBlobNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return store.UnmarshalTPMPolicyBinding(record)
}

// authorizedPolicySession builds the policy session that satisfies the
// authPolicy of an object bound to a named policy (see AuthorizedObjectPolicy).
//
// A key with a password and an outer PolicyAuthValue branch takes that
// branch: PolicyAuthValue, then PolicyOR, in a salted session carrying the
// password. It needs no approval, so it keeps working while the policy is
// revoked or the platform state has moved. Every other key redeems one of the
// policy's branch approvals (see approvedPolicySession).
func (tpm *TPM2) authorizedPolicySession(
	keyAttrs *types.KeyAttributes,
	binding *store.TPMPolicyBinding) (tpm2.Session, func() error, error) {

	index := tpm2.TPMHandle(binding.Index)
	hashAlg := tpm2.TPMAlgID(binding.HashAlg)
	indexName, err := tpm.NVIndexName(index)
	if err != nil {
		return nil, noopCloser, err
	}
	_, branches, err := AuthorizedObjectPolicy(hashAlg, indexName, binding.AuthValueBranch)
	if err != nil {
		return nil, noopCloser, err
	}

	auth := keyAuthValue(keyAttrs)
	if auth != nil && binding.AuthValueBranch {
		session, closer, err := tpm.startPolicySession(hashAlg, auth)
		if err != nil {
			return nil, noopCloser, err
		}
		if _, err := (tpm2.PolicyAuthValue{PolicySession: session.Handle()}).Execute(tpm.transport); err != nil {
			tpm.closeSession(closer, "authorized policy")
			return nil, noopCloser, err
		}
		if err := tpm.policyORBranches(session, branches); err != nil {
			tpm.closeSession(closer, "authorized policy")
			return nil, noopCloser, err
		}
		return session, closer, nil
	}

	session, closer, err := tpm.approvedPolicySession(binding, index, auth)
	if err != nil {
		return nil, noopCloser, err
	}
	if len(branches) > 1 {
		if err := tpm.policyORBranches(session, branches); err != nil {
			tpm.closeSession(closer, "authorized policy")
			return nil, noopCloser, err
		}
	}
	return session, closer, nil
}

// approvedPolicySession redeems the first branch approval of the policy
// binding names that the TPM accepts, trying them in branch order. auth is
// the object's password, or nil.
//
//   - A branch with an auth_value condition is tried only when auth is set,
//     so the dictionary-attack counter is never spent on a guess.
//   - A branch the TPM refuses at PolicyLocality, PolicyPCR or PolicyNV moves
//     on to the next. Each attempt gets a fresh session: a failed assertion
//     leaves a session unusable.
//   - Any other failure is returned at once: it is not a property of the
//     branch, and the next branch would meet it too.
//
// When no branch succeeds, *PolicyBranchesRefusedError carries every
// branch's refusal.
func (tpm *TPM2) approvedPolicySession(
	binding *store.TPMPolicyBinding,
	index tpm2.TPMHandle,
	auth []byte) (tpm2.Session, func() error, error) {

	resolver, err := tpm.policyBindingResolver()
	if err != nil {
		return nil, noopCloser, err
	}
	approvals, err := resolver.Approvals(binding.Scope, binding.Policy)
	if err != nil {
		return nil, noopCloser, err
	}
	if len(approvals) == 0 {
		return nil, noopCloser, &errs.Detail{Err: ErrInvalidPolicyApproval, Detail: "no branch approvals"}
	}
	hashAlg := tpm2.TPMAlgID(binding.HashAlg)
	refusals := make([]error, 0, len(approvals))
	for i, approval := range approvals {
		if err := validateApproval(approval, binding, hashAlg); err != nil {
			return nil, noopCloser, err
		}
		ref := branchRef{scope: binding.Scope, policy: binding.Policy, branch: i}
		var branchAuth []byte
		if approval.Branch.HasAuthValue() {
			if auth == nil {
				refusals = append(refusals, &PolicyAuthValueMissingError{Scope: ref.scope, Policy: ref.policy, Branch: i})
				continue
			}
			branchAuth = auth
		}
		session, closer, err := tpm.redeemApproval(approval, index, branchAuth, ref)
		if err == nil {
			return session, closer, nil
		}
		if !isBranchRefusal(err) {
			return nil, noopCloser, err
		}
		refusals = append(refusals, err)
	}
	return nil, noopCloser, &PolicyBranchesRefusedError{Scope: binding.Scope, Policy: binding.Policy, Branches: refusals}
}

// isBranchRefusal reports whether err is the TPM refusing one branch --
// its locality, its PCRs, or its epoch -- rather than a failure the next
// branch would meet too.
func isBranchRefusal(err error) bool {
	var locality *PolicyLocalityMismatchError
	var pcr *PolicyPCRMismatchError
	var revoked *PolicyApprovalRevokedError
	return errors.As(err, &locality) || errors.As(err, &pcr) || errors.As(err, &revoked)
}

// redeemApproval redeems one branch approval in a fresh policy session. The
// session carries auth, the object's password, only for a branch with an
// auth_value condition:
//
//  1. the branch's assertions            locality, PCRs, auth value
//  2. PolicyNV(counter == epoch)         fails once the approval is superseded
//  3. PolicyGetDigest == approvedPolicy  the approval describes this session
//  4. VerifySignature(authority, aHash)  yields the ticket
//  5. PolicyAuthorize(approvedPolicy, policyRef, authority Name, ticket)
//  6. PolicyAuthorizeNV(index)           the index names this authority
//
// Steps 1, 2, 5 and 6 are enforced by the TPM; step 3 only turns a
// mismatched approval into ErrPolicyApprovalMismatch instead of a ticket
// failure. PolicyAuthorize and PolicyAuthorizeNV replace the session digest
// but keep what the branch's assertions require of the command -- the
// locality, and the auth value in the session HMAC -- so the TPM checks them
// when the object is used.
func (tpm *TPM2) redeemApproval(
	approval *PolicyApproval,
	index tpm2.TPMHandle,
	auth []byte,
	ref branchRef) (tpm2.Session, func() error, error) {

	counterName, err := tpm.NVIndexName(approval.Counter)
	if err != nil {
		return nil, noopCloser, err
	}
	approved, err := ApprovedPolicyDigest(approval.HashAlg, approval.Branch, counterName, approval.Epoch)
	if err != nil {
		return nil, noopCloser, err
	}
	authority, err := approval.AuthorityPublic.Contents()
	if err != nil {
		return nil, noopCloser, &errs.Joined{Lead: ErrInvalidPolicyApproval, Detail: "authority public", Cause: err}
	}
	aHash, err := ApprovalDigest(authority.NameAlg, approved, approval.PolicyRef)
	if err != nil {
		return nil, noopCloser, err
	}

	session, closer, err := tpm.startPolicySession(approval.HashAlg, auth)
	if err != nil {
		return nil, noopCloser, err
	}
	fail := func(err error) (tpm2.Session, func() error, error) {
		tpm.closeSession(closer, "approved policy")
		return nil, noopCloser, err
	}

	if err := tpm.assertBranch(session, approval.Branch, ref); err != nil {
		return fail(err)
	}

	if err := tpm.policyNVEpoch(session, approval.Counter, counterName, approval.Epoch); err != nil {
		if errors.Is(err, tpm2.TPMRCPolicy) {
			err = &PolicyApprovalRevokedError{Scope: ref.scope, Policy: ref.policy, Branch: ref.branch, Epoch: approval.Epoch, Err: err}
		}
		return fail(err)
	}

	digest, err := tpm2.PolicyGetDigest{PolicySession: session.Handle()}.Execute(tpm.transport)
	if err != nil {
		return fail(err)
	}
	if !bytes.Equal(digest.PolicyDigest.Buffer, approved) {
		return fail(&errs.Detail{Err: ErrPolicyApprovalMismatch, Detail: "session digest differs from the approved policy"})
	}

	ticket, authorityName, err := tpm.verifyApproval(approval.AuthorityPublic, aHash, approval.Signature)
	if err != nil {
		return fail(err)
	}
	if _, err := (tpm2.PolicyAuthorize{
		PolicySession:  session.Handle(),
		ApprovedPolicy: tpm2.TPM2BDigest{Buffer: approved},
		PolicyRef:      tpm2.TPM2BDigest{Buffer: approval.PolicyRef},
		KeySign:        authorityName,
		CheckTicket:    *ticket,
	}).Execute(tpm.transport); err != nil {
		return fail(err)
	}

	if err := tpm.policyAuthorizeNV(session, index); err != nil {
		return fail(err)
	}
	return session, closer, nil
}

// validateApproval checks that approval is complete and describes the policy
// binding names.
func validateApproval(approval *PolicyApproval, binding *store.TPMPolicyBinding, hashAlg tpm2.TPMAlgID) error {
	switch {
	case approval == nil:
		return &errs.Detail{Err: ErrInvalidPolicyApproval, Detail: "nil approval"}
	case approval.HashAlg != hashAlg:
		return &errs.Detail{Err: ErrPolicyApprovalMismatch, Detail: "hash algorithm"}
	case approval.Index != tpm2.TPMHandle(binding.Index):
		return &errs.Detail{Err: ErrPolicyApprovalMismatch, Detail: "policy index"}
	case !bytes.Equal(approval.PolicyRef, PolicyRef(binding.Scope, binding.Policy)):
		return &errs.Detail{Err: ErrPolicyApprovalMismatch, Detail: "policy reference"}
	case approval.Counter == 0:
		return &errs.Detail{Err: ErrInvalidPolicyApproval, Detail: "no counter index"}
	}
	return nil
}

// policyNVEpoch runs TPM2_PolicyNV in session, requiring the counter index to
// equal epoch. The counter is read through its POLICYREAD authorization, so
// no secret is involved.
func (tpm *TPM2) policyNVEpoch(
	session tpm2.Session,
	counter tpm2.TPMHandle,
	counterName tpm2.TPM2BName,
	epoch uint64) error {

	auth, closer, err := tpm.nvPolicyReadAuth(counter, tpm2.TPMCCPolicyNV)
	if err != nil {
		return err
	}
	defer tpm.closeSession(closer, "counter policy read")

	_, err = tpm2.PolicyNV{
		AuthHandle:    auth,
		NVIndex:       tpm2.NamedHandle{Handle: counter, Name: counterName},
		PolicySession: session.Handle(),
		OperandB:      tpm2.TPM2BOperand{Buffer: epochOperand(epoch)},
		Offset:        0,
		Operation:     tpm2.TPMEOEq,
	}.Execute(tpm.transport)
	return err
}

// policyAuthorizeNV runs TPM2_PolicyAuthorizeNV in session against the policy
// index, read through its POLICYREAD authorization.
func (tpm *TPM2) policyAuthorizeNV(session tpm2.Session, index tpm2.TPMHandle) error {
	auth, closer, err := tpm.nvPolicyReadAuth(index, tpm2.TPMCCPolicyAuthorizeNV)
	if err != nil {
		return err
	}
	defer tpm.closeSession(closer, "policy index read")

	_, err = tpm2.PolicyAuthorizeNV{
		AuthHandle:    auth,
		NVIndex:       tpm2.NamedHandle{Handle: index, Name: auth.Name},
		PolicySession: session.Handle(),
	}.Execute(tpm.transport)
	return err
}

// policyORBranches runs TPM2_PolicyOR over branches in session.
func (tpm *TPM2) policyORBranches(session tpm2.Session, branches [][]byte) error {
	or := policyOR(branches)
	or.PolicySession = session.Handle()
	_, err := or.Execute(tpm.transport)
	return err
}

// startPolicySession starts a salted policy session in hashAlg. Every policy
// session that authorizes a command starts here; trial sessions, which
// authorize nothing, do not.
//
// The salt is what gives the session a key. Unsalted and unbound, the
// session key is the Empty Buffer (TPM 2.0 Part 1, section 19.6.8), so a
// session proving no auth value computes its command HMAC under a
// zero-length key, which FIPS 140-only mode refuses (#1531). A non-empty
// auth is the auth value a PolicyAuthValue branch proves: it is handed to
// the session, whose HMAC key becomes sessionKey || authValue (section
// 19.6), so a captured command neither reveals the value nor lets it be
// brute forced offline.
func (tpm *TPM2) startPolicySession(hashAlg tpm2.TPMAlgID, auth []byte) (tpm2.Session, func() error, error) {
	saltHandle, saltPub, release, err := tpm.saltKey()
	if err != nil {
		return nil, noopCloser, err
	}
	opts := []tpm2.AuthOption{tpm2.Salted(saltHandle, saltPub)}
	if len(auth) > 0 {
		opts = append(opts, tpm2.Auth(auth))
	}
	session, closer, err := tpm2.PolicySession(tpm.transport, hashAlg, sessionNonceSize, opts...)
	tpm.closeSession(release, "salt key")
	if err != nil {
		return nil, noopCloser, err
	}
	return session, closer, nil
}
