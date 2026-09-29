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
	"io/fs"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
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
// policy is the only way to use the object (its password, when it has one, is
// the policy's PolicyAuthValue branch). It returns the binding to record
// beside the object's blobs, or nil when the key names no authorized policy.
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
	index, hashAlg, err := resolver.PolicyIndex(scope, keyAttrs.TPMPolicy)
	if err != nil {
		return nil, err
	}
	if hashAlg != template.NameAlg {
		return nil, &errs.Detail{
			Err:    ErrPolicyHashMismatch,
			Detail: fmt.Sprintf("policy 0x%x, object 0x%x", hashAlg, template.NameAlg),
		}
	}

	pub, indexName, err := tpm.nvPublic(index)
	if err != nil {
		return nil, err
	}
	if !pub.Attributes.Written {
		return nil, &errs.Detail{Err: ErrPolicyIndexUnwritten, Detail: fmt.Sprintf("0x%08x", index)}
	}

	withAuthValue := keyAuthValue(keyAttrs) != nil
	authPolicy, _, err := AuthorizedObjectPolicy(hashAlg, indexName, withAuthValue)
	if err != nil {
		return nil, err
	}
	template.AuthPolicy = tpm2.TPM2BDigest{Buffer: authPolicy}
	template.ObjectAttributes.UserWithAuth = false

	tpm.logger.Debug("tpm: binding object to named policy",
		slog.String("cn", keyAttrs.CN),
		slog.String("scope", scope),
		slog.String("policy", keyAttrs.TPMPolicy),
		slog.String("index", fmt.Sprintf("0x%08x", index)),
		slog.Bool("auth_value_branch", withAuthValue))

	return &store.TPMPolicyBinding{
		Scope:           scope,
		Policy:          keyAttrs.TPMPolicy,
		Index:           uint32(index),
		HashAlg:         uint16(hashAlg),
		AuthValueBranch: withAuthValue,
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
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return store.UnmarshalTPMPolicyBinding(record)
}

// authorizedPolicySession builds the policy session that satisfies the
// authPolicy of an object bound to a named policy (see AuthorizedObjectPolicy).
//
// A key with a password and a PolicyAuthValue branch takes that branch:
// PolicyAuthValue, then PolicyOR, in a salted session carrying the password.
// It needs no approval, so it keeps working while the policy is revoked or the
// platform state has moved. Every other key takes the approved branch (see
// approvedPolicySession).
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

	if auth := keyAuthValue(keyAttrs); auth != nil && binding.AuthValueBranch {
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

	session, closer, err := tpm.approvedPolicySession(binding, index, indexName)
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

// approvedPolicySession redeems the current approval of the policy binding
// names, in a fresh policy session that carries no secret:
//
//  1. PolicyPCR(selection, pcrDigest)    fails once the platform state moves
//  2. PolicyNV(counter == epoch)         fails once the approval is superseded
//  3. PolicyGetDigest == approvedPolicy  the approval describes this session
//  4. VerifySignature(authority, aHash)  yields the ticket
//  5. PolicyAuthorize(approvedPolicy, policyRef, authority Name, ticket)
//  6. PolicyAuthorizeNV(index)           the index names this authority
//
// Steps 1, 2, 5 and 6 are enforced by the TPM; step 3 only turns a
// mismatched approval into ErrPolicyApprovalMismatch instead of a ticket
// failure.
func (tpm *TPM2) approvedPolicySession(
	binding *store.TPMPolicyBinding,
	index tpm2.TPMHandle,
	indexName tpm2.TPM2BName) (tpm2.Session, func() error, error) {

	resolver, err := tpm.policyBindingResolver()
	if err != nil {
		return nil, noopCloser, err
	}
	approval, err := resolver.Approval(binding.Scope, binding.Policy)
	if err != nil {
		return nil, noopCloser, err
	}
	hashAlg := tpm2.TPMAlgID(binding.HashAlg)
	if err := validateApproval(approval, binding, hashAlg); err != nil {
		return nil, noopCloser, err
	}

	counterName, err := tpm.NVIndexName(approval.Counter)
	if err != nil {
		return nil, noopCloser, err
	}
	approved, err := ApprovedPolicyDigest(hashAlg, approval.PCRSelection, approval.PCRDigest, counterName, approval.Epoch)
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

	session, closer, err := tpm.startPolicySession(hashAlg, nil)
	if err != nil {
		return nil, noopCloser, err
	}
	fail := func(err error) (tpm2.Session, func() error, error) {
		tpm.closeSession(closer, "approved policy")
		return nil, noopCloser, err
	}

	if _, err := (tpm2.PolicyPCR{
		PolicySession: session.Handle(),
		PcrDigest:     tpm2.TPM2BDigest{Buffer: approval.PCRDigest},
		Pcrs:          approval.PCRSelection,
	}).Execute(tpm.transport); err != nil {
		if errors.Is(err, tpm2.TPMRCValue) {
			err = &PolicyPCRMismatchError{Scope: binding.Scope, Policy: binding.Policy, Err: err}
		}
		return fail(err)
	}

	if err := tpm.policyNVEpoch(session, approval.Counter, counterName, approval.Epoch); err != nil {
		if errors.Is(err, tpm2.TPMRCPolicy) {
			err = &PolicyApprovalRevokedError{Scope: binding.Scope, Policy: binding.Policy, Epoch: approval.Epoch, Err: err}
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

// startPolicySession starts a policy session in hashAlg. A non-empty auth is
// the auth value a PolicyAuthValue branch proves: it is handed to the session,
// whose HMAC key becomes sessionKey || authValue (TPM 2.0 Part 1, section
// 19.6), and the session is salted so a captured command neither reveals the
// value nor lets it be brute forced offline. A session proving no secret
// needs no salt.
func (tpm *TPM2) startPolicySession(hashAlg tpm2.TPMAlgID, auth []byte) (tpm2.Session, func() error, error) {
	if len(auth) == 0 {
		return tpm2.PolicySession(tpm.transport, hashAlg, sessionNonceSize)
	}
	saltHandle, saltPub, release, err := tpm.saltKey()
	if err != nil {
		return nil, noopCloser, err
	}
	session, closer, err := tpm2.PolicySession(tpm.transport, hashAlg, sessionNonceSize,
		tpm2.Auth(auth),
		tpm2.Salted(saltHandle, saltPub))
	tpm.closeSession(release, "salt key")
	if err != nil {
		return nil, noopCloser, err
	}
	return session, closer, nil
}
