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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Named, authorized TPM policies (docs/tpm-policies/architecture.md, option A).
//
// An object created under the named policy P of scope S carries
//
//	authPolicy = PolicyAuthorizeNV(index(P))                     (no auth value)
//	authPolicy = PolicyOR(PolicyAuthorizeNV(index(P)),
//	                      PolicyAuthValue)                       (with auth value)
//
// index(P) holds PolicyAuthorize(authority(S), PolicyRef(S, P)), so the object
// follows whichever authority the index names, and the authority's signed
// approvals decide which platform state satisfies it:
//
//	approvedPolicy = PolicyPCR(selection, pcrDigest) -> PolicyNV(counter(S) == epoch)
//	aHash          = H(approvedPolicy || PolicyRef(S, P))
//	signature      = Sign(authority(S), aHash)
//
// Neither the PCR values nor the authority are part of the object's
// authPolicy, so a policy update (new PCR values, next epoch) and an authority
// rotation (rewrite index(P)) never re-key an object.

// SystemPolicyScope is the scope of the platform's own policies, used when a
// key carries no tenant.
const SystemPolicyScope = "system"

// policyRefDomain separates this package's policy references from any other
// use of TPM2_PolicyAuthorize's policyRef.
const policyRefDomain = "xkms/tpm-policy/v1"

// Owner-range NV indices (TCG "Registry of Reserved TPM 2.0 Handles and
// Localities", section 2.2): the range an owner allocates its own indices in.
const (
	// NVOwnerIndexFirst is the first NV index of the owner range.
	NVOwnerIndexFirst tpm2.TPMHandle = 0x01500000

	// NVOwnerIndexLast is the last NV index of the owner range.
	NVOwnerIndexLast tpm2.TPMHandle = 0x015FFFFF
)

var (
	// ErrPolicyResolverUnset is returned when a key names an authorized
	// policy but no PolicyBindingResolver has been set on the TPM.
	ErrPolicyResolverUnset = errors.New("tpm2: a named TPM policy was requested but no policy binding resolver is set")

	// ErrPolicyApprovalMismatch is returned when a policy session does not
	// reach the approved policy digest, or when an approval does not describe
	// the policy the object is bound to.
	ErrPolicyApprovalMismatch = errors.New("tpm2: the policy session does not match the policy approval")

	// ErrInvalidPolicyApproval is returned for an approval that is missing a
	// field the authorized session needs.
	ErrInvalidPolicyApproval = errors.New("tpm2: invalid policy approval")

	// ErrPolicyDigestCompute is returned when an authorized-policy trial
	// digest cannot be computed.
	ErrPolicyDigestCompute = errors.New("tpm2: failed to compute an authorized policy digest")

	// ErrPolicyHashMismatch is returned when a named policy's hash algorithm
	// differs from the name algorithm of the object bound to it: the TPM
	// compares the session digest with the object's authPolicy, so the two
	// must be the same algorithm.
	ErrPolicyHashMismatch = errors.New("tpm2: the policy hash algorithm differs from the object's name algorithm")

	// ErrPolicyIndexUnwritten is returned when an object would be bound to a
	// policy NV index that has never been written. The index's Name changes
	// on its first write, so an object bound before it could never be used.
	ErrPolicyIndexUnwritten = errors.New("tpm2: the policy NV index has not been written")

	// ErrInvalidPolicyIndexContent is returned when a policy NV index does
	// not hold a well-formed TPMT_HA of the expected algorithm and size.
	ErrInvalidPolicyIndexContent = errors.New("tpm2: invalid policy NV index content")

	// ErrTPMNVExhausted is returned when no NV index is free in the requested
	// range, or the TPM reports that its NV space is exhausted.
	ErrTPMNVExhausted = errors.New("tpm2: TPM NV space exhausted")

	// ErrInvalidNVIndexRange is returned for an NV index range that is empty
	// or lies outside the NV index handle type.
	ErrInvalidNVIndexRange = errors.New("tpm2: invalid NV index range")

	// ErrInvalidAuthoritySignature is returned when the authority's signature
	// cannot be converted into a TPMT_SIGNATURE.
	ErrInvalidAuthoritySignature = errors.New("tpm2: invalid policy authority signature")
)

// PolicyPCRMismatchError reports that TPM2_PolicyPCR refused the approved PCR
// values: the platform state has changed since the policy was approved. Err
// is the TPM response code, unchanged.
type PolicyPCRMismatchError struct {
	Scope  string
	Policy string
	Err    error
}

// Error describes the mismatch.
func (e *PolicyPCRMismatchError) Error() string {
	return fmt.Sprintf("tpm2: live PCRs do not match the approved values of policy %q in scope %q: %v",
		e.Policy, e.Scope, e.Err)
}

// Unwrap returns the TPM response code.
func (e *PolicyPCRMismatchError) Unwrap() error { return e.Err }

// PolicyApprovalRevokedError reports that TPM2_PolicyNV refused the approval's
// epoch: the scope's revocation counter has moved past it, so the approval has
// been superseded or revoked. Err is the TPM response code, unchanged.
type PolicyApprovalRevokedError struct {
	Scope  string
	Policy string
	Epoch  uint64
	Err    error
}

// Error describes the revocation.
func (e *PolicyApprovalRevokedError) Error() string {
	return fmt.Sprintf("tpm2: the approval of policy %q in scope %q at epoch %d is no longer current: %v",
		e.Policy, e.Scope, e.Epoch, e.Err)
}

// Unwrap returns the TPM response code.
func (e *PolicyApprovalRevokedError) Unwrap() error { return e.Err }

// PolicyApproval is an authority's signed approval of one platform state for
// one named policy, and everything a policy session needs to redeem it.
type PolicyApproval struct {
	// HashAlg is the policy session's hash algorithm.
	HashAlg tpm2.TPMAlgID

	// PCRSelection and PCRDigest are the TPM2_PolicyPCR operands of the
	// approved platform state.
	PCRSelection tpm2.TPMLPCRSelection
	PCRDigest    []byte

	// Counter is the scope's revocation counter NV index and Epoch the value
	// TPM2_PolicyNV requires it to hold.
	Counter tpm2.TPMHandle
	Epoch   uint64

	// PolicyRef is PolicyRef(scope, name) of the approved policy.
	PolicyRef []byte

	// AuthorityPublic is the public area of the key that signed the approval.
	AuthorityPublic tpm2.TPM2BPublic

	// Signature is the authority's signature over
	// ApprovalDigest(approvedPolicy, PolicyRef).
	Signature tpm2.TPMTSignature

	// Index is the policy NV index the approval redeems.
	Index tpm2.TPMHandle
}

// PolicyBindingResolver supplies the TPM with the state of named policies,
// which lives outside it: the policy registry.
type PolicyBindingResolver interface {
	// PolicyIndex returns the NV index and hash alg a named policy binds objects to.
	PolicyIndex(scope, name string) (tpm2.TPMHandle, tpm2.TPMAlgID, error)
	// Approval returns the current approval for a named policy.
	Approval(scope, name string) (*PolicyApproval, error)
}

// SetPolicyBindingResolver sets the resolver that key creation and key use
// consult for named policies. A nil r clears it.
func (tpm *TPM2) SetPolicyBindingResolver(r PolicyBindingResolver) {
	if r == nil {
		tpm.policyResolver.Store(nil)
		return
	}
	tpm.policyResolver.Store(&r)
}

// policyBindingResolver returns the configured resolver, or
// ErrPolicyResolverUnset.
func (tpm *TPM2) policyBindingResolver() (PolicyBindingResolver, error) {
	r := tpm.policyResolver.Load()
	if r == nil {
		return nil, ErrPolicyResolverUnset
	}
	return *r, nil
}

// isNamedPolicy reports whether a KeyAttributes.TPMPolicy value names an
// authorized policy rather than no policy or the built-in platform policy.
func isNamedPolicy(policy string) bool {
	return policy != "" && policy != types.TPMPolicyPlatform
}

// policyScope returns the policy scope of a key: its tenant, or
// SystemPolicyScope when it has none.
func policyScope(keyAttrs *types.KeyAttributes) string {
	if keyAttrs.TenantID == "" {
		return SystemPolicyScope
	}
	return keyAttrs.TenantID
}

// PolicyRef returns the TPM2_PolicyAuthorize policyRef of the named policy
// name in scope: SHA-256("xkms/tpm-policy/v1" || scope || 0x00 || name). The
// authority signs it together with the approved digest, so an approval of one
// policy cannot authorize an object bound to another.
func PolicyRef(scope, name string) []byte {
	h := sha256.New()
	h.Write([]byte(policyRefDomain))
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write([]byte(name))
	return h.Sum(nil)
}

// newPolicyCalculator returns a trial policy calculator for hashAlg.
func newPolicyCalculator(hashAlg tpm2.TPMAlgID) (*tpm2.PolicyCalculator, error) {
	calc, err := tpm2.NewPolicyCalculator(hashAlg)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPolicyDigestCompute, Cause: err}
	}
	return calc, nil
}

// trialDigest runs cmds through a trial policy calculator for hashAlg and
// returns the resulting digest.
func trialDigest(hashAlg tpm2.TPMAlgID, cmds ...tpm2.PolicyCommand) ([]byte, error) {
	calc, err := newPolicyCalculator(hashAlg)
	if err != nil {
		return nil, err
	}
	for _, cmd := range cmds {
		if err := cmd.Update(calc); err != nil {
			return nil, &errs.Joined{Lead: ErrPolicyDigestCompute, Detail: fmt.Sprintf("%T", cmd), Cause: err}
		}
	}
	return calc.Hash().Digest, nil
}

// AuthorizeDigest returns the policy digest after TPM2_PolicyAuthorize from a
// zero digest, naming the authority whose Name is authorityName and the
// reference policyRef. It is what a named policy's NV index holds (as a
// TPMT_HA of hashAlg), and so what PolicyAuthorizeNV compares against.
func AuthorizeDigest(hashAlg tpm2.TPMAlgID, authorityName tpm2.TPM2BName, policyRef []byte) ([]byte, error) {
	if len(authorityName.Buffer) == 0 {
		return nil, &errs.Detail{Err: ErrPolicyDigestCompute, Detail: "empty authority name"}
	}
	return trialDigest(hashAlg, tpm2.PolicyAuthorize{
		PolicyRef: tpm2.TPM2BDigest{Buffer: policyRef},
		KeySign:   authorityName,
	})
}

// epochOperand encodes epoch as the TPM2_PolicyNV operandB a counter index is
// compared with: eight octets, big endian, like the counter itself.
func epochOperand(epoch uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, epoch)
}

// ApprovedPolicyDigest returns the digest an authority approves: TPM2_PolicyPCR
// over pcrSel and pcrDigest, then TPM2_PolicyNV requiring the counter index
// whose Name is counterName to equal epoch (offset 0, TPM_EO_EQ).
//
// counterName must be the counter's Name as it is once written (its first
// increment sets TPMA_NV_WRITTEN, which is part of the Name).
func ApprovedPolicyDigest(
	hashAlg tpm2.TPMAlgID,
	pcrSel tpm2.TPMLPCRSelection,
	pcrDigest []byte,
	counterName tpm2.TPM2BName,
	epoch uint64) ([]byte, error) {

	if len(pcrSel.PCRSelections) == 0 || len(pcrDigest) == 0 {
		return nil, &errs.Detail{Err: ErrPolicyDigestCompute, Detail: "empty PCR selection or digest"}
	}
	if len(counterName.Buffer) == 0 {
		return nil, &errs.Detail{Err: ErrPolicyDigestCompute, Detail: "empty counter name"}
	}
	return trialDigest(hashAlg,
		tpm2.PolicyPCR{
			PcrDigest: tpm2.TPM2BDigest{Buffer: pcrDigest},
			Pcrs:      pcrSel,
		},
		tpm2.PolicyNV{
			NVIndex:   tpm2.NamedHandle{Name: counterName},
			OperandB:  tpm2.TPM2BOperand{Buffer: epochOperand(epoch)},
			Offset:    0,
			Operation: tpm2.TPMEOEq,
		})
}

// ApprovalDigest returns aHash = H(approvedPolicy || policyRef), the digest
// the authority signs and TPM2_PolicyAuthorize checks the ticket against
// (TCG TPM 2.0 Part 3, section 23.16). hashAlg is the authority's name
// algorithm.
func ApprovalDigest(hashAlg tpm2.TPMAlgID, approvedPolicy, policyRef []byte) ([]byte, error) {
	h, err := hashAlg.Hash()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPolicyDigestCompute, Cause: err}
	}
	hh := h.New()
	hh.Write(approvedPolicy)
	hh.Write(policyRef)
	return hh.Sum(nil), nil
}

// AuthorizedObjectPolicy returns the authPolicy of an object bound to the
// policy NV index whose Name is indexName, together with the branch digests
// a session names in TPM2_PolicyOR.
//
// Branch 1 is TPM2_PolicyAuthorizeNV(index). With withAuthValue, branch 2 is
// TPM2_PolicyAuthValue and authPolicy is their PolicyOR. Without it,
// authPolicy is branch 1 alone: an object with no auth value must not get a
// branch an empty password satisfies.
func AuthorizedObjectPolicy(
	hashAlg tpm2.TPMAlgID,
	indexName tpm2.TPM2BName,
	withAuthValue bool) (authPolicy []byte, branches [][]byte, err error) {

	if len(indexName.Buffer) == 0 {
		return nil, nil, &errs.Detail{Err: ErrPolicyDigestCompute, Detail: "empty policy index name"}
	}
	branch1, err := trialDigest(hashAlg, tpm2.PolicyAuthorizeNV{
		NVIndex: tpm2.NamedHandle{Name: indexName},
	})
	if err != nil {
		return nil, nil, err
	}
	if !withAuthValue {
		return branch1, [][]byte{branch1}, nil
	}
	branch2, err := trialDigest(hashAlg, tpm2.PolicyAuthValue{})
	if err != nil {
		return nil, nil, err
	}
	branches = [][]byte{branch1, branch2}
	authPolicy, err = trialDigest(hashAlg, policyOR(branches))
	if err != nil {
		return nil, nil, err
	}
	return authPolicy, branches, nil
}

// policyOR returns the TPM2_PolicyOR command over branches, for a trial
// calculator or, with PolicySession set, a live session.
func policyOR(branches [][]byte) tpm2.PolicyOr {
	digests := make([]tpm2.TPM2BDigest, len(branches))
	for i, b := range branches {
		digests[i] = tpm2.TPM2BDigest{Buffer: b}
	}
	return tpm2.PolicyOr{PHashList: tpm2.TPMLDigest{Digests: digests}}
}

// PolicyPCRSelection returns the TPML_PCR_SELECTION of pcrs in the bank
// hashAlg, as TPM2_PolicyPCR and TPM2_PCR_Read take it.
func PolicyPCRSelection(hashAlg tpm2.TPMAlgID, pcrs ...uint) tpm2.TPMLPCRSelection {
	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      hashAlg,
			PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
		}},
	}
}
