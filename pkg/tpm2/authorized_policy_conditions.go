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
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// PolicyConditionType identifies one kind of assertion a named policy's
// branch can require. The constants are declared in canonical order: a
// branch's assertions always run in this order, in a trial digest and in a
// live session alike, so the two reach the same digest whatever order the
// conditions were listed in.
type PolicyConditionType uint8

const (
	// PolicyConditionLocality is TPM2_PolicyLocality: the command must come
	// from one of the allowed localities.
	PolicyConditionLocality PolicyConditionType = iota + 1

	// PolicyConditionPCR is TPM2_PolicyPCR: the selected PCRs must hold the
	// approved values.
	PolicyConditionPCR

	// PolicyConditionAuthValue is TPM2_PolicyAuthValue: the object's auth
	// value must be presented.
	PolicyConditionAuthValue
)

// maxPolicyLocality is the highest locality TPM2_PolicyLocality selects with
// a bit of TPMA_LOCALITY; higher values are extended localities.
const maxPolicyLocality = 4

// PolicyCondition is one assertion of a policy branch. Only the operands of
// its Type are meaningful.
type PolicyCondition struct {
	Type PolicyConditionType

	// Locality is the TPMA_LOCALITY of a locality condition.
	Locality tpm2.TPMALocality

	// PCRSelection and PCRDigest are the TPM2_PolicyPCR operands of a PCR
	// condition.
	PCRSelection tpm2.TPMLPCRSelection
	PCRDigest    []byte
}

// PolicyBranch is one branch of a named policy: the AND of its conditions.
type PolicyBranch struct {
	Conditions []PolicyCondition
}

// HasAuthValue reports whether the branch has an auth_value condition, so a
// session redeeming it must prove the object's auth value.
func (b PolicyBranch) HasAuthValue() bool {
	return slices.ContainsFunc(b.Conditions, func(c PolicyCondition) bool {
		return c.Type == PolicyConditionAuthValue
	})
}

// canonical returns the branch's conditions in canonical order, refusing an
// empty branch and a condition of an unknown type.
func (b PolicyBranch) canonical() ([]PolicyCondition, error) {
	if len(b.Conditions) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidPolicyBranch, Detail: "no conditions"}
	}
	for _, c := range b.Conditions {
		if _, ok := conditionHandlers[c.Type]; !ok {
			return nil, &errs.Detail{Err: ErrInvalidPolicyBranch, Detail: fmt.Sprintf("unknown condition type %d", c.Type)}
		}
	}
	sorted := slices.Clone(b.Conditions)
	slices.SortStableFunc(sorted, func(x, y PolicyCondition) int { return int(x.Type) - int(y.Type) })
	return sorted, nil
}

// trialCommands returns the trial policy commands of the branch's
// assertions, in canonical order.
func (b PolicyBranch) trialCommands() ([]tpm2.PolicyCommand, error) {
	conditions, err := b.canonical()
	if err != nil {
		return nil, err
	}
	cmds := make([]tpm2.PolicyCommand, 0, len(conditions)+1)
	for _, c := range conditions {
		cmd, err := conditionHandlers[c.Type].trial(c)
		if err != nil {
			return nil, err
		}
		cmds = append(cmds, cmd)
	}
	return cmds, nil
}

// branchRef names the branch an assertion belongs to, for its typed errors.
type branchRef struct {
	scope  string
	policy string
	branch int
}

// conditionHandler builds one condition type's assertion: trial returns the
// command a trial calculator folds into the approved digest, and assert runs
// the same assertion in a live policy session, turning a refusal into the
// type's error.
type conditionHandler struct {
	trial  func(c PolicyCondition) (tpm2.PolicyCommand, error)
	assert func(tpm *TPM2, session tpm2.Session, c PolicyCondition, ref branchRef) error
}

// conditionHandlers dispatches on the condition type.
var conditionHandlers = map[PolicyConditionType]conditionHandler{
	PolicyConditionLocality:  {trial: localityTrial, assert: assertLocality},
	PolicyConditionPCR:       {trial: pcrTrial, assert: assertPCR},
	PolicyConditionAuthValue: {trial: authValueTrial, assert: assertAuthValue},
}

// assertBranch runs the branch's assertions in canonical order in session.
func (tpm *TPM2) assertBranch(session tpm2.Session, branch PolicyBranch, ref branchRef) error {
	conditions, err := branch.canonical()
	if err != nil {
		return err
	}
	for _, c := range conditions {
		if err := conditionHandlers[c.Type].assert(tpm, session, c, ref); err != nil {
			return err
		}
	}
	return nil
}

// localityTrial returns the TPM2_PolicyLocality trial command of c.
func localityTrial(c PolicyCondition) (tpm2.PolicyCommand, error) {
	bits := localityBits(c.Locality)
	if bits == 0 || bits>>(maxPolicyLocality+1) != 0 {
		return nil, &errs.Detail{Err: ErrInvalidPolicyBranch, Detail: fmt.Sprintf("locality condition TPMA_LOCALITY 0x%02x", bits)}
	}
	return policyLocality{Locality: c.Locality}, nil
}

// assertLocality runs TPM2_PolicyLocality in session. The TPM checks it only
// when the session authorizes a command, so a branch that does not allow
// commandLocality is refused here, before the session is spent on it.
func assertLocality(tpm *TPM2, session tpm2.Session, c PolicyCondition, ref branchRef) error {
	if localityBits(c.Locality)&(1<<commandLocality) == 0 {
		return &PolicyLocalityMismatchError{
			Scope:    ref.scope,
			Policy:   ref.policy,
			Branch:   ref.branch,
			Locality: commandLocality,
			Allowed:  c.Locality,
		}
	}
	return policyLocality{PolicySession: session.Handle(), Locality: c.Locality}.Execute(tpm.transport)
}

// pcrTrial returns the TPM2_PolicyPCR trial command of c.
func pcrTrial(c PolicyCondition) (tpm2.PolicyCommand, error) {
	if len(c.PCRSelection.PCRSelections) == 0 || len(c.PCRDigest) == 0 {
		return nil, &errs.Detail{Err: ErrInvalidPolicyBranch, Detail: "PCR condition without a selection or digest"}
	}
	return tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{Buffer: c.PCRDigest},
		Pcrs:      c.PCRSelection,
	}, nil
}

// assertPCR runs TPM2_PolicyPCR in session. The TPM refuses it with
// TPM_RC_VALUE once the live PCRs differ from the approved ones.
func assertPCR(tpm *TPM2, session tpm2.Session, c PolicyCondition, ref branchRef) error {
	_, err := tpm2.PolicyPCR{
		PolicySession: session.Handle(),
		PcrDigest:     tpm2.TPM2BDigest{Buffer: c.PCRDigest},
		Pcrs:          c.PCRSelection,
	}.Execute(tpm.transport)
	if errors.Is(err, tpm2.TPMRCValue) {
		return &PolicyPCRMismatchError{Scope: ref.scope, Policy: ref.policy, Branch: ref.branch, Err: err}
	}
	return err
}

// authValueTrial returns the TPM2_PolicyAuthValue trial command.
func authValueTrial(PolicyCondition) (tpm2.PolicyCommand, error) {
	return tpm2.PolicyAuthValue{}, nil
}

// assertAuthValue runs TPM2_PolicyAuthValue in session. The TPM checks the
// auth value when the session authorizes a command, through the session's
// HMAC, which is why the session must carry it (see startPolicySession).
func assertAuthValue(tpm *TPM2, session tpm2.Session, _ PolicyCondition, _ branchRef) error {
	_, err := tpm2.PolicyAuthValue{PolicySession: session.Handle()}.Execute(tpm.transport)
	return err
}

// PolicyLocalitySelection returns the TPMA_LOCALITY that allows localities,
// each 0 through 4.
func PolicyLocalitySelection(localities ...uint) (tpm2.TPMALocality, error) {
	var bits uint8
	for _, l := range localities {
		if l > maxPolicyLocality {
			return tpm2.TPMALocality{}, &errs.Detail{Err: ErrInvalidPolicyLocality, Detail: fmt.Sprintf("%d", l)}
		}
		bits |= 1 << l
	}
	if bits == 0 {
		return tpm2.TPMALocality{}, &errs.Detail{Err: ErrInvalidPolicyLocality, Detail: "no locality"}
	}
	locality, err := tpm2.Unmarshal[tpm2.TPMALocality]([]byte{bits})
	if err != nil {
		return tpm2.TPMALocality{}, &errs.Joined{Lead: ErrInvalidPolicyLocality, Cause: err}
	}
	return *locality, nil
}

// localityBits returns the TPMA_LOCALITY octet of l.
func localityBits(l tpm2.TPMALocality) uint8 {
	return tpm2.Marshal(l)[0]
}

// policyLocality is TPM2_PolicyLocality (TCG TPM 2.0 Part 3, section 23.4),
// which go-tpm v0.9.8 names a command code for but does not implement.
type policyLocality struct {
	PolicySession tpm2.TPMHandle
	Locality      tpm2.TPMALocality
}

// Update implements tpm2.PolicyCommand:
// policyDigest' = H(policyDigest || TPM_CC_PolicyLocality || locality).
func (cmd policyLocality) Update(policy *tpm2.PolicyCalculator) error {
	return policy.Update(tpm2.TPMCCPolicyLocality, cmd.Locality)
}

// Execute sends the command. It takes no authorization: its only handle is
// the policy session, which is a parameter rather than an authorization.
func (cmd policyLocality) Execute(t transport.TPM) error {
	locality := tpm2.Marshal(cmd.Locality)
	size := tpmHeaderSize + 4 + len(locality)
	buf := make([]byte, 0, size)
	buf = binary.BigEndian.AppendUint16(buf, tpmSTNoSessions)
	buf = binary.BigEndian.AppendUint32(buf, uint32(size)) // #nosec G115 -- a fixed 15 octets
	buf = binary.BigEndian.AppendUint32(buf, uint32(tpm2.TPMCCPolicyLocality))
	buf = binary.BigEndian.AppendUint32(buf, uint32(cmd.PolicySession))
	buf = append(buf, locality...)

	rsp, err := t.Send(buf)
	if err != nil {
		return &errs.Wrapped{Msg: "PolicyLocality: send", Err: err}
	}
	if len(rsp) < tpmHeaderSize {
		return &errs.Message{Msg: fmt.Sprintf("PolicyLocality: response too short: %d bytes", len(rsp))}
	}
	if code := binary.BigEndian.Uint32(rsp[6:10]); code != 0 {
		return tpm2.TPMRC(code)
	}
	return nil
}
