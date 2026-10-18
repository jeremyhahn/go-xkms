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
	"crypto/sha256"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/evidence"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/refvalue"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// UpdateBranch updates the policy's branch named branch from signed
// reference values rather than the live PCRs. corim is a COSE_Sign1 signed
// CoRIM that must verify under the configured reference signer at the
// service clock's time. The values of the branch's pcr condition become those
// attestation.PredictPCRs predicts the platform will hold once the images
// the CoRIM describes are booted, and the branch records the CoRIM as its
// Reference. Like UpdatePolicy, it then moves the scope's counter to its next
// epoch and re-signs every approved policy of the scope at it; the policy's
// other branches keep their values.
func (s *Service) UpdateBranch(ctx context.Context, tenant, name, branch string, corim []byte) (*Policy, error) {
	if s.referenceSigner == nil {
		return nil, ErrNoReferenceSigner
	}
	st, scope, p, unlock, err := s.lockPolicy(ctx, tenant, name)
	if err != nil {
		return nil, err
	}
	defer unlock()
	b := p.branch(branch)
	if b == nil {
		return nil, &InvalidBranchError{Branch: branch, Err: ErrNoSuchBranch}
	}
	c := branchPCRCondition(b)
	if c == nil {
		return nil, &InvalidBranchError{Branch: branch, Err: ErrNoPCRCondition}
	}
	opts := *s.referenceSigner
	opts.Now = s.clock()
	manifest, err := refvalue.VerifySigned(corim, opts)
	if err != nil {
		return nil, &ReferenceValuesError{Op: "verify the signed CoRIM", Err: err}
	}
	values, err := s.predictPCRs(st, c, manifest)
	if err != nil {
		return nil, err
	}
	c.PCRValues = values
	c.PCRDigest = pcrDigest(c.PCRs, values)
	digest := sha256.Sum256(corim)
	b.Reference = &Reference{
		ID:      manifest.ID,
		Profile: manifest.Profile,
		Signer:  manifest.Signer,
		Digest:  digest[:],
	}
	epoch, err := s.incrementCounter(st, scope)
	if err != nil {
		return nil, err
	}
	return s.resignAll(ctx, st, scope, epoch, p)
}

// branchPCRCondition returns b's pcr condition, or nil when it has none.
func branchPCRCondition(b *Branch) *Condition {
	for i := range b.Conditions {
		if b.Conditions[i].Type == ConditionPCR {
			return &b.Conditions[i]
		}
	}
	return nil
}

// predictPCRs predicts the values of c's PCRs from m, against the scope TPM's
// live values and, on the physical TPM, its boot event log. A vTPM has no
// boot event log, so only final PCR values can update its branches.
func (s *Service) predictPCRs(st *scopeState, c *Condition, m *refvalue.Manifest) (map[uint][]byte, error) {
	bank, err := pkgtpm2.ParsePCRBankAlgID(c.Bank)
	if err != nil {
		return nil, &InvalidPCRBankError{Bank: c.Bank}
	}
	live, err := readPCRs(st.tpm.TPM, st.name, c.Bank, c.PCRs)
	if err != nil {
		return nil, err
	}
	current := make(map[int][]byte, len(live))
	for pcr, value := range live {
		current[int(pcr)] = value
	}
	var log *evidence.EventLog
	var logErr error
	if st.tpm.TPM == s.tpm {
		if log, err = s.eventLog(); err != nil {
			logErr = &TPMError{Scope: st.name, Op: "read the boot event log", Err: err}
		}
	}
	predicted, err := attestation.PredictPCRs(log, m, bank, current)
	if err != nil {
		return nil, &ReferenceValuesError{Op: "predict PCR values", Err: errors.Join(err, logErr)}
	}
	out := make(map[uint][]byte, len(predicted))
	for pcr, value := range predicted {
		out[uint(pcr)] = value
	}
	return out, nil
}

// kernelEventLog parses the boot event log the kernel exposes for the
// physical TPM.
func (s *Service) kernelEventLog() (*evidence.EventLog, error) {
	raw, err := s.tpm.EventLog()
	if err != nil {
		return nil, err
	}
	return evidence.ParseEventLog(raw)
}
