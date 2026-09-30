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

package tpmpolicy

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"strings"

	"github.com/google/go-tpm/tpm2"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

const (
	// maxLocality is the highest locality a locality condition may allow.
	maxLocality = 4

	// maxDescription bounds a policy description, in bytes.
	maxDescription = 4096
)

// conditionSpec is what the service does with one condition type: normalize
// validates a requested condition and returns its stored form, capture reads
// the values it captures from the live TPM (nil when it captures nothing),
// and branch converts it to the pkg/tpm2 condition a trial digest and a
// policy session assert.
type conditionSpec struct {
	normalize func(c Condition) (Condition, error)
	capture   func(t *pkgtpm2.TPM2, scope string, c *Condition) error
	branch    func(c Condition) (pkgtpm2.PolicyCondition, error)
}

// conditionSpecs dispatches on the condition type.
var conditionSpecs = map[ConditionType]conditionSpec{
	ConditionPCR:       {normalize: normalizePCR, capture: capturePCR, branch: pcrCondition},
	ConditionAuthValue: {normalize: normalizeAuthValue, branch: authValueCondition},
	ConditionLocality:  {normalize: normalizeLocality, branch: localityCondition},
}

// conditionOperand is one requested operand of a condition, and whether it
// is set.
type conditionOperand struct {
	name string
	set  bool
}

// operands lists c's requested operands in a fixed order.
func (c Condition) operands() []conditionOperand {
	return []conditionOperand{
		{name: "bank", set: c.Bank != ""},
		{name: "pcrs", set: len(c.PCRs) > 0},
		{name: "localities", set: len(c.Localities) > 0},
	}
}

// refuseOperands refuses a condition that sets an operand outside allowed.
func refuseOperands(c Condition, allowed ...string) error {
	for _, op := range c.operands() {
		if op.set && !slices.Contains(allowed, op.name) {
			return &ConditionOperandError{Type: c.Type, Operand: op.name}
		}
	}
	return nil
}

// validateBranches validates requested branches and returns them in stored
// form: every condition normalized, nothing captured yet.
func validateBranches(branches []Branch) ([]Branch, error) {
	if len(branches) == 0 {
		return nil, ErrNoBranches
	}
	out := make([]Branch, len(branches))
	for i, b := range branches {
		conditions, err := validateConditions(b.Conditions)
		if err != nil {
			return nil, &InvalidBranchError{Branch: i, Err: err}
		}
		out[i] = Branch{Conditions: conditions}
	}
	return out, nil
}

// validateConditions validates one branch's conditions: at least one, at
// most one of each type, each valid for its type.
func validateConditions(conditions []Condition) ([]Condition, error) {
	if len(conditions) == 0 {
		return nil, ErrEmptyBranch
	}
	seen := make(map[ConditionType]bool, len(conditions))
	out := make([]Condition, len(conditions))
	for i, c := range conditions {
		spec, ok := conditionSpecs[c.Type]
		if !ok {
			return nil, &UnknownConditionTypeError{Type: c.Type}
		}
		if seen[c.Type] {
			return nil, &DuplicateConditionError{Type: c.Type}
		}
		seen[c.Type] = true
		if len(c.PCRValues) > 0 || len(c.PCRDigest) > 0 {
			return nil, ErrPCRValuesSupplied
		}
		normalized, err := spec.normalize(c)
		if err != nil {
			return nil, err
		}
		out[i] = normalized
	}
	return out, nil
}

// validateDescription refuses a description longer than maxDescription.
func validateDescription(description string) error {
	if len(description) > maxDescription {
		return &DescriptionTooLongError{Length: len(description), Max: maxDescription}
	}
	return nil
}

// capture reads the live values of every condition of p that captures any
// from the scope's TPM. The values are never supplied by a caller.
func capture(t *pkgtpm2.TPM2, scope string, p *Policy) error {
	for i := range p.Branches {
		conditions := p.Branches[i].Conditions
		for j := range conditions {
			spec, ok := conditionSpecs[conditions[j].Type]
			if !ok {
				return &UnknownConditionTypeError{Type: conditions[j].Type}
			}
			if spec.capture == nil {
				continue
			}
			if err := spec.capture(t, scope, &conditions[j]); err != nil {
				return err
			}
		}
	}
	return nil
}

// tpmBranch converts a stored branch to the pkg/tpm2 branch its approval
// covers.
func tpmBranch(b Branch) (pkgtpm2.PolicyBranch, error) {
	out := pkgtpm2.PolicyBranch{Conditions: make([]pkgtpm2.PolicyCondition, 0, len(b.Conditions))}
	for _, c := range b.Conditions {
		spec, ok := conditionSpecs[c.Type]
		if !ok {
			return pkgtpm2.PolicyBranch{}, &UnknownConditionTypeError{Type: c.Type}
		}
		converted, err := spec.branch(c)
		if err != nil {
			return pkgtpm2.PolicyBranch{}, err
		}
		out.Conditions = append(out.Conditions, converted)
	}
	return out, nil
}

// normalizePCR validates a pcr condition: a known bank and a non-empty set
// of PCRs 0 through 23, stored lower-case and ascending.
func normalizePCR(c Condition) (Condition, error) {
	if err := refuseOperands(c, "bank", "pcrs"); err != nil {
		return Condition{}, err
	}
	bank, _, pcrs, err := validateSelection(c.Bank, c.PCRs)
	if err != nil {
		return Condition{}, err
	}
	return Condition{Type: ConditionPCR, Bank: bank, PCRs: pcrs}, nil
}

// capturePCR reads c's PCRs from t into c.PCRValues and c.PCRDigest.
func capturePCR(t *pkgtpm2.TPM2, scope string, c *Condition) error {
	values, err := readPCRs(t, scope, c.Bank, c.PCRs)
	if err != nil {
		return err
	}
	c.PCRValues = values
	c.PCRDigest = pcrDigest(c.PCRs, values)
	return nil
}

// pcrCondition converts a captured pcr condition.
func pcrCondition(c Condition) (pkgtpm2.PolicyCondition, error) {
	bankAlg, err := pkgtpm2.ParsePCRBankAlgID(c.Bank)
	if err != nil {
		return pkgtpm2.PolicyCondition{}, &InvalidPCRBankError{Bank: c.Bank}
	}
	return pkgtpm2.PolicyCondition{
		Type:         pkgtpm2.PolicyConditionPCR,
		PCRSelection: pkgtpm2.PolicyPCRSelection(bankAlg, c.PCRs...),
		PCRDigest:    c.PCRDigest,
	}, nil
}

// normalizeAuthValue validates an auth_value condition, which takes no
// operand.
func normalizeAuthValue(c Condition) (Condition, error) {
	if err := refuseOperands(c); err != nil {
		return Condition{}, err
	}
	return Condition{Type: ConditionAuthValue}, nil
}

// authValueCondition converts an auth_value condition.
func authValueCondition(Condition) (pkgtpm2.PolicyCondition, error) {
	return pkgtpm2.PolicyCondition{Type: pkgtpm2.PolicyConditionAuthValue}, nil
}

// normalizeLocality validates a locality condition: a non-empty set of
// localities 0 through 4, stored ascending.
func normalizeLocality(c Condition) (Condition, error) {
	if err := refuseOperands(c, "localities"); err != nil {
		return Condition{}, err
	}
	if len(c.Localities) == 0 {
		return Condition{}, ErrEmptyLocalitySelection
	}
	sorted := slices.Clone(c.Localities)
	slices.Sort(sorted)
	for i, l := range sorted {
		if l > maxLocality {
			return Condition{}, &InvalidLocalityError{Locality: l}
		}
		if i > 0 && sorted[i-1] == l {
			return Condition{}, &InvalidLocalityError{Locality: l, Duplicate: true}
		}
	}
	return Condition{Type: ConditionLocality, Localities: sorted}, nil
}

// localityCondition converts a locality condition.
func localityCondition(c Condition) (pkgtpm2.PolicyCondition, error) {
	locality, err := pkgtpm2.PolicyLocalitySelection(c.Localities...)
	if err != nil {
		return pkgtpm2.PolicyCondition{}, err
	}
	return pkgtpm2.PolicyCondition{Type: pkgtpm2.PolicyConditionLocality, Locality: locality}, nil
}

// validateSelection normalizes a PCR bank and selection: the bank must be
// sha1, sha256, sha384 or sha512 and the PCRs a non-empty set of indices 0
// through 23. It returns the lower-case bank, its algorithm and the PCRs in
// ascending order.
func validateSelection(bank string, pcrs []uint) (string, tpm2.TPMAlgID, []uint, error) {
	bank = strings.ToLower(bank)
	alg, err := pkgtpm2.ParsePCRBankAlgID(bank)
	if err != nil {
		return "", 0, nil, &InvalidPCRBankError{Bank: bank}
	}
	if len(pcrs) == 0 {
		return "", 0, nil, ErrEmptyPCRSelection
	}
	sorted := slices.Clone(pcrs)
	slices.Sort(sorted)
	for i, pcr := range sorted {
		if pcr > maxPCR {
			return "", 0, nil, &InvalidPCRError{PCR: pcr}
		}
		if i > 0 && sorted[i-1] == pcr {
			return "", 0, nil, &InvalidPCRError{PCR: pcr, Duplicate: true}
		}
	}
	return bank, alg, sorted, nil
}

// readPCRs reads the live values of pcrs in bank from t.
func readPCRs(t *pkgtpm2.TPM2, scope, bank string, pcrs []uint) (map[uint][]byte, error) {
	banks, err := t.ReadPCRs(pcrs)
	if err != nil {
		return nil, &TPMError{Scope: scope, Op: "read PCRs", Err: err}
	}
	for _, b := range banks {
		if !strings.EqualFold(b.Algorithm, bank) {
			continue
		}
		values := make(map[uint][]byte, len(b.PCRs))
		for _, pcr := range b.PCRs {
			values[uint(pcr.ID)] = pcr.Value
		}
		if len(values) == len(pcrs) {
			return values, nil
		}
	}
	return nil, &PCRBankUnavailableError{Bank: bank}
}

// pcrDigest returns the TPM2_PolicyPCR pcrDigest operand of values: the
// session's hash (policyHashAlg) over the selected values concatenated in
// ascending PCR order (TCG TPM 2.0 Part 3, section 23.7). It is the session
// hash, not the bank's, whichever bank the values come from.
func pcrDigest(pcrs []uint, values map[uint][]byte) []byte {
	h := sha256.New()
	for _, pcr := range pcrs {
		h.Write(values[pcr])
	}
	return h.Sum(nil)
}

// verifyBranch compares b's pcr condition, if it has one, with the live PCRs
// of t.
func verifyBranch(t *pkgtpm2.TPM2, scope string, b Branch) (BranchVerification, error) {
	v := BranchVerification{Match: true}
	for _, c := range b.Conditions {
		if c.Type != ConditionPCR {
			continue
		}
		live, err := readPCRs(t, scope, c.Bank, c.PCRs)
		if err != nil {
			return BranchVerification{}, err
		}
		for _, pcr := range c.PCRs {
			if !bytes.Equal(live[pcr], c.PCRValues[pcr]) {
				v.Mismatched = append(v.Mismatched, pcr)
			}
		}
	}
	v.Match = len(v.Mismatched) == 0
	return v, nil
}
