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

package transport

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// DefaultTPMPolicyBank is the PCR bank a pcr condition of a branch spec
// selects when it names none.
const DefaultTPMPolicyBank = "sha256"

// TPM policy branch spec errors.
var (
	// ErrTPMPolicyBranchEmpty is returned for a branch spec without a
	// condition.
	ErrTPMPolicyBranchEmpty = errors.New("transport: a TPM policy branch needs at least one condition")

	// ErrTPMPolicyConditionUnknown is returned for a condition other than
	// pcr, auth_value or locality.
	ErrTPMPolicyConditionUnknown = errors.New("transport: unknown TPM policy condition (want pcr, auth_value or locality)")

	// ErrTPMPolicyConditionValue is returned for a condition whose value is
	// missing, unexpected or not a list of indices.
	ErrTPMPolicyConditionValue = errors.New("transport: malformed TPM policy condition value")

	// ErrTPMPolicyNoSelection is returned by TPMPolicyBranches given
	// neither PCRs nor branch specs.
	ErrTPMPolicyNoSelection = errors.New("transport: a TPM policy needs a PCR selection or at least one branch")

	// ErrTPMPolicyPCRsAndBranches is returned by TPMPolicyBranches given a
	// PCR selection or bank together with branch specs.
	ErrTPMPolicyPCRsAndBranches = errors.New("transport: a PCR selection and bank cannot be combined with branches")
)

// TPMPolicyBranchSpecError reports the condition of a branch spec that could
// not be parsed.
type TPMPolicyBranchSpecError struct {
	// Condition is the condition as written.
	Condition string
	Err       error
}

// Error implements the error interface.
func (e *TPMPolicyBranchSpecError) Error() string {
	return fmt.Sprintf("%v: %q", e.Err, e.Condition)
}

// Unwrap returns the sentinel describing the fault.
func (e *TPMPolicyBranchSpecError) Unwrap() error { return e.Err }

// TPMPolicyPCRBranch returns a branch holding one pcr condition over pcrs of
// bank: the whole of a policy that approves one PCR state.
func TPMPolicyPCRBranch(bank string, pcrs []uint) TPMPolicyBranch {
	return TPMPolicyBranch{Conditions: []TPMPolicyCondition{{Type: TPMPolicyConditionPCR, Bank: bank, PCRs: pcrs}}}
}

// String returns the branch in branch-spec form, the form
// ParseTPMPolicyBranch reads: "pcr=sha256:0,7;auth_value;locality=0".
func (b TPMPolicyBranch) String() string {
	parts := make([]string, len(b.Conditions))
	for i, c := range b.Conditions {
		parts[i] = c.String()
	}
	return strings.Join(parts, ";")
}

// String returns the condition in branch-spec form.
func (c TPMPolicyCondition) String() string {
	switch c.Type {
	case TPMPolicyConditionPCR:
		return c.Type + "=" + c.Bank + ":" + formatIndexList(c.PCRs)
	case TPMPolicyConditionLocality:
		return c.Type + "=" + formatIndexList(c.Localities)
	default:
		return c.Type
	}
}

// formatIndexList formats indices as "0,7,9".
func formatIndexList(indices []uint) string {
	parts := make([]string, len(indices))
	for i, index := range indices {
		parts[i] = strconv.FormatUint(uint64(index), 10)
	}
	return strings.Join(parts, ",")
}

// TPMPolicyBranches returns the branches of a policy the command line
// describes in one of two ways: specs, each a branch spec
// ParseTPMPolicyBranch reads, or a PCR selection of bank
// (DefaultTPMPolicyBank when empty) -- the one-branch policy most callers
// want. Giving both, or neither, is refused.
func TPMPolicyBranches(bank string, pcrs []uint, specs []string) ([]TPMPolicyBranch, error) {
	switch {
	case len(specs) > 0 && (len(pcrs) > 0 || bank != ""):
		return nil, ErrTPMPolicyPCRsAndBranches
	case len(specs) == 0 && len(pcrs) == 0:
		return nil, ErrTPMPolicyNoSelection
	case len(specs) == 0:
		if bank == "" {
			bank = DefaultTPMPolicyBank
		}
		return []TPMPolicyBranch{TPMPolicyPCRBranch(bank, pcrs)}, nil
	}
	branches := make([]TPMPolicyBranch, 0, len(specs))
	for _, spec := range specs {
		branch, err := ParseTPMPolicyBranch(spec)
		if err != nil {
			return nil, err
		}
		branches = append(branches, branch)
	}
	return branches, nil
}

// conditionParsers parses the value of each condition of a branch spec;
// present reports whether the condition was written with "=".
var conditionParsers = map[string]func(value string, present bool) (TPMPolicyCondition, error){
	TPMPolicyConditionPCR:       parsePCRCondition,
	TPMPolicyConditionAuthValue: parseAuthValueCondition,
	TPMPolicyConditionLocality:  parseLocalityCondition,
}

// ParseTPMPolicyBranch parses a branch spec, the command-line form of one
// TPM policy branch: conditions separated by ";", each one of
//
//	pcr=[BANK:]LIST   the PCRs in LIST of BANK (sha256 when omitted)
//	auth_value        the object's password
//	locality=LIST     the TPM localities in LIST
//
// where LIST is comma-separated indices or ranges ("0,7" or "0-7"). For
// example "pcr=sha256:0,7;auth_value;locality=0". Only the syntax is checked
// here: the server validates banks, indices and duplicate conditions.
func ParseTPMPolicyBranch(spec string) (TPMPolicyBranch, error) {
	var branch TPMPolicyBranch
	for _, part := range strings.Split(spec, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, present := strings.Cut(part, "=")
		parse, ok := conditionParsers[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return TPMPolicyBranch{}, &TPMPolicyBranchSpecError{Condition: part, Err: ErrTPMPolicyConditionUnknown}
		}
		condition, err := parse(strings.TrimSpace(value), present)
		if err != nil {
			return TPMPolicyBranch{}, &TPMPolicyBranchSpecError{Condition: part, Err: err}
		}
		branch.Conditions = append(branch.Conditions, condition)
	}
	if len(branch.Conditions) == 0 {
		return TPMPolicyBranch{}, ErrTPMPolicyBranchEmpty
	}
	return branch, nil
}

// parsePCRCondition parses the "[BANK:]LIST" value of a pcr condition.
func parsePCRCondition(value string, present bool) (TPMPolicyCondition, error) {
	if !present || value == "" {
		return TPMPolicyCondition{}, ErrTPMPolicyConditionValue
	}
	bank, list, named := strings.Cut(value, ":")
	if !named {
		bank, list = DefaultTPMPolicyBank, value
	}
	pcrs, err := parseIndexList(list)
	if err != nil {
		return TPMPolicyCondition{}, err
	}
	return TPMPolicyCondition{Type: TPMPolicyConditionPCR, Bank: strings.ToLower(strings.TrimSpace(bank)), PCRs: pcrs}, nil
}

// parseAuthValueCondition parses an auth_value condition, which takes no
// value.
func parseAuthValueCondition(value string, present bool) (TPMPolicyCondition, error) {
	if present || value != "" {
		return TPMPolicyCondition{}, ErrTPMPolicyConditionValue
	}
	return TPMPolicyCondition{Type: TPMPolicyConditionAuthValue}, nil
}

// parseLocalityCondition parses the LIST value of a locality condition.
func parseLocalityCondition(value string, present bool) (TPMPolicyCondition, error) {
	if !present || value == "" {
		return TPMPolicyCondition{}, ErrTPMPolicyConditionValue
	}
	localities, err := parseIndexList(value)
	if err != nil {
		return TPMPolicyCondition{}, err
	}
	return TPMPolicyCondition{Type: TPMPolicyConditionLocality, Localities: localities}, nil
}

// parseIndexList parses comma-separated indices and ascending ranges
// ("0,7" or "0-7,9").
func parseIndexList(list string) ([]uint, error) {
	var out []uint
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		first, last, isRange := strings.Cut(item, "-")
		if !isRange {
			last = first
		}
		lo, err := strconv.ParseUint(strings.TrimSpace(first), 10, 8)
		if err != nil {
			return nil, ErrTPMPolicyConditionValue
		}
		hi, err := strconv.ParseUint(strings.TrimSpace(last), 10, 8)
		if err != nil || hi < lo {
			return nil, ErrTPMPolicyConditionValue
		}
		for i := lo; i <= hi; i++ {
			out = append(out, uint(i))
		}
	}
	return out, nil
}
