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
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateBranches_Normalizes proves valid branches are stored in
// normal form: banks lower-case, PCRs and localities ascending, and a
// password-only branch allowed.
func TestValidateBranches_Normalizes(t *testing.T) {
	got, err := validateBranches([]Branch{
		{Conditions: []Condition{
			{Type: ConditionAuthValue},
			{Type: ConditionPCR, Bank: "SHA256", PCRs: []uint{23, 7}},
			{Type: ConditionLocality, Localities: []uint{3, 0}},
		}},
		authValueBranch(),
	})
	require.NoError(t, err)
	assert.Equal(t, []Branch{
		{Conditions: []Condition{
			{Type: ConditionAuthValue},
			{Type: ConditionPCR, Bank: "sha256", PCRs: []uint{7, 23}},
			{Type: ConditionLocality, Localities: []uint{0, 3}},
		}},
		authValueBranch(),
	}, got)
}

// TestValidateBranches_Refusals proves every invalid structure is refused
// with its typed error, naming the branch it is in.
func TestValidateBranches_Refusals(t *testing.T) {
	var (
		badBank   *InvalidPCRBankError
		badPCR    *InvalidPCRError
		badLoc    *InvalidLocalityError
		unknown   *UnknownConditionTypeError
		duplicate *DuplicateConditionError
		operand   *ConditionOperandError
	)
	for _, tc := range []struct {
		name  string
		cond  Condition
		extra *Condition
		check func(error) bool
	}{
		{"unknown type", Condition{Type: "time"}, nil, func(err error) bool { return errors.As(err, &unknown) }},
		{"duplicate pcr", Condition{Type: ConditionPCR, Bank: "sha256", PCRs: []uint{7}},
			&Condition{Type: ConditionPCR, Bank: "sha1", PCRs: []uint{7}}, func(err error) bool { return errors.As(err, &duplicate) }},
		{"duplicate auth_value", Condition{Type: ConditionAuthValue},
			&Condition{Type: ConditionAuthValue}, func(err error) bool { return errors.As(err, &duplicate) }},
		{"duplicate locality", Condition{Type: ConditionLocality, Localities: []uint{0}},
			&Condition{Type: ConditionLocality, Localities: []uint{1}}, func(err error) bool { return errors.As(err, &duplicate) }},
		{"bad bank", Condition{Type: ConditionPCR, Bank: "sm3", PCRs: []uint{7}}, nil, func(err error) bool { return errors.As(err, &badBank) }},
		{"no PCRs", Condition{Type: ConditionPCR, Bank: "sha256"}, nil, func(err error) bool { return errors.Is(err, ErrEmptyPCRSelection) }},
		{"PCR 24", Condition{Type: ConditionPCR, Bank: "sha256", PCRs: []uint{24}}, nil, func(err error) bool { return errors.As(err, &badPCR) }},
		{"supplied values", Condition{Type: ConditionPCR, Bank: "sha256", PCRs: []uint{7}, PCRValues: map[uint][]byte{7: {1}}}, nil,
			func(err error) bool { return errors.Is(err, ErrPCRValuesSupplied) }},
		{"supplied digest", Condition{Type: ConditionPCR, Bank: "sha256", PCRs: []uint{7}, PCRDigest: []byte{1}}, nil,
			func(err error) bool { return errors.Is(err, ErrPCRValuesSupplied) }},
		{"pcr with localities", Condition{Type: ConditionPCR, Bank: "sha256", PCRs: []uint{7}, Localities: []uint{0}}, nil,
			func(err error) bool { return errors.As(err, &operand) && operand.Operand == "localities" }},
		{"auth_value with bank", Condition{Type: ConditionAuthValue, Bank: "sha256"}, nil,
			func(err error) bool { return errors.As(err, &operand) && operand.Operand == "bank" }},
		{"locality with pcrs", Condition{Type: ConditionLocality, Localities: []uint{0}, PCRs: []uint{7}}, nil,
			func(err error) bool { return errors.As(err, &operand) && operand.Operand == "pcrs" }},
		{"no localities", Condition{Type: ConditionLocality}, nil, func(err error) bool { return errors.Is(err, ErrEmptyLocalitySelection) }},
		{"locality 5", Condition{Type: ConditionLocality, Localities: []uint{5}}, nil,
			func(err error) bool { return errors.As(err, &badLoc) && !badLoc.Duplicate }},
		{"locality twice", Condition{Type: ConditionLocality, Localities: []uint{2, 2}}, nil,
			func(err error) bool { return errors.As(err, &badLoc) && badLoc.Duplicate }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conditions := []Condition{tc.cond}
			if tc.extra != nil {
				conditions = append(conditions, *tc.extra)
			}
			_, err := validateBranches([]Branch{pcrBranch(), {Conditions: conditions}})
			var branchErr *InvalidBranchError
			require.ErrorAs(t, err, &branchErr)
			assert.Equal(t, 1, branchErr.Branch)
			assert.True(t, tc.check(err), "got %v", err)
		})
	}

	_, err := validateBranches(nil)
	require.ErrorIs(t, err, ErrNoBranches)
	_, err = validateBranches([]Branch{{}})
	require.ErrorIs(t, err, ErrEmptyBranch)
}

// TestCreatePolicyRequest_Branches proves the deprecated Bank and PCRs mean
// one branch holding one pcr condition, and are refused beside Branches.
func TestCreatePolicyRequest_Branches(t *testing.T) {
	got, err := CreatePolicyRequest{Bank: "sha256", PCRs: []uint{7}}.branches()
	require.NoError(t, err)
	assert.Equal(t, []Branch{{Conditions: []Condition{{Type: ConditionPCR, Bank: "sha256", PCRs: []uint{7}}}}}, got)

	got, err = CreatePolicyRequest{Branches: []Branch{authValueBranch()}}.branches()
	require.NoError(t, err)
	assert.Equal(t, []Branch{authValueBranch()}, got)

	_, err = CreatePolicyRequest{Bank: "sha256", Branches: []Branch{authValueBranch()}}.branches()
	require.ErrorIs(t, err, ErrAmbiguousPolicyRequest)
}

// TestTPMBranch_Converts proves stored conditions become the pkg/tpm2
// conditions their approvals cover, and a corrupt stored record is refused.
func TestTPMBranch_Converts(t *testing.T) {
	got, err := tpmBranch(Branch{Conditions: []Condition{
		{Type: ConditionPCR, Bank: "sha1", PCRs: []uint{7}, PCRDigest: []byte{1}},
		{Type: ConditionLocality, Localities: []uint{0, 4}},
		{Type: ConditionAuthValue},
	}})
	require.NoError(t, err)
	require.Len(t, got.Conditions, 3)
	assert.Equal(t, pkgtpm2.PolicyPCRSelection(tpm2.TPMAlgSHA1, 7), got.Conditions[0].PCRSelection)
	assert.True(t, got.Conditions[1].Locality.TPMLocFour)
	assert.Equal(t, pkgtpm2.PolicyConditionAuthValue, got.Conditions[2].Type)

	var unknown *UnknownConditionTypeError
	_, err = tpmBranch(Branch{Conditions: []Condition{{Type: "time"}}})
	require.ErrorAs(t, err, &unknown)
	var badBank *InvalidPCRBankError
	_, err = tpmBranch(Branch{Conditions: []Condition{{Type: ConditionPCR, Bank: "sm3"}}})
	require.ErrorAs(t, err, &badBank)
	_, err = tpmBranch(Branch{Conditions: []Condition{{Type: ConditionLocality, Localities: []uint{9}}}})
	require.ErrorIs(t, err, pkgtpm2.ErrInvalidPolicyLocality)
}

// TestPolicy_LegacyView proves the deprecated single-branch fields show the
// first pcr condition and the first approval, and nothing once revoked or
// when the policy has no pcr condition.
func TestPolicy_LegacyView(t *testing.T) {
	pcr := pcrBranch()
	pcr.Conditions[0].PCRValues = map[uint][]byte{testPCR: {1}}
	pcr.Conditions[0].PCRDigest = []byte{2}
	p := &Policy{
		Branches:  []Branch{authValueBranch(), pcr},
		Approvals: []*Approval{{Epoch: 3}, {Epoch: 3}},
	}
	p.syncLegacyView()
	assert.Equal(t, "sha256", p.Bank)
	assert.Equal(t, []uint{testPCR}, p.PCRs)
	assert.Equal(t, []byte{2}, p.PCRDigest)
	assert.Equal(t, uint64(3), p.Approval.Epoch)
	assert.True(t, p.hasAuthValueCondition())

	p.revoke()
	p.Branches = []Branch{authValueBranch()}
	p.Approvals = p.Approvals[:1]
	p.syncLegacyView()
	assert.Nil(t, p.Approval)
	assert.Empty(t, p.Bank)
	assert.Nil(t, p.PCRs)
}

// TestPolicy_Approved proves a policy is approved only when every branch
// holds an approval.
func TestPolicy_Approved(t *testing.T) {
	two := []Branch{pcrBranch(), authValueBranch()}
	assert.True(t, (&Policy{Branches: two, Approvals: []*Approval{{}, {}}}).approved())
	assert.False(t, (&Policy{Branches: two, Approvals: []*Approval{{}, nil}}).approved())
	assert.False(t, (&Policy{Branches: two, Approvals: []*Approval{{}}}).approved())
	assert.False(t, (&Policy{}).approved())
	assert.False(t, (&Policy{Branches: []Branch{pcrBranch()}}).hasAuthValueCondition())
}

// TestService_CreateAndDescriptionValidation proves requests are validated
// before any TPM or registry work: a bad structure, an ambiguous request and
// an oversized description are refused, and SetDescription refuses an
// oversized description and an unknown policy.
func TestService_CreateAndDescriptionValidation(t *testing.T) {
	svc, _ := newOfflineService(t)
	ctx := context.Background()

	_, err := svc.CreatePolicy(ctx, "acme", CreatePolicyRequest{Name: "boot"})
	require.ErrorIs(t, err, ErrNoBranches)
	_, err = svc.CreatePolicy(ctx, "acme", CreatePolicyRequest{Name: "boot", Bank: "sha256", PCRs: []uint{7}, Branches: []Branch{pcrBranch()}})
	require.ErrorIs(t, err, ErrAmbiguousPolicyRequest)
	long := strings.Repeat("d", maxDescription+1)
	var tooLong *DescriptionTooLongError
	_, err = svc.CreatePolicy(ctx, "acme", CreatePolicyRequest{Name: "boot", Description: long, Branches: []Branch{pcrBranch()}})
	require.ErrorAs(t, err, &tooLong)
	assert.Equal(t, maxDescription+1, tooLong.Length)

	_, err = svc.SetDescription(ctx, "acme", "boot", long)
	require.ErrorAs(t, err, &tooLong)
	_, err = svc.SetDescription(ctx, "acme", PlatformPolicy, "x")
	require.ErrorIs(t, err, ErrReservedPolicy)
}
