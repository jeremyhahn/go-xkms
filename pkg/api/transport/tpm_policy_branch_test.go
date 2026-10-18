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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseTPMPolicyBranch parses the branch specs the CLIs accept: every
// condition type, a default bank, ranges, case and whitespace.
func TestParseTPMPolicyBranch(t *testing.T) {
	tests := []struct {
		spec string
		want TPMPolicyBranch
	}{
		{"pcr=sha256:0,7;auth_value;locality=0", TPMPolicyBranch{Conditions: []TPMPolicyCondition{
			{Type: TPMPolicyConditionPCR, Bank: "sha256", PCRs: []uint{0, 7}},
			{Type: TPMPolicyConditionAuthValue},
			{Type: TPMPolicyConditionLocality, Localities: []uint{0}},
		}}},
		{"pcr=0-2,7", TPMPolicyPCRBranch(DefaultTPMPolicyBank, []uint{0, 1, 2, 7})},
		{" PCR = SHA384:7 ; ", TPMPolicyPCRBranch("sha384", []uint{7})},
		{"auth_value", TPMPolicyBranch{Conditions: []TPMPolicyCondition{{Type: TPMPolicyConditionAuthValue}}}},
		{"locality=0,3-4", TPMPolicyBranch{Conditions: []TPMPolicyCondition{{Type: TPMPolicyConditionLocality, Localities: []uint{0, 3, 4}}}}},
		{"name=next;pcr=0,7", TPMPolicyBranch{Name: "next", Conditions: TPMPolicyPCRBranch(DefaultTPMPolicyBank, []uint{0, 7}).Conditions}},
		{"auth_value; Name = current ", TPMPolicyBranch{Name: "current", Conditions: []TPMPolicyCondition{{Type: TPMPolicyConditionAuthValue}}}},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			got, err := ParseTPMPolicyBranch(tt.spec)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestParseTPMPolicyBranch_Errors refuses malformed specs with the typed
// error naming the offending condition.
func TestParseTPMPolicyBranch_Errors(t *testing.T) {
	tests := []struct {
		spec      string
		want      error
		condition string
	}{
		{"time=5", ErrTPMPolicyConditionUnknown, "time=5"},
		{"pcr", ErrTPMPolicyConditionValue, "pcr"},
		{"pcr=sha256:", ErrTPMPolicyConditionValue, "pcr=sha256:"},
		{"pcr=sha256:x", ErrTPMPolicyConditionValue, "pcr=sha256:x"},
		{"pcr=7-3", ErrTPMPolicyConditionValue, "pcr=7-3"},
		{"auth_value=secret", ErrTPMPolicyConditionValue, "auth_value=secret"},
		{"auth_value=", ErrTPMPolicyConditionValue, "auth_value="},
		{"locality", ErrTPMPolicyConditionValue, "locality"},
		{"locality=-1", ErrTPMPolicyConditionValue, "locality=-1"},
		{"name;pcr=7", ErrTPMPolicyBranchName, "name"},
		{"name=;pcr=7", ErrTPMPolicyBranchName, "name="},
		{"name=a;name=b;pcr=7", ErrTPMPolicyBranchName, "name=b"},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			_, err := ParseTPMPolicyBranch(tt.spec)
			require.ErrorIs(t, err, tt.want)
			var specErr *TPMPolicyBranchSpecError
			require.ErrorAs(t, err, &specErr)
			assert.Equal(t, tt.condition, specErr.Condition)
			assert.Contains(t, err.Error(), tt.condition)
		})
	}

	for _, spec := range []string{"", " ; ;", "name=next"} {
		_, err := ParseTPMPolicyBranch(spec)
		require.ErrorIs(t, err, ErrTPMPolicyBranchEmpty)
	}
}

// TestTPMPolicyBranch_String renders a branch in the spec form the parser
// reads back.
func TestTPMPolicyBranch_String(t *testing.T) {
	b := TPMPolicyBranch{Conditions: []TPMPolicyCondition{
		{Type: TPMPolicyConditionPCR, Bank: "sha256", PCRs: []uint{0, 7}},
		{Type: TPMPolicyConditionAuthValue},
		{Type: TPMPolicyConditionLocality, Localities: []uint{0, 3}},
	}}
	assert.Equal(t, "pcr=sha256:0,7;auth_value;locality=0,3", b.String())
	parsed, err := ParseTPMPolicyBranch(b.String())
	require.NoError(t, err)
	assert.Equal(t, b, parsed)
	assert.Empty(t, TPMPolicyBranch{}.String())

	b.Name = "next"
	assert.Equal(t, "name=next;pcr=sha256:0,7;auth_value;locality=0,3", b.String())
	parsed, err = ParseTPMPolicyBranch(b.String())
	require.NoError(t, err)
	assert.Equal(t, b, parsed)
}

// TestTPMPolicyReference_String proves a reference names its CoRIM, the
// signer when the CoRIM names one, and the CoRIM's digest.
func TestTPMPolicyReference_String(t *testing.T) {
	assert.Equal(t, "boot-image-v2 signed by Example Provider, sha256 abcd",
		TPMPolicyReference{ID: "boot-image-v2", Signer: "Example Provider", Digest: []byte{0xab, 0xcd}}.String())
	assert.Equal(t, "(no id), sha256 00", TPMPolicyReference{Digest: []byte{0x00}}.String())
}

// TestTPMPolicyBranches builds the one pcr branch of a PCR selection, with
// the default bank when none is named, or the parsed branch specs, and
// refuses both, neither, or a malformed spec.
func TestTPMPolicyBranches(t *testing.T) {
	got, err := TPMPolicyBranches("", []uint{0, 7}, nil)
	require.NoError(t, err)
	assert.Equal(t, []TPMPolicyBranch{TPMPolicyPCRBranch(DefaultTPMPolicyBank, []uint{0, 7})}, got)

	got, err = TPMPolicyBranches("sha384", []uint{7}, nil)
	require.NoError(t, err)
	assert.Equal(t, "pcr=sha384:7", got[0].String())

	got, err = TPMPolicyBranches("", nil, []string{"pcr=0", "auth_value"})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "auth_value", got[1].String())

	_, err = TPMPolicyBranches("", nil, nil)
	assert.ErrorIs(t, err, ErrTPMPolicyNoSelection)
	_, err = TPMPolicyBranches("", []uint{7}, []string{"auth_value"})
	assert.ErrorIs(t, err, ErrTPMPolicyPCRsAndBranches)
	_, err = TPMPolicyBranches("sha1", nil, []string{"auth_value"})
	assert.ErrorIs(t, err, ErrTPMPolicyPCRsAndBranches)
	_, err = TPMPolicyBranches("", nil, []string{"auth_value", "bogus"})
	assert.ErrorIs(t, err, ErrTPMPolicyConditionUnknown)
}
