package tpm2

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testName is a syntactically valid SHA-256 Name (alg id + digest).
func testName(fill byte) tpm2.TPM2BName {
	buf := binary.BigEndian.AppendUint16(nil, uint16(tpm2.TPMAlgSHA256))
	for range 32 {
		buf = append(buf, fill)
	}
	return tpm2.TPM2BName{Buffer: buf}
}

// TestPolicyRef_Definition pins PolicyRef to its documented formula and
// proves the NUL separator keeps (scope, name) pairs from colliding.
func TestPolicyRef_Definition(t *testing.T) {
	want := sha256.Sum256([]byte("xkms/tpm-policy/v1" + "tenant-a" + "\x00" + "boot"))
	assert.Equal(t, want[:], PolicyRef("tenant-a", "boot"))

	assert.NotEqual(t, PolicyRef("ab", "c"), PolicyRef("a", "bc"))
	assert.NotEqual(t, PolicyRef("tenant-a", "boot"), PolicyRef("tenant-b", "boot"))
}

// TestPolicyScope_DefaultsToSystem proves a key with no tenant belongs to the
// system scope.
func TestPolicyScope_DefaultsToSystem(t *testing.T) {
	assert.Equal(t, SystemPolicyScope, policyScope(&types.KeyAttributes{}))
	assert.Equal(t, "tenant-a", policyScope(&types.KeyAttributes{TenantID: "tenant-a"}))
}

// TestIsNamedPolicy proves only a policy name other than "" and "platform"
// selects the authorized-policy path.
func TestIsNamedPolicy(t *testing.T) {
	assert.False(t, isNamedPolicy(""))
	assert.False(t, isNamedPolicy(types.TPMPolicyPlatform))
	assert.True(t, isNamedPolicy("boot"))
}

// TestAuthorizedObjectPolicy_Branches proves a key without an auth value gets
// PolicyAuthorizeNV alone -- no branch an empty password could satisfy -- and
// a key with one gets the PolicyOR of both branches.
func TestAuthorizedObjectPolicy_Branches(t *testing.T) {
	name := testName(0x11)

	noAuth, noAuthBranches, err := AuthorizedObjectPolicy(tpm2.TPMAlgSHA256, name, false)
	require.NoError(t, err)
	require.Len(t, noAuthBranches, 1)
	assert.Equal(t, noAuthBranches[0], noAuth)

	withAuth, branches, err := AuthorizedObjectPolicy(tpm2.TPMAlgSHA256, name, true)
	require.NoError(t, err)
	require.Len(t, branches, 2)
	assert.Equal(t, noAuth, branches[0], "branch 1 is the same PolicyAuthorizeNV digest")
	assert.NotEqual(t, noAuth, withAuth)

	other, _, err := AuthorizedObjectPolicy(tpm2.TPMAlgSHA256, testName(0x22), false)
	require.NoError(t, err)
	assert.NotEqual(t, noAuth, other, "the authPolicy names its index")
}

// TestAuthorizedPolicyDigests_RejectInvalidInput proves each digest function
// refuses input it cannot turn into a meaningful digest.
func TestAuthorizedPolicyDigests_RejectInvalidInput(t *testing.T) {
	_, _, err := AuthorizedObjectPolicy(tpm2.TPMAlgSHA256, tpm2.TPM2BName{}, true)
	require.ErrorIs(t, err, ErrPolicyDigestCompute)

	_, err = AuthorizeDigest(tpm2.TPMAlgSHA256, tpm2.TPM2BName{}, PolicyRef("s", "p"))
	require.ErrorIs(t, err, ErrPolicyDigestCompute)

	_, err = AuthorizeDigest(tpm2.TPMAlgNull, testName(1), PolicyRef("s", "p"))
	require.ErrorIs(t, err, ErrPolicyDigestCompute)

	_, err = ApprovedPolicyDigest(tpm2.TPMAlgSHA256, pcrBranch(make([]byte, 32)), tpm2.TPM2BName{}, 1)
	require.ErrorIs(t, err, ErrPolicyDigestCompute)

	_, err = ApprovalDigest(tpm2.TPMAlgNull, make([]byte, 32), PolicyRef("s", "p"))
	require.ErrorIs(t, err, ErrPolicyDigestCompute)
}

// pcrBranch is a branch of one PCR condition over PCR 23 with digest.
func pcrBranch(digest []byte) PolicyBranch {
	return PolicyBranch{Conditions: []PolicyCondition{{
		Type:         PolicyConditionPCR,
		PCRSelection: PolicyPCRSelection(tpm2.TPMAlgSHA256, 23),
		PCRDigest:    digest,
	}}}
}

// TestApprovedPolicyDigest_BindsEpochAndPCRs proves the approved digest
// changes with the epoch and with the PCR value, which is what makes an
// approval specific to one platform state at one epoch.
func TestApprovedPolicyDigest_BindsEpochAndPCRs(t *testing.T) {
	pcr := make([]byte, 32)
	base, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256, pcrBranch(pcr), testName(1), 1)
	require.NoError(t, err)

	nextEpoch, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256, pcrBranch(pcr), testName(1), 2)
	require.NoError(t, err)
	assert.NotEqual(t, base, nextEpoch)

	otherPCR, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256, pcrBranch(append([]byte{1}, pcr[1:]...)), testName(1), 1)
	require.NoError(t, err)
	assert.NotEqual(t, base, otherPCR)
}

// TestApprovedPolicyDigest_CanonicalOrder proves a branch's digest does not
// depend on the order its conditions are listed in, that it runs them as
// PolicyLocality, PolicyPCR, PolicyAuthValue, and that each condition changes
// the digest.
func TestApprovedPolicyDigest_CanonicalOrder(t *testing.T) {
	locality, err := PolicyLocalitySelection(0, 3)
	require.NoError(t, err)
	pcr := pcrBranch(make([]byte, 32)).Conditions[0]
	loc := PolicyCondition{Type: PolicyConditionLocality, Locality: locality}
	auth := PolicyCondition{Type: PolicyConditionAuthValue}

	listed, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256,
		PolicyBranch{Conditions: []PolicyCondition{auth, pcr, loc}}, testName(1), 1)
	require.NoError(t, err)
	canonical, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256,
		PolicyBranch{Conditions: []PolicyCondition{loc, pcr, auth}}, testName(1), 1)
	require.NoError(t, err)
	assert.Equal(t, canonical, listed)

	want, err := trialDigest(tpm2.TPMAlgSHA256,
		policyLocality{Locality: locality},
		tpm2.PolicyPCR{PcrDigest: tpm2.TPM2BDigest{Buffer: pcr.PCRDigest}, Pcrs: pcr.PCRSelection},
		tpm2.PolicyAuthValue{},
		tpm2.PolicyNV{
			NVIndex:   tpm2.NamedHandle{Name: testName(1)},
			OperandB:  tpm2.TPM2BOperand{Buffer: epochOperand(1)},
			Operation: tpm2.TPMEOEq,
		})
	require.NoError(t, err)
	assert.Equal(t, want, canonical)

	withoutAuth, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256,
		PolicyBranch{Conditions: []PolicyCondition{loc, pcr}}, testName(1), 1)
	require.NoError(t, err)
	assert.NotEqual(t, canonical, withoutAuth)
}

// TestApprovedPolicyDigest_RejectsInvalidBranch proves a branch that cannot
// be asserted is refused: no conditions, an unknown type, a PCR condition
// without its operands, and a locality condition allowing nothing.
func TestApprovedPolicyDigest_RejectsInvalidBranch(t *testing.T) {
	for name, branch := range map[string]PolicyBranch{
		"empty":            {},
		"unknown type":     {Conditions: []PolicyCondition{{Type: 99}}},
		"pcr no digest":    pcrBranch(nil),
		"pcr no selection": {Conditions: []PolicyCondition{{Type: PolicyConditionPCR, PCRDigest: make([]byte, 32)}}},
		"no locality":      {Conditions: []PolicyCondition{{Type: PolicyConditionLocality}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256, branch, testName(1), 1)
			require.ErrorIs(t, err, ErrInvalidPolicyBranch)
		})
	}
}

// TestPolicyBranch_HasAuthValue proves only a branch with an auth_value
// condition requires the object's password.
func TestPolicyBranch_HasAuthValue(t *testing.T) {
	assert.False(t, pcrBranch(make([]byte, 32)).HasAuthValue())
	assert.True(t, PolicyBranch{Conditions: []PolicyCondition{{Type: PolicyConditionAuthValue}}}.HasAuthValue())
}

// TestPolicyLocalitySelection proves localities map to their TPMA_LOCALITY
// bits and that extended localities and an empty set are refused.
func TestPolicyLocalitySelection(t *testing.T) {
	got, err := PolicyLocalitySelection(0, 2, 4)
	require.NoError(t, err)
	assert.Equal(t, uint8(0b10101), localityBits(got))
	assert.True(t, got.TPMLocZero)
	assert.True(t, got.TPMLocFour)
	assert.False(t, got.TPMLocOne)

	_, err = PolicyLocalitySelection(5)
	require.ErrorIs(t, err, ErrInvalidPolicyLocality)
	_, err = PolicyLocalitySelection()
	require.ErrorIs(t, err, ErrInvalidPolicyLocality)
}

// TestIsBranchRefusal proves only a branch's own refusals move the session
// on to the next branch.
func TestIsBranchRefusal(t *testing.T) {
	assert.True(t, isBranchRefusal(&PolicyPCRMismatchError{Err: tpm2.TPMRCValue}))
	assert.True(t, isBranchRefusal(&PolicyLocalityMismatchError{}))
	assert.True(t, isBranchRefusal(&PolicyApprovalRevokedError{Err: tpm2.TPMRCPolicy}))
	assert.False(t, isBranchRefusal(tpm2.TPMRCValue))
	assert.False(t, isBranchRefusal(ErrPolicyApprovalMismatch))
}

// TestApprovalDigest_Definition pins aHash = H(approvedPolicy || policyRef).
func TestApprovalDigest_Definition(t *testing.T) {
	approved := make([]byte, 32)
	ref := PolicyRef("system", "boot")
	got, err := ApprovalDigest(tpm2.TPMAlgSHA256, approved, ref)
	require.NoError(t, err)
	want := sha256.Sum256(append(append([]byte(nil), approved...), ref...))
	assert.Equal(t, want[:], got)
}

// TestPCRCompositeDigest_MatchesComputePolicyPCRDigest proves the operand is
// the one ComputePolicyPCRDigest folds into its policy digest, and that it is
// the hash of the PCR values in index order.
func TestPCRCompositeDigest_MatchesComputePolicyPCRDigest(t *testing.T) {
	values := map[string]string{
		"sha256:7":  hex.EncodeToString(make([]byte, 32)),
		"sha256:23": hex.EncodeToString(append([]byte{0xFF}, make([]byte, 31)...)),
	}
	operand, err := PCRCompositeDigest(PCRBankSHA256, []int{23, 7}, values)
	require.NoError(t, err)

	composite := append(make([]byte, 32), append([]byte{0xFF}, make([]byte, 31)...)...)
	want := sha256.Sum256(composite)
	assert.Equal(t, want[:], operand)

	policy, err := ComputePolicyPCRDigest(PCRBankSHA256, []int{7, 23}, values)
	require.NoError(t, err)
	trial, err := trialDigest(tpm2.TPMAlgSHA256, tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{Buffer: operand},
		Pcrs:      PolicyPCRSelection(tpm2.TPMAlgSHA256, 7, 23),
	})
	require.NoError(t, err)
	assert.Equal(t, trial, policy)
}

// TestPCRCompositeDigest_RejectsInvalidInput proves missing indices and
// malformed values are refused.
func TestPCRCompositeDigest_RejectsInvalidInput(t *testing.T) {
	_, err := PCRCompositeDigest(PCRBankSHA256, nil, nil)
	require.ErrorIs(t, err, ErrPolicyEmptyPCRs)

	_, err = PCRCompositeDigest(PCRBankSHA256, []int{7}, map[string]string{"sha256:7": "zz"})
	require.ErrorIs(t, err, ErrPolicyInvalidDigest)
}

// TestNVReadPolicy_PerIndexType proves each authorized index type gets a read
// policy of its own two commands, and an unknown type is refused.
func TestNVReadPolicy_PerIndexType(t *testing.T) {
	ordinary, ordBranches, err := nvReadPolicy(tpm2.TPMAlgSHA256, tpm2.TPMNTOrdinary)
	require.NoError(t, err)
	counter, ctrBranches, err := nvReadPolicy(tpm2.TPMAlgSHA256, tpm2.TPMNTCounter)
	require.NoError(t, err)
	require.Len(t, ordBranches, 2)
	require.Len(t, ctrBranches, 2)
	assert.Equal(t, ordBranches[0], ctrBranches[0], "both allow TPM2_NV_Read")
	assert.NotEqual(t, ordinary, counter)

	_, _, err = nvReadPolicy(tpm2.TPMAlgSHA256, tpm2.TPMNTExtend)
	require.ErrorIs(t, err, ErrPolicyDigestCompute)
}

// TestPolicyErrors_UnwrapResponseCode proves the typed refusals keep the TPM
// response code in the chain.
func TestPolicyErrors_UnwrapResponseCode(t *testing.T) {
	pcrErr := &PolicyPCRMismatchError{Scope: "system", Policy: "boot", Err: tpm2.TPMRCValue}
	assert.ErrorIs(t, pcrErr, tpm2.TPMRCValue)
	assert.Contains(t, pcrErr.Error(), `"boot"`)

	revoked := &PolicyApprovalRevokedError{Scope: "system", Policy: "boot", Epoch: 3, Err: tpm2.TPMRCPolicy}
	assert.ErrorIs(t, revoked, tpm2.TPMRCPolicy)
	assert.Contains(t, revoked.Error(), "epoch 3")

	allowed, err := PolicyLocalitySelection(3)
	require.NoError(t, err)
	locality := &PolicyLocalityMismatchError{Scope: "system", Policy: "boot", Branch: 1, Allowed: allowed}
	assert.Contains(t, locality.Error(), "0x08")
	missing := &PolicyAuthValueMissingError{Scope: "system", Policy: "boot", Branch: 2}
	assert.Contains(t, missing.Error(), "branch 2")

	refused := &PolicyBranchesRefusedError{Scope: "system", Policy: "boot", Branches: []error{pcrErr, locality, missing}}
	assert.ErrorIs(t, refused, tpm2.TPMRCValue)
	var asLocality *PolicyLocalityMismatchError
	assert.ErrorAs(t, refused, &asLocality)
	assert.Contains(t, refused.Error(), "branch 2")
}

// TestSetPolicyBindingResolver_Clear proves a nil resolver clears it.
func TestSetPolicyBindingResolver_Clear(t *testing.T) {
	tpm := &TPM2{}
	_, err := tpm.policyBindingResolver()
	require.ErrorIs(t, err, ErrPolicyResolverUnset)

	var r PolicyBindingResolver = nopResolver{}
	tpm.SetPolicyBindingResolver(r)
	got, err := tpm.policyBindingResolver()
	require.NoError(t, err)
	assert.Equal(t, r, got)

	tpm.SetPolicyBindingResolver(nil)
	_, err = tpm.policyBindingResolver()
	require.ErrorIs(t, err, ErrPolicyResolverUnset)
}

type nopResolver struct{}

func (nopResolver) PolicyIndex(string, string) (PolicyIndexInfo, error) {
	return PolicyIndexInfo{}, nil
}

func (nopResolver) Approvals(string, string) ([]*PolicyApproval, error) { return nil, nil }
