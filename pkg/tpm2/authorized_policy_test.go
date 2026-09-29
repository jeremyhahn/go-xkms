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

	sel := PolicyPCRSelection(tpm2.TPMAlgSHA256, 23)
	_, err = ApprovedPolicyDigest(tpm2.TPMAlgSHA256, sel, nil, testName(1), 1)
	require.ErrorIs(t, err, ErrPolicyDigestCompute)
	_, err = ApprovedPolicyDigest(tpm2.TPMAlgSHA256, tpm2.TPMLPCRSelection{}, make([]byte, 32), testName(1), 1)
	require.ErrorIs(t, err, ErrPolicyDigestCompute)
	_, err = ApprovedPolicyDigest(tpm2.TPMAlgSHA256, sel, make([]byte, 32), tpm2.TPM2BName{}, 1)
	require.ErrorIs(t, err, ErrPolicyDigestCompute)

	_, err = ApprovalDigest(tpm2.TPMAlgNull, make([]byte, 32), PolicyRef("s", "p"))
	require.ErrorIs(t, err, ErrPolicyDigestCompute)
}

// TestApprovedPolicyDigest_BindsEpochAndPCRs proves the approved digest
// changes with the epoch and with the PCR value, which is what makes an
// approval specific to one platform state at one epoch.
func TestApprovedPolicyDigest_BindsEpochAndPCRs(t *testing.T) {
	sel := PolicyPCRSelection(tpm2.TPMAlgSHA256, 23)
	pcr := make([]byte, 32)
	base, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256, sel, pcr, testName(1), 1)
	require.NoError(t, err)

	nextEpoch, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256, sel, pcr, testName(1), 2)
	require.NoError(t, err)
	assert.NotEqual(t, base, nextEpoch)

	otherPCR, err := ApprovedPolicyDigest(tpm2.TPMAlgSHA256, sel, append([]byte{1}, pcr[1:]...), testName(1), 1)
	require.NoError(t, err)
	assert.NotEqual(t, base, otherPCR)
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

func (nopResolver) PolicyIndex(string, string) (tpm2.TPMHandle, tpm2.TPMAlgID, error) {
	return 0, 0, nil
}

func (nopResolver) Approval(string, string) (*PolicyApproval, error) { return nil, nil }
