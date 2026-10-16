//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signStatic signs with key, its policy resolved from records alone by a
// StaticPolicyResolver, and restores the fixture's resolver afterwards.
func (f *policyFixture) signStatic(t *testing.T, key *types.KeyAttributes, records ...[]byte) error {
	t.Helper()
	static, err := NewStaticPolicyResolver(records...)
	require.NoError(t, err)
	f.h.TPM.SetPolicyBindingResolver(static)
	defer f.h.TPM.SetPolicyBindingResolver(f.resolver)
	return f.sign(key)
}

// rewriteRecord returns record with its approvals passed through edit and
// its authority set to theirs.
func rewriteRecord(t *testing.T, record []byte, edit func(*PolicyApproval)) []byte {
	t.Helper()
	binding, err := store.UnmarshalTPMPolicyBinding(record)
	require.NoError(t, err)
	for i, encoded := range binding.Approvals {
		approval, err := unmarshalPolicyApproval(encoded)
		require.NoError(t, err)
		edit(approval)
		binding.Authority = tpm2.Marshal(approval.AuthorityPublic)
		binding.Approvals[i], err = marshalPolicyApproval(approval)
		require.NoError(t, err)
	}
	return marshalRecord(t, binding)
}

// TestStaticPolicyResolver_AuthorizesFromTheRecord proves a key bound to a
// named policy is usable with nothing but its binding record: the static
// resolver built from the .tpmpolicy blob replaces the registry.
func TestStaticPolicyResolver_AuthorizesFromTheRecord(t *testing.T) {
	f := newPolicyFixture(t)
	key := f.createBoundKey(t, "static-resolver", nil)
	record := f.mustBlob(key, store.FSEXT_TPM_POLICY)

	f.h.TPM.SetPolicyBindingResolver(nil)
	require.ErrorIs(t, f.sign(key), ErrPolicyResolverUnset, "without a resolver the key is unusable")
	require.NoError(t, f.signStatic(t, key, record))
}

// TestStaticPolicyResolver_Refusals proves a binding record that was
// tampered with, stripped of its signatures or approvals, signed by another
// authority, or naming another policy authorizes nothing: the resolver
// refuses what it can check, and the TPM refuses the rest at use.
func TestStaticPolicyResolver_Refusals(t *testing.T) {
	f := newPolicyFixture(t)
	key := f.createBoundKey(t, "static-refusals", nil)
	record := f.mustBlob(key, store.FSEXT_TPM_POLICY)

	tampered := rewriteRecord(t, record, func(a *PolicyApproval) {
		ecc, err := a.Signature.Signature.ECDSA()
		require.NoError(t, err)
		s := append([]byte(nil), ecc.SignatureS.Buffer...)
		s[len(s)-1] ^= 0x01
		a.Signature.Signature = tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       ecc.Hash,
			SignatureR: ecc.SignatureR,
			SignatureS: tpm2.TPM2BECCParameter{Buffer: s},
		})
	})
	unsigned := rewriteRecord(t, record, func(a *PolicyApproval) {
		a.Signature = tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgNull}
	})
	noApprovals, err := store.UnmarshalTPMPolicyBinding(record)
	require.NoError(t, err)
	noApprovals.Authority, noApprovals.Approvals = nil, nil

	foreign := f.approve(t, f.createAuthority(t, "foreign-authority"))
	foreignSigned := rewriteRecord(t, record, func(a *PolicyApproval) {
		a.AuthorityPublic, a.Signature = foreign[0].AuthorityPublic, foreign[0].Signature
	})
	foreignAuthority, err := store.UnmarshalTPMPolicyBinding(record)
	require.NoError(t, err)
	foreignAuthority.Authority = tpm2.Marshal(foreign[0].AuthorityPublic)

	otherPolicy, err := store.UnmarshalTPMPolicyBinding(record)
	require.NoError(t, err)
	otherPolicy.Policy, otherPolicy.Authority, otherPolicy.Approvals = "other", nil, nil

	built := []struct {
		name   string
		record []byte
		want   error
	}{
		{"tampered signature", tampered, tpm2.TPMRCSignature},
		{"approvals stripped", marshalRecord(t, noApprovals), ErrPolicyRevoked},
		{"signed by a foreign authority", foreignSigned, tpm2.TPMRCValue},
		{"record of another policy only", marshalRecord(t, otherPolicy), ErrPolicyBindingUnknown},
	}
	for _, tc := range built {
		t.Run(tc.name, func(t *testing.T) {
			err := f.signStatic(t, key, tc.record)
			require.Error(t, err, "the TPM must refuse the key")
			assert.ErrorIs(t, err, tc.want)
		})
	}

	_, err = NewStaticPolicyResolver(unsigned)
	assert.ErrorIs(t, err, ErrInvalidPolicyApproval, "an unsigned approval is refused when the resolver is built")
	_, err = NewStaticPolicyResolver(marshalRecord(t, foreignAuthority))
	assert.ErrorIs(t, err, ErrPolicyApprovalMismatch, "an authority that did not sign the approvals is refused")

	require.NoError(t, f.signStatic(t, key, record), "the genuine record still authorizes the key")
}
