package tpm2

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	recordScope  = "acme"
	recordPolicy = "boot"
	recordIndex  = tpm2.TPMHandle(0x01500020)
)

// recordAuthority returns a parseable authority public area; unique tells
// two authorities apart.
func recordAuthority(unique byte) tpm2.TPM2BPublic {
	template := tpm2.ECCSRKTemplate
	template.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: bytes.Repeat([]byte{unique}, 32)},
		Y: tpm2.TPM2BECCParameter{Buffer: bytes.Repeat([]byte{unique}, 32)},
	})
	return tpm2.New2B(template)
}

// recordApproval returns an approval of recordPolicy's branch, signed (in
// form only) by authority, with a locality and a PCR condition.
func recordApproval(authority tpm2.TPM2BPublic) *PolicyApproval {
	return &PolicyApproval{
		HashAlg: tpm2.TPMAlgSHA256,
		Branch: PolicyBranch{Conditions: []PolicyCondition{
			{Type: PolicyConditionLocality, Locality: tpm2.TPMALocality{TPMLocZero: true}},
			{
				Type: PolicyConditionPCR,
				PCRSelection: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{
					{Hash: tpm2.TPMAlgSHA256, PCRSelect: []byte{0x00, 0x00, 0x01}},
				}},
				PCRDigest: bytes.Repeat([]byte{0xAB}, 32),
			},
		}},
		Counter:         0x01500010,
		Epoch:           7,
		PolicyRef:       PolicyRef(recordScope, recordPolicy),
		AuthorityPublic: authority,
		Signature: tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
				Hash:       tpm2.TPMAlgSHA256,
				SignatureR: tpm2.TPM2BECCParameter{Buffer: bytes.Repeat([]byte{0x11}, 32)},
				SignatureS: tpm2.TPM2BECCParameter{Buffer: bytes.Repeat([]byte{0x22}, 32)},
			}),
		},
		Index: recordIndex,
	}
}

// recordResolver answers with fixed approvals.
type recordResolver struct {
	approvals []*PolicyApproval
	err       error
}

func (r recordResolver) PolicyIndex(string, string) (PolicyIndexInfo, error) {
	return PolicyIndexInfo{Index: recordIndex, HashAlg: tpm2.TPMAlgSHA256}, nil
}

func (r recordResolver) Approvals(string, string) ([]*PolicyApproval, error) {
	return r.approvals, r.err
}

// recordBinding returns a binding record of recordPolicy carrying approvals.
func recordBinding(t *testing.T, approvals ...*PolicyApproval) *store.TPMPolicyBinding {
	t.Helper()
	binding := &store.TPMPolicyBinding{
		Scope:   recordScope,
		Policy:  recordPolicy,
		Index:   uint32(recordIndex),
		HashAlg: uint16(tpm2.TPMAlgSHA256),
	}
	var err error
	binding.Authority, binding.Approvals, err = bindingApprovals(recordResolver{approvals: approvals}, recordScope, recordPolicy)
	require.NoError(t, err)
	return binding
}

func marshalRecord(t *testing.T, binding *store.TPMPolicyBinding) []byte {
	t.Helper()
	record, err := binding.MarshalBinary()
	require.NoError(t, err)
	return record
}

// TestPolicyApprovalEncoding_RoundTrip proves every field of an approval,
// conditions included, survives the binding-record encoding.
func TestPolicyApprovalEncoding_RoundTrip(t *testing.T) {
	want := recordApproval(recordAuthority(1))
	encoded, err := marshalPolicyApproval(want)
	require.NoError(t, err)

	got, err := unmarshalPolicyApproval(encoded)
	require.NoError(t, err)
	assert.Equal(t, want.HashAlg, got.HashAlg)
	assert.Equal(t, want.Counter, got.Counter)
	assert.Equal(t, want.Epoch, got.Epoch)
	assert.Equal(t, want.Index, got.Index)
	assert.Equal(t, want.PolicyRef, got.PolicyRef)
	assert.Equal(t, tpm2.Marshal(want.AuthorityPublic), tpm2.Marshal(got.AuthorityPublic))
	assert.Equal(t, tpm2.Marshal(want.Signature), tpm2.Marshal(got.Signature))
	require.Len(t, got.Branch.Conditions, 2)
	assert.Equal(t, want.Branch.Conditions[0].Locality, got.Branch.Conditions[0].Locality)
	assert.Nil(t, got.Branch.Conditions[0].PCRDigest)
	assert.Equal(t, want.Branch.Conditions[1].PCRSelection, got.Branch.Conditions[1].PCRSelection)
	assert.Equal(t, want.Branch.Conditions[1].PCRDigest, got.Branch.Conditions[1].PCRDigest)

	again, err := marshalPolicyApproval(got)
	require.NoError(t, err)
	assert.Equal(t, encoded, again)
}

// TestPolicyApprovalEncoding_Errors covers approvals that cannot be encoded
// and encodings that do not decode.
func TestPolicyApprovalEncoding_Errors(t *testing.T) {
	_, err := marshalPolicyApproval(nil)
	assert.ErrorIs(t, err, ErrInvalidPolicyApproval)

	crowded := recordApproval(recordAuthority(1))
	crowded.Branch.Conditions = make([]PolicyCondition, maxApprovalConditions+1)
	_, err = marshalPolicyApproval(crowded)
	assert.ErrorIs(t, err, ErrInvalidPolicyApproval)

	long := recordApproval(recordAuthority(1))
	long.PolicyRef = make([]byte, maxApprovalField+1)
	_, err = marshalPolicyApproval(long)
	assert.ErrorIs(t, err, ErrInvalidPolicyApproval)

	encoded, err := marshalPolicyApproval(recordApproval(recordAuthority(1)))
	require.NoError(t, err)
	for n := range len(encoded) {
		_, err := unmarshalPolicyApproval(encoded[:n])
		require.ErrorIs(t, err, ErrInvalidPolicyApproval, "truncated to %d bytes", n)
	}
	_, err = unmarshalPolicyApproval(append(encoded, 0))
	assert.ErrorIs(t, err, ErrInvalidPolicyApproval, "trailing bytes")

	// withFields encodes an approval header followed by the given
	// authority, signature and one condition's raw locality and selection.
	withFields := func(authority, signature, locality, selection []byte) []byte {
		w := &approvalWriter{out: make([]byte, 18)}
		w.field("policy reference", []byte("ref"))
		w.field("authority public area", authority)
		w.field("signature", signature)
		w.out = append(w.out, 1, uint8(PolicyConditionPCR))
		w.out = append(w.out, locality...)
		w.field("PCR selection", selection)
		w.field("PCR digest", nil)
		require.NoError(t, w.err)
		return w.out
	}
	approval := recordApproval(recordAuthority(1))
	authority := tpm2.Marshal(approval.AuthorityPublic)
	signature := tpm2.Marshal(approval.Signature)
	selection := tpm2.Marshal(approval.Branch.Conditions[1].PCRSelection)
	_, err = unmarshalPolicyApproval(withFields(authority, signature, []byte{0}, selection))
	require.NoError(t, err, "the hand-built encoding is valid")

	for name, data := range map[string][]byte{
		"authority":     withFields([]byte{0x00, 0x09}, signature, []byte{0}, selection),
		"signature":     withFields(authority, []byte{0x00}, []byte{0}, selection),
		"pcr selection": withFields(authority, signature, []byte{0}, []byte{0x00, 0x00, 0x00, 0x05}),
	} {
		_, err := unmarshalPolicyApproval(data)
		assert.ErrorIs(t, err, ErrInvalidPolicyApproval, name)
	}
}

// TestBindingApprovals covers what a binding record carries for each
// resolver answer.
func TestBindingApprovals(t *testing.T) {
	first, second := recordApproval(recordAuthority(1)), recordApproval(recordAuthority(1))
	authority, approvals, err := bindingApprovals(recordResolver{approvals: []*PolicyApproval{first, second}}, recordScope, recordPolicy)
	require.NoError(t, err)
	assert.Equal(t, tpm2.Marshal(first.AuthorityPublic), authority)
	assert.Len(t, approvals, 2)

	for name, r := range map[string]recordResolver{
		"revoked":           {err: &errs.Detail{Err: ErrPolicyRevoked, Detail: recordPolicy}},
		"no approvals":      {},
		"mixed authorities": {approvals: []*PolicyApproval{first, recordApproval(recordAuthority(2))}},
	} {
		authority, approvals, err := bindingApprovals(r, recordScope, recordPolicy)
		require.NoError(t, err, name)
		assert.Nil(t, authority, name)
		assert.Nil(t, approvals, name)
	}

	failure := errors.New("registry down")
	_, _, err = bindingApprovals(recordResolver{err: failure}, recordScope, recordPolicy)
	assert.ErrorIs(t, err, failure)
	_, _, err = bindingApprovals(recordResolver{approvals: []*PolicyApproval{nil}}, recordScope, recordPolicy)
	assert.ErrorIs(t, err, ErrInvalidPolicyApproval)
	long := recordApproval(recordAuthority(1))
	long.PolicyRef = make([]byte, maxApprovalField+1)
	_, _, err = bindingApprovals(recordResolver{approvals: []*PolicyApproval{long}}, recordScope, recordPolicy)
	assert.ErrorIs(t, err, ErrInvalidPolicyApproval)
}

// TestRefreshPolicyBinding proves a refresh rewrites a record's approvals
// and leaves an object with no record alone.
func TestRefreshPolicyBinding(t *testing.T) {
	blobs, err := store.NewBackendBlobStore(slog.New(slog.NewTextHandler(io.Discard, nil)), storage.New())
	require.NoError(t, err)
	attrs := &types.KeyAttributes{CN: "bound-key"}
	revoked := recordBinding(t)
	require.NoError(t, blobs.Save(attrs, marshalRecord(t, revoked), store.FSEXT_TPM_POLICY, false))

	approval := recordApproval(recordAuthority(1))
	require.NoError(t, RefreshPolicyBinding(recordResolver{approvals: []*PolicyApproval{approval}}, attrs, blobs))
	record, err := blobs.Get(attrs, store.FSEXT_TPM_POLICY)
	require.NoError(t, err)
	assert.Equal(t, marshalRecord(t, recordBinding(t, approval)), record)

	unbound := &types.KeyAttributes{CN: "unbound-key"}
	require.NoError(t, RefreshPolicyBinding(recordResolver{}, unbound, blobs))
	_, err = blobs.Get(unbound, store.FSEXT_TPM_POLICY)
	assert.ErrorIs(t, err, store.ErrBlobNotFound, "no record is created")
}

// TestRefreshPolicyBinding_Errors covers a missing resolver or backend, a
// corrupt record and a failing resolver.
func TestRefreshPolicyBinding_Errors(t *testing.T) {
	blobs, err := store.NewBackendBlobStore(slog.New(slog.NewTextHandler(io.Discard, nil)), storage.New())
	require.NoError(t, err)
	attrs := &types.KeyAttributes{CN: "bound-key"}

	assert.ErrorIs(t, RefreshPolicyBinding(nil, attrs, blobs), ErrPolicyResolverUnset)
	assert.ErrorIs(t, RefreshPolicyBinding(recordResolver{}, attrs, nil), ErrNoStorageBackend)

	require.NoError(t, blobs.Save(attrs, []byte("not a binding"), store.FSEXT_TPM_POLICY, false))
	assert.Error(t, RefreshPolicyBinding(recordResolver{}, attrs, blobs), "a corrupt record must not be overwritten")

	require.NoError(t, blobs.Save(attrs, marshalRecord(t, recordBinding(t)), store.FSEXT_TPM_POLICY, true))
	failure := errors.New("registry down")
	assert.ErrorIs(t, RefreshPolicyBinding(recordResolver{err: failure}, attrs, blobs), failure)
}

// TestStaticPolicyResolver proves the resolver answers from records alone.
func TestStaticPolicyResolver(t *testing.T) {
	approval := recordApproval(recordAuthority(1))
	bound := recordBinding(t, approval)
	bound.AuthValueCondition = true
	record := marshalRecord(t, bound)
	revoked := recordBinding(t)
	revoked.Policy = "retired"

	r, err := NewStaticPolicyResolver(record, record, marshalRecord(t, revoked))
	require.NoError(t, err, "an identical duplicate is accepted")

	info, err := r.PolicyIndex(recordScope, recordPolicy)
	require.NoError(t, err)
	assert.Equal(t, PolicyIndexInfo{Index: recordIndex, HashAlg: tpm2.TPMAlgSHA256, AuthValueCondition: true}, info)
	approvals, err := r.Approvals(recordScope, recordPolicy)
	require.NoError(t, err)
	require.Len(t, approvals, 1)
	assert.Equal(t, tpm2.Marshal(approval.Signature), tpm2.Marshal(approvals[0].Signature))

	_, err = r.Approvals(recordScope, "retired")
	assert.ErrorIs(t, err, ErrPolicyRevoked, "a record without approvals authorizes nothing")
	_, err = r.PolicyIndex(recordScope, "missing")
	assert.ErrorIs(t, err, ErrPolicyBindingUnknown)
	_, err = r.Approvals("other", recordPolicy)
	assert.ErrorIs(t, err, ErrPolicyBindingUnknown)

	empty, err := NewStaticPolicyResolver()
	require.NoError(t, err)
	_, err = empty.Approvals(recordScope, recordPolicy)
	assert.ErrorIs(t, err, ErrPolicyBindingUnknown)
}

// TestNewStaticPolicyResolver_Rejects covers records the resolver refuses:
// malformed, signed by another authority, approving another policy, or
// conflicting with another record.
func TestNewStaticPolicyResolver_Rejects(t *testing.T) {
	record := func(mutate func(*store.TPMPolicyBinding)) []byte {
		binding := recordBinding(t, recordApproval(recordAuthority(1)))
		mutate(binding)
		return marshalRecord(t, binding)
	}
	otherPolicy := recordApproval(recordAuthority(1))
	otherPolicy.PolicyRef = PolicyRef(recordScope, "other")
	otherApproval, err := marshalPolicyApproval(otherPolicy)
	require.NoError(t, err)

	_, err = NewStaticPolicyResolver([]byte("not a binding"))
	var formatErr *store.TPMPolicyBindingFormatError
	assert.ErrorAs(t, err, &formatErr)

	tests := []struct {
		name    string
		records [][]byte
		want    error
	}{
		{"malformed approval", [][]byte{record(func(b *store.TPMPolicyBinding) { b.Approvals[0] = []byte("x") })}, ErrInvalidPolicyApproval},
		{"wrong authority", [][]byte{record(func(b *store.TPMPolicyBinding) { b.Authority = tpm2.Marshal(recordAuthority(2)) })}, ErrPolicyApprovalMismatch},
		{"approval of another policy", [][]byte{record(func(b *store.TPMPolicyBinding) { b.Approvals[0] = otherApproval })}, ErrPolicyApprovalMismatch},
		{"conflicting records", [][]byte{record(func(*store.TPMPolicyBinding) {}), record(func(b *store.TPMPolicyBinding) { b.Index++ })}, ErrPolicyApprovalMismatch},
	}
	for _, tc := range tests {
		t.Run(strings.ReplaceAll(tc.name, " ", "_"), func(t *testing.T) {
			_, err := NewStaticPolicyResolver(tc.records...)
			assert.ErrorIs(t, err, tc.want)
		})
	}
}
