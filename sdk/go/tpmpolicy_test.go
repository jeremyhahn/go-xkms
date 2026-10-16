package xkms

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sdkBindingRecord returns a binding record of system/boot written while the
// policy was revoked: it names the policy's NV index and carries no approvals.
func sdkBindingRecord(t *testing.T) []byte {
	t.Helper()
	record, err := (&store.TPMPolicyBinding{
		Scope:   "system",
		Policy:  "boot",
		Index:   0x01500020,
		HashAlg: 0x000B,
	}).MarshalBinary()
	require.NoError(t, err)
	return record
}

// TestNewTPMStaticPolicyResolver proves the SDK's static resolver answers
// from a binding record and classifies with the SDK's own errors.
func TestNewTPMStaticPolicyResolver(t *testing.T) {
	r, err := NewTPMStaticPolicyResolver(sdkBindingRecord(t))
	require.NoError(t, err)
	var resolver TPMPolicyBindingResolver = r

	info, err := resolver.PolicyIndex("system", "boot")
	require.NoError(t, err)
	assert.EqualValues(t, 0x01500020, info.Index)

	_, err = resolver.Approvals("system", "boot")
	assert.ErrorIs(t, err, ErrTPMPolicyRevoked, "a record without approvals authorizes nothing")
	_, err = resolver.Approvals("system", "other")
	assert.ErrorIs(t, err, ErrTPMPolicyUnbound)
}

// TestNewTPMStaticPolicyResolver_Refusals proves a record that does not
// decode is refused as a TPMPolicyBindingFormatError.
func TestNewTPMStaticPolicyResolver_Refusals(t *testing.T) {
	_, err := NewTPMStaticPolicyResolver([]byte("not a binding record"))
	var formatErr *TPMPolicyBindingFormatError
	assert.ErrorAs(t, err, &formatErr)

	record := sdkBindingRecord(t)
	_, err = NewTPMStaticPolicyResolver(record[:len(record)-1])
	assert.ErrorAs(t, err, &formatErr, "a truncated record")
}
