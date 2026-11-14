package xkms_test

import (
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// consumerResolver is a resolver written outside the SDK, as go-quicbaas
// writes one: it names only SDK types and answers from the SDK's static
// resolver.
type consumerResolver struct {
	static xkms.TPMPolicyBindingResolver
}

func (c consumerResolver) PolicyIndex(scope, name string) (xkms.TPMPolicyIndexInfo, error) {
	return c.static.PolicyIndex(scope, name)
}

func (c consumerResolver) Approvals(scope, name string) ([]*xkms.TPMPolicyBranchApproval, error) {
	return c.static.Approvals(scope, name)
}

// TestTPMPolicyBindingResolver_OutsideTheSDK proves a consumer of sdk/go can
// build a .tpmpolicy binding record, the static resolver from it, and its own
// PolicyBindingResolver, through the SDK's exports alone.
func TestTPMPolicyBindingResolver_OutsideTheSDK(t *testing.T) {
	record, err := (&xkms.TPMPolicyBindingRecord{
		Scope:   "system",
		Policy:  "boot",
		Index:   0x01500020,
		HashAlg: 0x000B,
	}).MarshalBinary()
	require.NoError(t, err)

	static, err := xkms.NewTPMStaticPolicyResolver(record)
	require.NoError(t, err)
	var resolver xkms.TPMPolicyBindingResolver = consumerResolver{static: static}

	info, err := resolver.PolicyIndex("system", "boot")
	require.NoError(t, err)
	assert.EqualValues(t, 0x01500020, info.Index)
	assert.EqualValues(t, 0x000B, info.HashAlg)

	_, err = resolver.Approvals("system", "boot")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyRevoked)
	_, err = resolver.PolicyIndex("system", "other")
	assert.ErrorIs(t, err, xkms.ErrTPMPolicyUnbound)
}
