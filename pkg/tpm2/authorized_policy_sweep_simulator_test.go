//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestAuthorizedPolicy_EveryCommandFailurePropagates sweeps signing with a
// key bound to a named policy, through each kind of policy session: a
// redeemed branch approval, a password key's outer branch (PolicyAuthValue,
// then PolicyOR), the same key's approved branch (approval, then PolicyOR),
// and a composite policy whose branch requires the password. No TPM failure
// may yield a signature.
func TestAuthorizedPolicy_EveryCommandFailurePropagates(t *testing.T) {
	tests := []struct {
		name    string
		fixture func(t *testing.T) *policyFixture
		key     func(t *testing.T, f *policyFixture) *types.KeyAttributes
		// flush is the position of Sign's last command, the deferred flush
		// of the loaded key; it is logged, not returned.
		flush int
	}{
		{
			name:    "approved branch",
			fixture: newPolicyFixture,
			key: func(t *testing.T, f *policyFixture) *types.KeyAttributes {
				return f.createBoundKey(t, "sweep-approved", nil)
			},
			flush: 35,
		},
		{
			name:    "outer password branch",
			fixture: newPolicyFixture,
			key: func(t *testing.T, f *policyFixture) *types.KeyAttributes {
				return f.createBoundKey(t, "sweep-outer-password", mustPassword(t, []byte("sweep-pin")))
			},
			flush: 19,
		},
		{
			name:    "approved branch of a password key",
			fixture: newPolicyFixture,
			key: func(t *testing.T, f *policyFixture) *types.KeyAttributes {
				return withoutPassword(f.createBoundKey(t, "sweep-approved-password", mustPassword(t, []byte("sweep-pin"))))
			},
			flush: 36,
		},
		{
			name: "composite password branch",
			fixture: func(t *testing.T) *policyFixture {
				return newCompositePolicyFixture(t, branchSpec{pcr: true}, branchSpec{authValue: true})
			},
			key: func(t *testing.T, f *policyFixture) *types.KeyAttributes {
				return f.createBoundKey(t, "sweep-composite-password", mustPassword(t, []byte("sweep-pin")))
			},
			flush: 35,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
				f := tt.fixture(t)
				key := tt.key(t, f)

				return f.h.TPM.transport, func(tr transport.TPM) error {
					f.h.TPM.transport = tr
					return f.sign(key)
				}
			}, tt.flush)
		})
	}
}
