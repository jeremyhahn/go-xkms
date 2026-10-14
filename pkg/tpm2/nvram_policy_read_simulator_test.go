//go:build tpm_simulator

package tpm2

import (
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// platformBoundNVAttrs returns attributes for an owner NV index bound to the
// platform policy, so it is read through TPMA_NV_POLICYREAD.
func platformBoundNVAttrs(t *testing.T, h *simHarness, handle uint32) *types.KeyAttributes {
	t.Helper()
	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)
	return &types.KeyAttributes{
		CN:        "policy-read-nv",
		Parent:    srkAttrs,
		TPMPolicy: types.TPMPolicyPlatform,
		TPMAttributes: &types.TPMAttributes{
			Handle:    tpm2.TPMHandle(handle),
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
}

// definePlatformBoundCounter defines and increments a platform-bound
// counter: a counter is unreadable until its first increment.
func definePlatformBoundCounter(t *testing.T, h *simHarness) *types.KeyAttributes {
	t.Helper()
	counter := platformBoundNVAttrs(t, h, nvramCounterIndex)
	require.NoError(t, h.TPM.NVDefineCounter(counter))
	_, err := h.TPM.NVIncrement(counter)
	require.NoError(t, err)
	return counter
}

// definePlatformBoundExtend defines and extends a platform-bound extend
// index: it is unreadable until its first extend.
func definePlatformBoundExtend(t *testing.T, h *simHarness, data []byte) *types.KeyAttributes {
	t.Helper()
	extend := platformBoundNVAttrs(t, h, nvramExtendIndex)
	require.NoError(t, h.TPM.NVDefineExtend(extend))
	require.NoError(t, h.TPM.NVExtend(extend, data))
	return extend
}

// TestNVReadCounter_PlatformPolicy proves a platform-bound counter is read
// through its PCR policy, and refused once the platform PCR moves.
func TestNVReadCounter_PlatformPolicy(t *testing.T) {
	h := newSimHarness(t, nil)
	counter := definePlatformBoundCounter(t, h)

	before, err := h.TPM.NVReadCounter(counter)
	require.NoError(t, err)
	_, err = h.TPM.NVIncrement(counter)
	require.NoError(t, err)
	after, err := h.TPM.NVReadCounter(counter)
	require.NoError(t, err)
	assert.Equal(t, before+1, after)

	h.extendPlatformPCR(t, []byte("tampered-boot"))
	_, err = h.TPM.NVReadCounter(counter)
	require.ErrorIs(t, err, tpm2.TPMRCPolicyFail)
}

// TestNVReadExtend_PlatformPolicy proves a platform-bound extend index is
// read through its PCR policy, and refused once the platform PCR moves.
func TestNVReadExtend_PlatformPolicy(t *testing.T) {
	h := newSimHarness(t, nil)
	measurement := []byte("measurement")
	extend := definePlatformBoundExtend(t, h, measurement)

	digest, err := h.TPM.NVReadExtend(extend)
	require.NoError(t, err)
	want := sha256.Sum256(append(make([]byte, sha256.Size), measurement...))
	assert.Equal(t, want[:], digest)

	h.extendPlatformPCR(t, []byte("tampered-boot"))
	_, err = h.TPM.NVReadExtend(extend)
	require.ErrorIs(t, err, tpm2.TPMRCPolicyFail)
}

// TestNVReadCounter_PlatformPolicy_EveryCommandFailurePropagates sweeps the
// policy read of a platform-bound counter.
func TestNVReadCounter_PlatformPolicy_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		counter := definePlatformBoundCounter(t, h)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.NVReadCounter(counter)
			return err
		}
	}, policyReadFlush)
}

// TestNVReadExtend_PlatformPolicy_EveryCommandFailurePropagates sweeps the
// policy read of a platform-bound extend index.
func TestNVReadExtend_PlatformPolicy_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		extend := definePlatformBoundExtend(t, h, []byte("measurement"))

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.NVReadExtend(extend)
			return err
		}
	}, policyReadFlush)
}

// policyReadFlush is the position, counted from the end, of a policy read's
// last command, the deferred flush of its policy session; it is logged, not
// returned.
const policyReadFlush = -1
