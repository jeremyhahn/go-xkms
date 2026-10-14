//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestNVWrite_EveryCommandFailurePropagates sweeps NVWrite's command
// sequence (platform policy digest, NV define, NV write) proving a failure
// at any step surfaces as an error rather than being silently absorbed.
func TestNVWrite_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		ekAttrs, err := h.TPM.EKAttributes()
		require.NoError(t, err)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			keyAttrs := &types.KeyAttributes{
				Parent:    ekAttrs,
				Password:  mustPassword(t, []byte("test")),
				TPMPolicy: types.TPMPolicyPlatform,
				SealData:  types.NewSealData([]byte("secret")),
				TPMAttributes: &types.TPMAttributes{
					Handle:    tpm2.TPMHandle(nvramOwnerIndex),
					HashAlg:   tpm2.TPMAlgSHA256,
					Hierarchy: tpm2.TPMRHOwner,
				},
			}
			return h.TPM.NVWrite(keyAttrs)
		}
	},
		// The last command is the deferred FlushContext of the salted
		// session that authorized and encrypted the writes: the secret is
		// already written, so its failure is logged, not returned.
		10)
}

// TestNVRead_EveryCommandFailurePropagates sweeps NVRead's command sequence
// (NV read public, platform policy session setup, NV read) against a
// pre-written ordinary index using the platform-policy read path.
func TestNVRead_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		ekAttrs, err := h.TPM.EKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			Parent:    ekAttrs,
			Password:  mustPassword(t, []byte("test")),
			TPMPolicy: types.TPMPolicyPlatform,
			SealData:  types.NewSealData([]byte("secret")),
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramOwnerIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}
		require.NoError(t, h.TPM.NVWrite(keyAttrs))

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.NVRead(keyAttrs, uint16(len("secret")))
			return err
		}
	},
		// The last two commands are the deferred FlushContexts of the salted
		// session that encrypted the data on its way out and of the
		// PolicyPCR session the index's read policy takes: NVRead has already
		// read and returned the data by the time they run, so their failures
		// are logged (see the defers in NVRead) and must not turn a
		// successful read into an error.
		-2, -1)
}

// TestNVDefineCounter_EveryCommandFailurePropagates sweeps NVDefineCounter's
// command sequence (platform policy digest, NV define space).
func TestNVDefineCounter_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		ekAttrs, err := h.TPM.EKAttributes()
		require.NoError(t, err)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			keyAttrs := &types.KeyAttributes{
				Parent:    ekAttrs,
				TPMPolicy: types.TPMPolicyPlatform,
				TPMAttributes: &types.TPMAttributes{
					Handle:    tpm2.TPMHandle(nvramCounterIndex),
					HashAlg:   tpm2.TPMAlgSHA256,
					Hierarchy: tpm2.TPMRHOwner,
				},
			}
			return h.TPM.NVDefineCounter(keyAttrs)
		}
	},
		// The last command is the deferred FlushContext of the salted
		// session that authorized TPM2_NV_DefineSpace; the index is already
		// defined, so its failure is logged, not returned.
		5)
}

// TestNVDefineExtend_EveryCommandFailurePropagates sweeps NVDefineExtend's
// command sequence (platform policy digest, NV define space).
func TestNVDefineExtend_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		ekAttrs, err := h.TPM.EKAttributes()
		require.NoError(t, err)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			keyAttrs := &types.KeyAttributes{
				Parent:    ekAttrs,
				TPMPolicy: types.TPMPolicyPlatform,
				TPMAttributes: &types.TPMAttributes{
					Handle:    tpm2.TPMHandle(nvramExtendIndex),
					HashAlg:   tpm2.TPMAlgSHA256,
					Hierarchy: tpm2.TPMRHOwner,
				},
			}
			return h.TPM.NVDefineExtend(keyAttrs)
		}
	},
		// The last command is the deferred FlushContext of the salted
		// session that authorized TPM2_NV_DefineSpace; the index is already
		// defined, so its failure is logged, not returned.
		5)
}

// TestNVIncrement_EveryCommandFailurePropagates sweeps NVIncrement's command
// sequence against a pre-defined counter index (NV read public, session
// setup, NV increment, NV read-back of the new value).
func TestNVIncrement_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		ekAttrs, err := h.TPM.EKAttributes()
		require.NoError(t, err)

		counter := &types.KeyAttributes{
			Parent: ekAttrs,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramCounterIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}
		require.NoError(t, h.TPM.NVDefineCounter(counter))

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.NVIncrement(counter)
			return err
		}
	})
}

// TestNVReadCounter_EveryCommandFailurePropagates sweeps NVReadCounter's
// command sequence against a pre-defined counter index.
func TestNVReadCounter_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		ekAttrs, err := h.TPM.EKAttributes()
		require.NoError(t, err)

		counter := &types.KeyAttributes{
			Parent: ekAttrs,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramCounterIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}
		require.NoError(t, h.TPM.NVDefineCounter(counter))
		// A freshly-defined counter is TPM_RC_NV_UNINITIALIZED until its
		// first increment (TCG Part 3 §31.15); NVReadCounter cannot be
		// exercised against a counter that has never been written.
		_, err = h.TPM.NVIncrement(counter)
		require.NoError(t, err)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.NVReadCounter(counter)
			return err
		}
	})
}

// TestNVReadExtend_EveryCommandFailurePropagates sweeps NVReadExtend's
// command sequence against a pre-defined extend index.
func TestNVReadExtend_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		ekAttrs, err := h.TPM.EKAttributes()
		require.NoError(t, err)

		extend := &types.KeyAttributes{
			Parent: ekAttrs,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramExtendIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}
		require.NoError(t, h.TPM.NVDefineExtend(extend))
		// A freshly-defined extend index is TPM_RC_NV_UNINITIALIZED until
		// its first extend (TCG Part 3 §31.15); NVReadExtend cannot be
		// exercised against an index that has never been extended.
		require.NoError(t, h.TPM.NVExtend(extend, []byte("measurement")))

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.NVReadExtend(extend)
			return err
		}
	})
}

// TestNVUndefine_EveryCommandFailurePropagates sweeps NVUndefine's command
// sequence (NV read public, NV undefine space) against a pre-defined index.
func TestNVUndefine_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		ekAttrs, err := h.TPM.EKAttributes()
		require.NoError(t, err)

		counter := &types.KeyAttributes{
			Parent: ekAttrs,
			TPMAttributes: &types.TPMAttributes{
				Handle:    tpm2.TPMHandle(nvramCounterIndex),
				HashAlg:   tpm2.TPMAlgSHA256,
				Hierarchy: tpm2.TPMRHOwner,
			},
		}
		require.NoError(t, h.TPM.NVDefineCounter(counter))

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			return h.TPM.NVUndefine(counter)
		}
	})
}

// TestWriteCertToNVRAM_EveryCommandFailurePropagates sweeps
// writeCertToNVRAM's command sequence (NV buffer max capability query, NV
// define space, one or more NV writes).
func TestWriteCertToNVRAM_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			return h.TPM.writeCertToNVRAM(tpm2.TPMHandle(nvramOwnerIndex), []byte("fake-certificate-der"))
		}
	})
}

// TestReadCertFromNVRAM_EveryCommandFailurePropagates sweeps
// readCertFromNVRAM's command sequence against a pre-written certificate.
func TestReadCertFromNVRAM_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		require.NoError(t, h.TPM.writeCertToNVRAM(tpm2.TPMHandle(nvramOwnerIndex), []byte("fake-certificate-der")))

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.readCertFromNVRAM(tpm2.TPMHandle(nvramOwnerIndex))
			return err
		}
	})
}

// TestDeleteCertFromNVRAM_EveryCommandFailurePropagates sweeps
// deleteCertFromNVRAM's command sequence against a pre-written certificate.
func TestDeleteCertFromNVRAM_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		require.NoError(t, h.TPM.writeCertToNVRAM(tpm2.TPMHandle(nvramOwnerIndex), []byte("fake-certificate-der")))

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			return h.TPM.deleteCertFromNVRAM(tpm2.TPMHandle(nvramOwnerIndex))
		}
	})
}

// TestNVWrite_SecretExceedsUint16_ReturnsErrWithoutTouchingTheTPM proves the
// oversized-secret guard rejects the write before any TPM command is
// issued -- a secret this large cannot be represented in NV_DefineSpace's
// uint16 DataSize field at all, so the check must fire in Go, not rely on
// the TPM to reject it.
func TestNVWrite_SecretExceedsUint16_ReturnsErrWithoutTouchingTheTPM(t *testing.T) {
	h := newSimHarness(t, nil)
	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)

	oversized := make([]byte, 1<<16+1)
	keyAttrs := &types.KeyAttributes{
		Parent:   ekAttrs,
		Password: mustPassword(t, []byte("test")),
		SealData: types.NewSealData(oversized),
		TPMAttributes: &types.TPMAttributes{
			Handle:    tpm2.TPMHandle(nvramOwnerIndex),
			HashAlg:   tpm2.TPMAlgSHA256,
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	err = h.TPM.NVWrite(keyAttrs)
	require.ErrorIs(t, err, ErrNVSecretTooLarge)
}
