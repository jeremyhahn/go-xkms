//go:build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestCreateStorageKey_EveryCommandFailurePropagates sweeps
// CreateStorageKey's command sequence (parent read, session setup,
// TPM2_Create, blob persistence) proving no TPM failure is reported as a
// created storage key.
func TestCreateStorageKey_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		srkAttrs := createPlatformPolicySRK(t, h, mustPassword(t, []byte("platform-srk-pin")))

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			return h.TPM.CreateStorageKey(&types.KeyAttributes{
				CN:            "storage-key-sweep",
				KeyAlgorithm:  x509.RSA,
				KeyType:       types.KeyTypeStorage,
				Parent:        srkAttrs,
				Password:      mustPassword(t, []byte("storage-key-secret")),
				StoreType:     types.StoreTPM2,
				TPMAttributes: &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
			}, h.Backend)
		}
	},
		// The last two commands are the deferred flushes of the parent's
		// policy session and the encryption session; both are logged, not
		// returned.
		10, 11)
}

// TestCreateSecretKey_EveryCommandFailurePropagates sweeps CreateSecretKey's
// command sequence the same way for the AES secret key path.
func TestCreateSecretKey_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		attrs := childKeyAttrs(t, h, "secret-key-sweep", x509.RSA, types.KeyTypeHMAC)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			return h.TPM.CreateSecretKey(attrs, h.Backend)
		}
	},
		// The last command is the deferred flush of the session that
		// encrypted the key's sensitive area; it is logged, not returned.
		5)
}

// TestCreateLAK_EveryCommandFailurePropagates sweeps CreateLAK's command
// sequence (key creation, reload, persistence, readback) proving no TPM
// failure leaves a LAK reported as persisted.
func TestCreateLAK_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newLAKHarness(t)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.CreateLAK(nil, h.Backend, false)
			return err
		}
	},
		// The last command is a deferred best-effort session flush.
		-1)
}

// TestSealKey_EveryCommandFailurePropagates sweeps SealKey's command
// sequence proving no TPM failure is reported as a sealed secret.
func TestSealKey_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		attrs := sealedKeyAttrs(t, h, "seal-sweep", false, mustPassword(t, []byte("seal-pin")))

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.SealKey(attrs, h.Backend, true)
			return err
		}
	},
		// The last command is a deferred best-effort session flush.
		7)
}

// TestUnsealKey_EveryCommandFailurePropagates sweeps UnsealKey's command
// sequence against a sealed secret proving no TPM failure yields a secret.
func TestUnsealKey_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		attrs := sealedKeyAttrs(t, h, "unseal-sweep", false, mustPassword(t, []byte("seal-pin")))
		attrs.SealData = types.NewSealData([]byte("sealed-sweep-secret"))
		_, err := h.TPM.SealKey(attrs, h.Backend, true)
		require.NoError(t, err)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.UnsealKey(sealedKeyAttrs(t, h, "unseal-sweep", false, mustPassword(t, []byte("seal-pin"))), h.Backend)
			return err
		}
	},
		// The last three commands are the deferred best-effort flushes of
		// the loaded object and its sessions.
		8, 9, 10)
}

// TestQuote_EveryCommandFailurePropagates sweeps Quote's command sequence
// (TPM2_Quote, then one PCR read per bank and PCR) proving no TPM failure
// yields a quote. A failed PCR read used to drop its bank silently, so the
// quote was returned with PCR state missing banks the TPM has.
func TestQuote_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.Quote([]uint{0, 7}, []byte("quote-sweep-nonce"))
			return err
		}
	})
}

// TestReadPCRs_ReadFailureIsReported proves a PCR read that fails for a
// reason other than an unsupported bank is reported, not skipped.
func TestReadPCRs_ReadFailureIsReported(t *testing.T) {
	h := newSimHarness(t, nil)
	healthy := h.TPM.transport
	t.Cleanup(func() { h.TPM.transport = healthy })

	banks, err := h.TPM.ReadPCRs([]uint{0})
	require.NoError(t, err)
	require.NotEmpty(t, banks)

	h.TPM.transport = &nSendTransport{inner: healthy, n: 1}
	banks, err = h.TPM.ReadPCRs([]uint{0})
	require.ErrorIs(t, err, ErrPCRRead)
	require.Nil(t, banks)
}
