//go:build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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
