//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestCreateECDSA_EveryCommandFailurePropagates sweeps CreateECDSA's command
// sequence (parent session setup, TPM2_Create, TPM2_Load, readback, blob
// persistence) proving a failure at any TPM round trip surfaces as an error
// rather than leaving a half-created key silently reported as success.
func TestCreateECDSA_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		tpm, srkAttrs, backend := deleteKeyRegressionFixture(t, false)
		tpmImpl := tpm.(*TPM2)

		return tpmImpl.transport, func(tr transport.TPM) error {
			tpmImpl.transport = tr
			genAttrs := &types.KeyAttributes{
				CN:            "create-ecdsa-sweep",
				KeyAlgorithm:  x509.ECDSA,
				KeyType:       types.KeyTypeSigning,
				StoreType:     types.StoreTPM2,
				Parent:        srkAttrs,
				ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
			}
			_, err := tpmImpl.CreateECDSA(genAttrs, backend, true)
			return err
		}
	},
		// The final command is the deferred tpm.Flush of the new key's
		// transient handle (ecdsa.go): it fires unconditionally, including
		// on the success path, and its own contract (tpm.Flush, mirroring
		// flushSilent) is to log a flush failure rather than fail the
		// caller's already-completed key creation.
		7)
}

// TestCreateRSA_EveryCommandFailurePropagates sweeps CreateRSA's command
// sequence the same way TestCreateECDSA_EveryCommandFailurePropagates does
// for the RSA key path.
func TestCreateRSA_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		tpm, srkAttrs, backend := deleteKeyRegressionFixture(t, false)
		tpmImpl := tpm.(*TPM2)

		return tpmImpl.transport, func(tr transport.TPM) error {
			tpmImpl.transport = tr
			genAttrs := &types.KeyAttributes{
				CN:            "create-rsa-sweep",
				KeyAlgorithm:  x509.RSA,
				KeyType:       types.KeyTypeSigning,
				StoreType:     types.StoreTPM2,
				Parent:        srkAttrs,
				RSAAttributes: &types.RSAAttributes{KeySize: 2048},
			}
			_, err := tpmImpl.CreateRSA(genAttrs, backend, true)
			return err
		}
	},
		// See the matching comment in TestCreateECDSA_EveryCommandFailurePropagates:
		// the final command is the deferred best-effort transient-handle flush.
		7)
}
