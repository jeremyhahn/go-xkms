//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestCreateRSA_EveryCommandFailurePropagates sweeps CreateRSA's command
// sequence the same way TestCreateECDSA_EveryCommandFailurePropagates does
// for the RSA key path.
func TestCreateRSA_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		tpm, srkAttrs, backend := deleteKeyRegressionFixture(t)
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
		// the final three commands are the deferred best-effort flushes.
		10, 11, 12)
}
