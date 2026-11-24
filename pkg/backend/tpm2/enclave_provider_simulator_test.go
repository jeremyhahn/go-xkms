//go:build tpm_simulator

// The enclave provider conformance suite over the TPM 2.0 Backend, the
// Sealer go-xkms ships to callers (docs/enclaveprovider/tpm-equivalence.md
// row 31). pkg/tpm2 runs the same suite over its *TPM2 directly.

package tpm2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/enclaveprovider/enclaveprovidertest"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func TestEnclaveProvider_Conformance_Simulator(t *testing.T) {
	b := newSimBackend(t)
	objectAuth, err := types.NewPasswordFromString("enclave-provider-object-auth")
	require.NoError(t, err)
	enclaveprovidertest.Run(t, enclaveprovidertest.Backend{
		Sealer: b,
		KeyAttributes: &types.KeyAttributes{
			CN:       "enclave-provider",
			Parent:   b.SRKAttributes(),
			Password: objectAuth,
		},
		SkipResidueSweep: "the reference TPM simulator runs in this process and holds the unsealed secret in its own RAM; the TPM2_Unseal response crosses the command transport's buffers below pkg/tpm2",
	})
}
