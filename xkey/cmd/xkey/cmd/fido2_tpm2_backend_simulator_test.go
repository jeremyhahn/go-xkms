//go:build tpm_simulator

package cmd

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/xkmstest"
)

// TestCreateFIDO2TPM2KeyBackendOpensProvisionedTPM is ruling 988: after
// `tpm install` provisioned the TPM (and setup enrolled the Platform SRK), the
// fido2 tpm2 backend opens it with the same configuration the `tpm` commands
// use (SSRK, EK, IAK, IDevID, LAK), and so creates credential keys under the
// provisioned SRK.
func TestCreateFIDO2TPM2KeyBackendOpensProvisionedTPM(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	cfg := xkms.DefaultTPMConfig
	require.NoError(t, xkmstest.EnrollPlatformSRK(sim.tpm, &cfg))

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend, err := createFIDO2TPM2KeyBackend(&FIDO2Config{TPMDevice: ""}, logger)
	require.NoError(t, err)
	require.NotNil(t, backend)
	t.Cleanup(func() {
		assert.NoError(t, backend.Close())
	})

	const coseES256 = -7
	handle, publicKey, err := backend.GenerateCredentialKey(coseES256, []byte("ruling-988-credential"))
	require.NoError(t, err)
	assert.NotEmpty(t, publicKey)
	assert.NotNil(t, handle)
}
