//go:build tpm_simulator

package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCreateFIDO2TPM2KeyBackendOpensProvisionedTPM is ruling 988: after
// `tpm install` provisioned the TPM (and setup enrolled the Platform SRK), the
// fido2 tpm2 backend opens it with the same configuration the `tpm` commands
// use (SSRK, EK, IAK, IDevID, LAK), and so creates credential keys under the
// provisioned SRK.
func TestCreateFIDO2TPM2KeyBackendOpensProvisionedTPM(t *testing.T) {
	sim := installTPMForSRK(t)
	pinFile := writeSRKPINFile(t, testSRKUserPIN)

	_, err := runSRKEnroll(t, "", "--pin-file", pinFile)
	require.NoError(t, err)

	require.NoError(t, createSRKCredential(t, sim, pinFile, ""))
}
