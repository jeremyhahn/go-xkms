//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// platformCertIndices are the NV indices this package defines for the
// IDevID and IAK certificates, which a factory reset must release.
var platformCertIndices = []tpm2.TPMHandle{iakCert, idevIDCert}

// TestFactoryReset_UndefinesPlatformCertIndices proves a factory reset
// releases the IDevID and IAK certificate NV indices it provisioned.
func TestFactoryReset_UndefinesPlatformCertIndices(t *testing.T) {
	h := newSimHarness(t, nil)
	for _, index := range platformCertIndices {
		require.NoError(t, h.TPM.writeCertToNVRAM(index, []byte("platform-certificate-der")))
	}

	require.NoError(t, h.TPM.FactoryReset(nil))

	for _, index := range platformCertIndices {
		_, err := tpm2.NVReadPublic{NVIndex: index}.Execute(h.TPM.transport)
		assert.Error(t, err, "NV index 0x%08X must be undefined by the reset", uint32(index))
	}
}

// TestFactoryReset_RefusedUndefineKeepsCertIndices proves an NV undefine the
// owner hierarchy refuses is reported as ErrFactoryReset and leaves the
// certificate in place.
func TestFactoryReset_RefusedUndefineKeepsCertIndices(t *testing.T) {
	h := newSimHarness(t, nil)
	require.NoError(t, h.TPM.writeCertToNVRAM(iakCert, []byte("platform-certificate-der")))

	err := h.TPM.FactoryReset([]byte("not-the-owner-auth"))
	assert.ErrorIs(t, err, ErrFactoryReset)

	cert, err := h.TPM.readCertFromNVRAM(iakCert)
	require.NoError(t, err, "a refused reset must leave the certificate index defined")
	assert.Equal(t, []byte("platform-certificate-der"), cert)
}
