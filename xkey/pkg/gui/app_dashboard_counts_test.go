package gui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewApp_StatusCountsLocalInventory verifies that once the local stores
// are open the dashboard status counts what they hold: OATH accounts and
// FIDO2 credentials add up to the key count, and only occupied PIV slots
// count as certificates.
func TestNewApp_StatusCountsLocalInventory(t *testing.T) {
	app := newPIVReadyApp(t)

	empty := app.appService.GetStatus()
	require.NotNil(t, empty)
	assert.Zero(t, empty.KeyCount)
	assert.Zero(t, empty.OATHAccountCount)
	assert.Zero(t, empty.FIDO2CredCount)
	assert.Zero(t, empty.PIVCertCount, "no slot is occupied yet")

	_, err := app.oathService.AddAccount("otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256&issuer=Example")
	require.NoError(t, err)
	storePIVCert(t, "software")

	status := app.appService.GetStatus()
	require.NotNil(t, status)
	assert.Equal(t, 1, status.OATHAccountCount)
	assert.Zero(t, status.FIDO2CredCount)
	assert.Equal(t, 1, status.KeyCount, "the key count sums OATH accounts and FIDO2 credentials")
	assert.Equal(t, 1, status.PIVCertCount)
}
