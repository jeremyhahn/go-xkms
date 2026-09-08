//go:build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

// These tests pin the provisioning ceremony of TCG "TPM 2.0 Keys for Device
// Identity and Attestation" v1.00 r12 to its fail-closed shape: the ceremony
// either completes or the device has no identity, and Install says which.
//
// Before this, Install discarded the EK certificate lookup error, logged a
// failed CreateIDevID as "continuing without it", ignored every lookup error
// other than TPM_RC_HANDLE, and returned nil -- so a device with no IDevID
// reported itself provisioned. Every test here fails against that code.

// idevidInstallHarness provisions a simulator with an IDevID configured but
// no EK certificate anywhere the TPM could find one: nothing in NV RAM, and
// the certificate store is not consulted while a cert handle is configured.
func idevidInstallHarness(t *testing.T) *simHarness {
	t.Helper()
	return newSimHarness(t, func(c *Config) {
		c.IDevID = &IDevIDConfig{
			CN:                 "device-id-001",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			Manufacturer:       "ATT",
			Model:              "xkms-test-device",
			Pad:                true,
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			Serial:             "SN-0000-0001",
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		}
	})
}

// identityOnly asks Install for the IDevID step alone. Provision has already
// created the EK, SRK and IAK, and no SO PIN is passed so the hierarchy
// authorizations stay as Provision left them.
func identityOnly() *InstallOptions {
	return &InstallOptions{IDevID: true}
}

func TestInstall_IDevID_RefusesWithoutEKCertificate(t *testing.T) {
	h := idevidInstallHarness(t)

	err := h.TPM.Install(nil, identityOnly())
	require.Error(t, err, "a device that cannot carry its EK certificate in the CSR cannot enroll (section 6.2.2 step 4b)")
	assert.ErrorIs(t, err, ErrDevIDProvisionEKCert)
	assert.ErrorIs(t, err, ErrEndorsementCertNotFound, "the cause must remain reachable")

	_, err = h.TPM.IDevIDAttributes()
	require.Error(t, err, "no IDevID may be minted when the ceremony cannot complete")
	assert.ErrorIs(t, err, tpmRCHandle, "the IDevID handle must still be empty")
}

func TestInstall_IDevID_CreatesIdentityWhenEKCertificatePresent(t *testing.T) {
	h := idevidInstallHarness(t)

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	ekCert := selfSignedCertForKey(t, ekPub)
	require.NoError(t, h.TPM.ProvisionEKCert(nil, ekCert.Raw),
		"the test acts as the TPM manufacturer and writes the EK certificate to NV RAM")

	require.NoError(t, h.TPM.Install(nil, identityOnly()))

	idevid, err := h.TPM.IDevIDAttributes()
	require.NoError(t, err, "Install must leave a usable IDevID behind")
	require.NotNil(t, idevid.TPMAttributes)
	assert.NotEmpty(t, idevid.TPMAttributes.Name.Buffer)

	t.Run("a second Install finds the IDevID and does nothing", func(t *testing.T) {
		require.NoError(t, h.TPM.Install(nil, identityOnly()))

		again, err := h.TPM.IDevIDAttributes()
		require.NoError(t, err)
		assert.Equal(t, idevid.TPMAttributes.Name.Buffer, again.TPMAttributes.Name.Buffer,
			"the IDevID must not be re-created once it exists")
	})
}

func TestInstall_IDevID_LookupFaultIsRefused(t *testing.T) {
	h := idevidInstallHarness(t)

	// Warm the IAK cache so the injected fault lands on the IDevID lookup and
	// nowhere earlier.
	_, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	faulty := &createFaultyTransport{inner: h.TPM.transport, failCC: tpm2.TPMCCReadPublic}
	h.TPM.transport = faulty
	t.Cleanup(func() { h.TPM.transport = faulty.inner })

	err = h.TPM.Install(nil, identityOnly())
	require.Error(t, err, "a lookup answer other than TPM_RC_HANDLE is a fault, not an absent key")
	assert.ErrorIs(t, err, ErrDevIDProvisionLookup)
	assert.NotErrorIs(t, err, ErrDevIDProvisionEKCert,
		"the fault must be reported as what it is, not as a missing certificate")
	assert.Equal(t, 1, faulty.failCount, "the fault must have fired on the IDevID lookup")
}

func TestInstall_IDevID_CreationFailureIsRefused(t *testing.T) {
	h := idevidInstallHarness(t)

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	require.NoError(t, h.TPM.ProvisionEKCert(nil, selfSignedCertForKey(t, ekPub).Raw))

	_, err = h.TPM.IAKAttributes()
	require.NoError(t, err)

	faulty := &createFaultyTransport{inner: h.TPM.transport, failCC: tpm2.TPMCCCreatePrimary}
	h.TPM.transport = faulty
	t.Cleanup(func() { h.TPM.transport = faulty.inner })

	err = h.TPM.Install(nil, identityOnly())
	require.Error(t, err, "a failed CreateIDevID is a failed ceremony; previously it was logged and skipped")
	assert.ErrorIs(t, err, ErrDevIDProvisionIDevID)
	assert.Equal(t, 1, faulty.failCount, "the fault must have fired on TPM2_CreatePrimary")

	h.TPM.transport = faulty.inner
	_, err = h.TPM.IDevIDAttributes()
	require.Error(t, err)
	assert.ErrorIs(t, err, tpmRCHandle, "nothing may be left at the IDevID handle after a refused ceremony")
}

func TestInstall_IAK_LookupFaultIsRefused(t *testing.T) {
	h := newSimHarness(t, nil)

	// Provision cached the EK attributes and the IAK attributes. Drop the
	// IAK cache so Install has to ask the TPM, and let that be the command
	// that faults.
	h.TPM.iakAttrs = nil
	_, err := h.TPM.EKAttributes()
	require.NoError(t, err)

	faulty := &createFaultyTransport{inner: h.TPM.transport, failCC: tpm2.TPMCCReadPublic}
	h.TPM.transport = faulty
	t.Cleanup(func() { h.TPM.transport = faulty.inner })

	err = h.TPM.Install(nil, &InstallOptions{IAK: true})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDevIDProvisionLookup)
	assert.Equal(t, 1, faulty.failCount, "the fault must have fired on the IAK lookup")
}

func TestInstall_IAK_FindsExistingKey(t *testing.T) {
	h := newSimHarness(t, nil)

	before, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	require.NoError(t, h.TPM.Install(nil, &InstallOptions{IAK: true}))

	after, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	assert.Equal(t, before.TPMAttributes.Name.Buffer, after.TPMAttributes.Name.Buffer,
		"an existing IAK must be found, not re-created")
}
