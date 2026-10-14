//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lakCertHandle is the NV index the NV RAM mode tests store the LAK
// certificate at; it sits beside the IDevID/IAK indexes newNVRAMCertTPM uses.
const lakCertHandle = 0x01C90020

// newLAKCertHarness returns a simulator TPM with the LAK created and an
// in-memory certificate store wired, ready for certificate provisioning.
func newLAKCertHarness(t *testing.T) *simHarness {
	t.Helper()
	h := newLAKHarness(t)
	_, err := h.TPM.CreateLAK(nil, h.Backend, false)
	require.NoError(t, err)
	h.TPM.certStore = store.NewMemoryCertStore(h.Logger)
	return h
}

// TestLAKCertificate_NotConfigured pins that every LAK certificate method
// refuses a TPM with no LAK config instead of reaching for a handle.
func TestLAKCertificate_NotConfigured(t *testing.T) {
	h := newSimHarness(t, nil)

	assert.ErrorIs(t, h.TPM.ProvisionLAKCert(nil), ErrNotConfigured)
	_, err := h.TPM.LAKCertificate()
	assert.ErrorIs(t, err, ErrNotConfigured)
	assert.ErrorIs(t, h.TPM.DeleteLAKCertificate(), ErrNotConfigured)
}

// TestLAKCertificate_NotCreated pins that provisioning or reading a
// certificate before the LAK exists surfaces the missing key, not a
// certificate-store error.
func TestLAKCertificate_NotCreated(t *testing.T) {
	h := newLAKHarness(t)
	cert := createTestCertWithKey(t, &mustECDSAKey(t).PublicKey)

	assert.Error(t, h.TPM.ProvisionLAKCert(cert))
	_, err := h.TPM.LAKCertificate()
	assert.Error(t, err)
}

// TestLAKCertificate_StoreRoundTrip covers the certificate-store mode
// (CertHandle zero): provision, read back, delete, then not-found.
func TestLAKCertificate_StoreRoundTrip(t *testing.T) {
	h := newLAKCertHarness(t)
	lakAttrs, err := h.TPM.LAKAttributes()
	require.NoError(t, err)
	cert := certForTPMKey(t, lakAttrs, "lak-device-001")

	_, err = h.TPM.LAKCertificate()
	require.ErrorIs(t, err, ErrLAKCertNotFound, "no certificate is stored yet")

	require.NoError(t, h.TPM.ProvisionLAKCert(cert))
	stored, err := h.TPM.LAKCertificate()
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, stored.Raw)

	require.NoError(t, h.TPM.DeleteLAKCertificate())
	_, err = h.TPM.LAKCertificate()
	assert.ErrorIs(t, err, ErrLAKCertNotFound)
}

// TestLAKCertificate_NVRAMRoundTrip covers the NV RAM mode with no
// certificate store wired, proving the store is never consulted.
func TestLAKCertificate_NVRAMRoundTrip(t *testing.T) {
	h := newLAKCertHarness(t)
	h.TPM.config.LAK.CertHandle = lakCertHandle
	h.TPM.certStore = nil
	lakAttrs, err := h.TPM.LAKAttributes()
	require.NoError(t, err)
	cert := certForTPMKey(t, lakAttrs, "lak-device-001")

	require.NoError(t, h.TPM.ProvisionLAKCert(cert))
	stored, err := h.TPM.LAKCertificate()
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, stored.Raw)

	require.NoError(t, h.TPM.DeleteLAKCertificate())
	_, err = h.TPM.LAKCertificate()
	assert.Error(t, err, "the NV index is gone after delete")
}

// TestProvisionLAKCert_PublicKeyMismatch pins that a certificate for some
// other key is rejected and nothing is stored.
func TestProvisionLAKCert_PublicKeyMismatch(t *testing.T) {
	h := newLAKCertHarness(t)
	cert := createTestCertWithKey(t, &mustECDSAKey(t).PublicKey)

	assert.ErrorIs(t, h.TPM.ProvisionLAKCert(cert), ErrCertPublicKeyMismatch)
	_, err := h.TPM.LAKCertificate()
	assert.ErrorIs(t, err, ErrLAKCertNotFound)
}

// TestLAKCertificate_StoreNotConfigured pins the typed error when store
// mode is configured but no certificate store is wired.
func TestLAKCertificate_StoreNotConfigured(t *testing.T) {
	h := newLAKCertHarness(t)
	h.TPM.certStore = nil

	_, err := h.TPM.LAKCertificate()
	assert.ErrorIs(t, err, ErrCertStoreNotConfigured)
	assert.ErrorIs(t, h.TPM.DeleteLAKCertificate(), ErrCertStoreNotConfigured)
}
