//go:build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newECCIdentityHarness provisions a device whose EK, IAK and IDevID are
// all P-256. The IDevID follows the EK's algorithm, so only an ECC EK
// yields an ECC IDevID.
func newECCIdentityHarness(t *testing.T) *identityHarness {
	t.Helper()
	h := newSimHarness(t, func(c *Config) {
		c.EK.KeyAlgorithm = x509.ECDSA.String()
		c.EK.RSAConfig = nil
		c.EK.ECCConfig = &store.ECCConfig{Curve: "P-256"}
		c.IAK.KeyAlgorithm = x509.ECDSA.String()
		c.IAK.RSAConfig = nil
		c.IAK.ECCConfig = &store.ECCConfig{Curve: "P-256"}
		c.IAK.SignatureAlgorithm = x509.ECDSAWithSHA256.String()
		c.IDevID = &IDevIDConfig{
			CN:                 "device-id-ecc",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.ECDSA.String(),
			ECCConfig:          &store.ECCConfig{Curve: "P-256"},
			Manufacturer:       "ATT",
			Model:              "xkms-test-device",
			Serial:             "SN-ECC-0001",
			SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		}
	})

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	ekPub, err := h.TPM.EKECC()
	require.NoError(t, err)
	ekCert := selfSignedCertForKey(t, ekPub)

	idevidAttrs, csr, err := h.TPM.CreateIDevID(iakAttrs, ekCert, nil)
	require.NoError(t, err, "an all-ECC device must be able to mint its IDevID")
	require.NotNil(t, csr)
	return &identityHarness{simHarness: h, IAK: iakAttrs, IDevID: idevidAttrs, EKCert: ekCert}
}

// TestCreateIDevID_ECC_RecordsP256Key proves an ECC IDevID records its own
// P-256 public key and its CSR verifies under the ECC IAK.
func TestCreateIDevID_ECC_RecordsP256Key(t *testing.T) {
	h := newECCIdentityHarness(t)

	pub, err := x509.ParsePKIXPublicKey(h.IDevID.TPMAttributes.PublicKeyBytes)
	require.NoError(t, err)
	eccPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok, "the IDevID public key must be ECDSA, got %T", pub)
	assert.Equal(t, elliptic.P256(), eccPub.Curve)

	attrs, _, err := h.TPM.VerifyTCG_CSR_IAK(h.csr(t), x509.ECDSAWithSHA256)
	require.NoError(t, err, "the CSR must verify under the ECC IAK")
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
}

// TestCreateIDevID_RecreateReplacesPersistedKey proves a second CreateIDevID
// evicts the persisted IDevID and persists the new one in its place instead
// of failing on the occupied handle.
func TestCreateIDevID_RecreateReplacesPersistedKey(t *testing.T) {
	h := newECCIdentityHarness(t)
	first := h.IDevID.TPMAttributes.PublicKeyBytes

	second, _, err := h.TPM.CreateIDevID(h.IAK, h.EKCert, []byte("nonce"))
	require.NoError(t, err)
	assert.Equal(t, h.IDevID.TPMAttributes.Handle, second.TPMAttributes.Handle)
	_, persisted, err := h.TPM.ReadHandle(second.TPMAttributes.Handle)
	require.NoError(t, err)
	assert.Equal(t, second.TPMAttributes.Public.Unique, persisted.Unique,
		"the handle must hold the key just created")
	assert.NotEmpty(t, first)
}

// TestCreateIDevID_ConfigErrors proves CreateIDevID refuses a missing,
// unparseable or unnamed IDevID configuration before touching the TPM.
func TestCreateIDevID_ConfigErrors(t *testing.T) {
	h := newECCIdentityHarness(t)

	saved := h.TPM.config.IDevID
	h.TPM.config.IDevID = nil
	_, _, err := h.TPM.CreateIDevID(h.IAK, h.EKCert, nil)
	assert.ErrorIs(t, err, ErrNotConfigured)

	bad := *saved
	bad.ECCConfig = &store.ECCConfig{Curve: "no-such-curve"}
	h.TPM.config.IDevID = &bad
	_, _, err = h.TPM.CreateIDevID(h.IAK, h.EKCert, nil)
	assert.Error(t, err)

	unnamed := *saved
	unnamed.CN, unnamed.Model, unnamed.Serial = "", "", ""
	h.TPM.config.IDevID = &unnamed
	_, _, err = h.TPM.CreateIDevID(h.IAK, h.EKCert, nil)
	assert.Error(t, err, "an IDevID with no name and no model/serial must be refused")

	oversized := *saved
	oversized.KeyAlgorithm = x509.RSA.String()
	oversized.ECCConfig = nil
	oversized.RSAConfig = &store.RSAConfig{KeySize: 1 << 17}
	oversized.SignatureAlgorithm = x509.SHA256WithRSAPSS.String()
	h.TPM.config.IDevID = &oversized
	_, _, err = h.TPM.CreateIDevID(h.IAK, h.EKCert, nil)
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}
