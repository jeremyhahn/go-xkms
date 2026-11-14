//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newEmptyAuthSimHarness is newSimHarness with the EK hierarchy auth left
// unset in the configuration. The harness provisions without an SO PIN, so
// the TPM's hierarchy auth stays empty; the configuration has to say so for
// the EK attributes a fresh process derives from it to authorize correctly.
func newEmptyAuthSimHarness(t *testing.T) *simHarness {
	t.Helper()
	return newSimHarness(t, func(c *Config) { c.EK.HierarchyAuth = nil })
}

// writeEKCertToNV issues a certificate for ekPub from a throwaway CA and
// writes it to the EK certificate NV index, the way a TPM manufacturer
// leaves an EK Credential Profile certificate behind.
func writeEKCertToNV(t *testing.T, tpm *TPM2, ekPub crypto.PublicKey) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, ekPub, caKey)
	require.NoError(t, err)

	require.NoError(t, tpm.ProvisionEKCert(nil, der))
}

// evictPersistentEK removes the persistent EK, leaving the TPM in the state
// TPM2_Clear leaves it in: the endorsement seed, and so the EK it derives,
// is unchanged and the manufacturer certificate is still in NV, but no EK
// is loaded at the configured persistent handle.
func evictPersistentEK(t *testing.T, tpm *TPM2) {
	t.Helper()

	handle := tpm2.TPMHandle(tpm.config.EK.Handle)
	name, _, err := tpm.ReadHandle(handle)
	require.NoError(t, err)
	require.NoError(t, tpm.evictControl(
		tpm2.TPMRHOwner, nil, tpm2.NamedHandle{Handle: handle, Name: name}, handle))
}

// TestAnswerCredentialChallenge_NonPersistentEK_CreatesTransientEK is the
// reproduction of #1437: with the EK certificate in NV and no persistent EK,
// the challenge is answered by an EK created transiently from the TCG
// template matching the certificate, and that EK is flushed afterwards.
func TestAnswerCredentialChallenge_NonPersistentEK_CreatesTransientEK(t *testing.T) {
	h := newEmptyAuthSimHarness(t)

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	writeEKCertToNV(t, h.TPM, ekPub)
	evictPersistentEK(t, h.TPM)
	// Start from the attributes a freshly started process derives.
	h.TPM.ekAttrs = nil

	key, err := h.TPM.CreateActivationKey()
	require.NoError(t, err)
	challenge, secret, err := NewCredentialChallenge(ekPub, key.Name.Buffer)
	require.NoError(t, err)

	got, err := h.TPM.AnswerCredentialChallenge(key, challenge)
	require.NoError(t, err)
	assert.Equal(t, secret, got)

	handles, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)
	assert.Empty(t, handles, "the transient EK and the activation key must both be flushed")
}

// TestAnswerCredentialChallenge_ECCEKUsesTheResolvedCertIndex: an ECC P-256
// EK config that keeps the default CertHandle 0x01C00002 reads its
// certificate at 0x01C0000A (TCG EK Credential Profile v2.1 §2.2.1.4) when no
// persistent EK exists, and never the unrelated RSA certificate at the
// configured handle.
func TestAnswerCredentialChallenge_ECCEKUsesTheResolvedCertIndex(t *testing.T) {
	h := newSimHarness(t, func(c *Config) {
		c.EK.HierarchyAuth = nil
		c.EK.CertHandle = ekCertIndexRSA2048
		c.EK.KeyAlgorithm = x509.ECDSA.String()
		c.EK.RSAConfig = nil
		c.EK.ECCConfig = &store.ECCConfig{Curve: "P-256"}
	})

	ekPub, err := h.TPM.EKECC()
	require.NoError(t, err)
	writeEKCertToNV(t, h.TPM, ekPub)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "unrelated-rsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	rsaDER, err := x509.CreateCertificate(rand.Reader, rsaTemplate, rsaTemplate, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	require.NoError(t, h.TPM.writeCertToNVRAM(tpm2.TPMHandle(ekCertIndexRSA2048), nil, rsaDER))
	evictPersistentEK(t, h.TPM)
	h.TPM.ekAttrs = nil

	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMHandle(ekCertIndexECCP256), ekAttrs.TPMAttributes.CertHandle)

	key, err := h.TPM.CreateActivationKey()
	require.NoError(t, err)
	challenge, secret, err := NewCredentialChallenge(ekPub, key.Name.Buffer)
	require.NoError(t, err)

	got, err := h.TPM.AnswerCredentialChallenge(key, challenge)
	require.NoError(t, err)
	assert.Equal(t, secret, got)
}

// TestAnswerCredentialChallenge_P384ConfigReadsTheP384CertIndex: an ECDSA
// P-384 EK config on the default CertHandle discovers its certificate at
// 0x01C00016 (TCG EK Credential Profile v2.1 §2.2.1.4), so a manufacturer's
// certificate there reads back. CreateEK has only the P-256 ECCEKTemplate,
// so provisioning a P-384 certificate is refused with ErrEKCertKeyType.
func TestAnswerCredentialChallenge_P384ConfigReadsTheP384CertIndex(t *testing.T) {
	h := newSimHarness(t, func(c *Config) {
		c.EK.HierarchyAuth = nil
		c.EK.CertHandle = ekCertIndexRSA2048
		c.EK.KeyAlgorithm = x509.ECDSA.String()
		c.EK.RSAConfig = nil
		c.EK.ECCConfig = &store.ECCConfig{Curve: "P-384"}
	})

	ekPub, err := h.TPM.EKECC()
	require.NoError(t, err)
	require.Equal(t, elliptic.P256(), ekPub.Curve, "CreateEK uses the P-256 template")

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, ekPub, caKey)
	require.NoError(t, err)

	// Provisioning refuses the P-384 index: no EK template makes that key.
	assert.ErrorIs(t, h.TPM.ProvisionEKCert(nil, der), ErrEKCertKeyType)
	_, err = tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(ekCertIndexECCP384)}.Execute(h.TPM.transport)
	assert.ErrorIs(t, err, tpmRCHandle, "provisioning writes nothing at the P-384 index")

	// A certificate the manufacturer put at the P-384 index is still found,
	// and the unrelated one at the configured RSA index is never read.
	unrelated := createTestCertDER(t)
	require.NoError(t, h.TPM.writeCertToNVRAM(tpm2.TPMHandle(ekCertIndexRSA2048), nil, unrelated))
	require.NoError(t, h.TPM.writeCertToNVRAM(tpm2.TPMHandle(ekCertIndexECCP384), nil, der))
	got, err := h.TPM.EKCertificate()
	require.NoError(t, err)
	assert.Equal(t, der, got.Raw, "EKCertificate reads the P-384 index")

	evictPersistentEK(t, h.TPM)
	h.TPM.ekAttrs = nil
	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMHandle(ekCertIndexECCP384), ekAttrs.TPMAttributes.CertHandle)

	// Recovery has no transient template for a high-range index, so it is
	// refused typed instead of activating with another certificate.
	key, err := h.TPM.CreateActivationKey()
	require.NoError(t, err)
	challenge, _, err := NewCredentialChallenge(ekPub, key.Name.Buffer)
	require.NoError(t, err)
	_, err = h.TPM.AnswerCredentialChallenge(key, challenge)
	assert.ErrorIs(t, err, ErrEKTemplateUnsupported)
}

// TestAnswerCredentialChallenge_NonPersistentEK_NoCertInNV proves a missing
// persistent EK with no EK certificate in NV is refused with
// ErrEKCertNotInNV: there is nothing to select or verify a template against.
func TestAnswerCredentialChallenge_NonPersistentEK_NoCertInNV(t *testing.T) {
	h := newEmptyAuthSimHarness(t)

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	evictPersistentEK(t, h.TPM)

	key, err := h.TPM.CreateActivationKey()
	require.NoError(t, err)
	challenge, _, err := NewCredentialChallenge(ekPub, key.Name.Buffer)
	require.NoError(t, err)

	_, err = h.TPM.AnswerCredentialChallenge(key, challenge)
	assert.ErrorIs(t, err, ErrEKCertNotInNV)
}

// TestAnswerCredentialChallenge_NonPersistentEK_UnsupportedCertKey proves a
// certificate whose key has no TCG EK template in this package (P-384) is
// refused with ErrEKTemplateUnsupported before any EK is created.
func TestAnswerCredentialChallenge_NonPersistentEK_UnsupportedCertKey(t *testing.T) {
	h := newEmptyAuthSimHarness(t)

	certKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	writeEKCertToNV(t, h.TPM, &certKey.PublicKey)
	evictPersistentEK(t, h.TPM)
	h.TPM.ekAttrs = nil

	key, err := h.TPM.CreateActivationKey()
	require.NoError(t, err)
	challenge, _, err := NewCredentialChallenge(&certKey.PublicKey, key.Name.Buffer)
	require.NoError(t, err)

	_, err = h.TPM.AnswerCredentialChallenge(key, challenge)
	assert.ErrorIs(t, err, ErrEKTemplateUnsupported)
}

// TestAnswerCredentialChallenge_NonPersistentEK_CertKeyMismatch proves the
// transient EK is checked against the certificate: a certificate for a key
// this TPM's endorsement seed does not derive is refused with
// ErrEKPublicKeyMismatch, and the transient EK is still flushed.
func TestAnswerCredentialChallenge_NonPersistentEK_CertKeyMismatch(t *testing.T) {
	h := newEmptyAuthSimHarness(t)

	foreignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	writeEKCertToNV(t, h.TPM, &foreignKey.PublicKey)
	evictPersistentEK(t, h.TPM)
	h.TPM.ekAttrs = nil

	key, err := h.TPM.CreateActivationKey()
	require.NoError(t, err)
	challenge, _, err := NewCredentialChallenge(&foreignKey.PublicKey, key.Name.Buffer)
	require.NoError(t, err)

	_, err = h.TPM.AnswerCredentialChallenge(key, challenge)
	assert.ErrorIs(t, err, ErrEKPublicKeyMismatch)

	handles, err := transientHandles(h.TPM.transport)
	require.NoError(t, err)
	assert.Empty(t, handles, "the transient EK must be flushed on the refusal path")
}
