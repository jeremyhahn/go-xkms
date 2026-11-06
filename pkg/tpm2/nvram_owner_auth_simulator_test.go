//go:build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newOwnedSimHarness returns a provisioned simulator whose owner hierarchy
// is protected by soPIN, the state of a TPM an operator has taken ownership
// of.
func newOwnedSimHarness(t *testing.T, mutate func(*Config), soPIN []byte) *simHarness {
	t.Helper()
	h := newSimHarness(t, mutate)
	owner := tpm2.TPMRHOwner
	require.NoError(t, h.TPM.SetHierarchyAuth(nil, mustPassword(t, soPIN), &owner))
	return h
}

// TestWriteCertToNVRAM_OwnedTPMWritesWithSuppliedAuth: on an owned TPM the
// define and write run under TPM_RH_OWNER with the caller's authorization
// (Part 3 §31.3.1, §31.7.1).
func TestWriteCertToNVRAM_OwnedTPMWritesWithSuppliedAuth(t *testing.T) {
	soPIN := []byte("so-pin-1725-owned")
	h := newOwnedSimHarness(t, nil, soPIN)
	index := tpm2.TPMHandle(nvramOwnerIndex)
	cert := nvramTestCert(t)

	require.NoError(t, h.TPM.writeCertToNVRAM(index, soPIN, cert.Raw))

	got, err := h.TPM.readCertFromNVRAM(index)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, got)
}

// TestWriteCertToNVRAM_WrongOwnerAuthFailsTyped: a wrong or missing SO PIN
// is reported as ErrNVCertHierarchyAuth, and no index is left behind.
func TestWriteCertToNVRAM_WrongOwnerAuthFailsTyped(t *testing.T) {
	soPIN := []byte("so-pin-1725-wrong")
	h := newOwnedSimHarness(t, nil, soPIN)
	index := tpm2.TPMHandle(nvramOwnerIndex)
	cert := nvramTestCert(t)

	for name, auth := range map[string][]byte{"wrong": []byte("not-the-so-pin"), "missing": nil} {
		err := h.TPM.writeCertToNVRAM(index, auth, cert.Raw)
		assert.ErrorIs(t, err, ErrNVCertHierarchyAuth, name)
	}

	_, err := tpm2.NVReadPublic{NVIndex: index}.Execute(h.TPM.transport)
	assert.ErrorIs(t, err, tpmRCHandle, "a rejected define must not leave an index")
}

// TestWriteCertToNVRAM_ExistingMatchingIndexIsRewritten: provisioning a
// second time writes the existing index (same size) or redefines it (new
// size) instead of failing with TPM_RC_NV_DEFINED.
func TestWriteCertToNVRAM_ExistingMatchingIndexIsRewritten(t *testing.T) {
	soPIN := []byte("so-pin-1725-rewrite")
	h := newOwnedSimHarness(t, nil, soPIN)
	index := tpm2.TPMHandle(nvramOwnerIndex)
	first := nvramTestCert(t)

	require.NoError(t, h.TPM.writeCertToNVRAM(index, soPIN, first.Raw))
	require.NoError(t, h.TPM.writeCertToNVRAM(index, soPIN, first.Raw), "same-size rewrite")

	larger := nvramTestCertLargerThan(t, len(first.Raw)+1)
	require.NoError(t, h.TPM.writeCertToNVRAM(index, soPIN, larger.Raw), "resize redefines the index")

	got, err := h.TPM.readCertFromNVRAM(index)
	require.NoError(t, err)
	assert.Equal(t, larger.Raw, got)
}

// TestWriteCertToNVRAM_MismatchedIndexFailsTyped: an index at the handle
// that is not a certificate index of ours is refused and left untouched.
func TestWriteCertToNVRAM_MismatchedIndexFailsTyped(t *testing.T) {
	soPIN := []byte("so-pin-1725-mismatch")
	h := newOwnedSimHarness(t, nil, soPIN)
	index := tpm2.TPMHandle(nvramOwnerIndex)
	foreign := tpm2.TPMSNVPublic{
		NVIndex: index,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerWrite: true,
			OwnerRead:  true,
			NoDA:       true,
			NT:         tpm2.TPMNTOrdinary,
		},
		DataSize: 16,
	}
	_, err := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(soPIN)},
		PublicInfo: tpm2.New2B(foreign),
	}.Execute(h.TPM.transport)
	require.NoError(t, err, "test setup: a foreign owner index")

	err = h.TPM.writeCertToNVRAM(index, soPIN, nvramTestCert(t).Raw)
	assert.ErrorIs(t, err, ErrNVCertIndexMismatch)

	rsp, err := tpm2.NVReadPublic{NVIndex: index}.Execute(h.TPM.transport)
	require.NoError(t, err)
	stored, err := rsp.NVPublic.Contents()
	require.NoError(t, err)
	assert.Equal(t, foreign.Attributes, stored.Attributes, "the foreign index is left untouched")
	assert.Equal(t, foreign.DataSize, stored.DataSize)
}

// TestProvisionEKCert_ECCEKLandsAtECCIndex: an ECC P-256 EK's certificate is
// written at 0x01C0000A (TCG EK Credential Profile v2.1 §2.2.1.4), not at the
// configured RSA default, and under the owner hierarchy (Part 3 §31.3.1).
func TestProvisionEKCert_ECCEKLandsAtECCIndex(t *testing.T) {
	soPIN := []byte("so-pin-1725-ecc-ek")
	h := newOwnedSimHarness(t, func(c *Config) {
		c.EK.KeyAlgorithm = x509.ECDSA.String()
		c.EK.RSAConfig = nil
		c.EK.ECCConfig = &store.ECCConfig{Curve: "P-256"}
	}, soPIN)
	certDER := createTestCertDER(t)

	require.NoError(t, h.TPM.ProvisionEKCert(soPIN, certDER))

	got, err := h.TPM.readCertFromNVRAM(ekCertIndexECCP256)
	require.NoError(t, err)
	assert.Equal(t, certDER, got)
	_, err = tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(ekCertIndexRSA2048)}.Execute(h.TPM.transport)
	assert.ErrorIs(t, err, tpmRCHandle, "nothing is written at the RSA index")
}

// TestProvisionEKCert_OwnedTPMWithoutAuthFailsTyped: the EK certificate
// define on an owned TPM needs the SO PIN like every other certificate.
func TestProvisionEKCert_OwnedTPMWithoutAuthFailsTyped(t *testing.T) {
	h := newOwnedSimHarness(t, nil, []byte("so-pin-1725-ek-noauth"))

	err := h.TPM.ProvisionEKCert(nil, createTestCertDER(t))
	assert.ErrorIs(t, err, ErrNVCertHierarchyAuth)
}

// TestDeleteCertFromNVRAM_OwnedTPMDeletesWithSuppliedAuth checks a certificate
// index on an owned TPM is undefined under the SO PIN as owner auth (TCG
// Part 3 §31.4.1), and that a wrong or missing auth fails typed and leaves
// the index in place.
func TestDeleteCertFromNVRAM_OwnedTPMDeletesWithSuppliedAuth(t *testing.T) {
	soPIN := []byte("so-pin-1725-delete")
	h := newOwnedSimHarness(t, nil, soPIN)
	index := tpm2.TPMHandle(nvramOwnerIndex)
	require.NoError(t, h.TPM.writeCertToNVRAM(index, soPIN, nvramTestCert(t).Raw))

	for name, auth := range map[string][]byte{"wrong": []byte("not-the-so-pin"), "missing": nil} {
		err := h.TPM.deleteCertFromNVRAM(index, auth)
		assert.ErrorIs(t, err, ErrNVCertHierarchyAuth, name)
	}
	_, err := tpm2.NVReadPublic{NVIndex: index}.Execute(h.TPM.transport)
	require.NoError(t, err, "a rejected undefine must leave the index")

	require.NoError(t, h.TPM.deleteCertFromNVRAM(index, soPIN))
	_, err = tpm2.NVReadPublic{NVIndex: index}.Execute(h.TPM.transport)
	assert.ErrorIs(t, err, tpmRCHandle)
}
