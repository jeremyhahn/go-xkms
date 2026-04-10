package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCertPEM(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := createTestCert(t, "test-cert", key)
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	return string(pem.EncodeToMemory(block)), key
}

// --- GetCertificate ---

func TestGetCertificate_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := createTestCert(t, "cert-key", key)
	err = software.SaveCert("cert-key", cert)
	require.NoError(t, err)

	resp, err := svc.GetCertificate(context.Background(), "software", "cert-key")
	require.NoError(t, err)
	assert.Equal(t, "cert-key", resp.KeyID)
	assert.Contains(t, resp.CertificatePEM, "BEGIN CERTIFICATE")
}

func TestGetCertificate_NotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetCertificate(context.Background(), "software", "nonexistent")
	require.Error(t, err)
}

func TestGetCertificate_InvalidKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetCertificate(context.Background(), "software", "")
	require.Error(t, err)
}

// --- SaveCertificate ---

func TestServicerSaveCertificate_Success(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	pemStr, _ := testCertPEM(t)

	err = svc.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{
		Backend:        "software",
		KeyID:          "save-cert",
		CertificatePEM: pemStr,
	})
	require.NoError(t, err)
}

func TestSaveCertificate_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SaveCertificate(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestSaveCertificate_InvalidPEM(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{
		Backend:        "software",
		KeyID:          "bad-pem",
		CertificatePEM: "not-valid-pem",
	})
	require.Error(t, err)
}

// --- DeleteCertificate ---

func TestDeleteCertificate_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := createTestCert(t, "del-cert", key)
	err = software.SaveCert("del-cert", cert)
	require.NoError(t, err)

	err = svc.DeleteCertificate(context.Background(), "software", "del-cert")
	require.NoError(t, err)

	_, err = software.GetCert("del-cert")
	require.Error(t, err)
}

func TestDeleteCertificate_NotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.DeleteCertificate(context.Background(), "software", "ghost")
	require.Error(t, err)
}

// --- CertificateExists ---

func TestServicerCertificateExists_True(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := createTestCert(t, "exists-cert", key)
	err = software.SaveCert("exists-cert", cert)
	require.NoError(t, err)

	exists, err := svc.CertificateExists(context.Background(), "software", "exists-cert")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestServicerCertificateExists_False(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	exists, err := svc.CertificateExists(context.Background(), "software", "nope")
	require.NoError(t, err)
	assert.False(t, exists)
}

// --- ListCertificates ---

func TestListCertificates_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert1 := createTestCert(t, "list-cert-1", key)
	cert2 := createTestCert(t, "list-cert-2", key)
	require.NoError(t, software.SaveCert("list-cert-1", cert1))
	require.NoError(t, software.SaveCert("list-cert-2", cert2))

	resp, err := svc.ListCertificates(context.Background(), "software")
	require.NoError(t, err)
	assert.Len(t, resp.Certificates, 2)
}

func TestListCertificates_Empty(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.ListCertificates(context.Background(), "software")
	require.NoError(t, err)
	assert.Empty(t, resp.Certificates)
}

// --- SaveCertificateChain ---

func TestSaveCertificateChain_NilRequest(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SaveCertificateChain(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestSaveCertificateChain_EmptyChain(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{
		Backend:  "software",
		KeyID:    "chain-key",
		ChainPEM: []string{},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEmptyChain))
}

// --- GetCertificateChain ---

func TestGetCertificateChain_NotImplementedInMock(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetCertificateChain(context.Background(), "software", "any-key")
	require.Error(t, err)
}

// --- GetTLSCertificate ---

func TestGetTLSCertificate_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := createTestCert(t, "tls-cert", key)
	require.NoError(t, software.SaveCert("tls-cert", cert))

	resp, err := svc.GetTLSCertificate(context.Background(), "software", "tls-cert")
	require.NoError(t, err)
	assert.Equal(t, "tls-cert", resp.KeyID)
	assert.Contains(t, resp.CertificatePEM, "BEGIN CERTIFICATE")
}

func TestGetTLSCertificate_NotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetTLSCertificate(context.Background(), "software", "nope")
	require.Error(t, err)
}

// --- Additional certificate chain and validation tests ---

func TestSaveCertificateChain_PassesValidationButMockFails(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert1 := createTestCert(t, "chain-cert-1", key)
	cert2 := createTestCert(t, "chain-cert-2", key)

	block1 := &pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw}
	block2 := &pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw}

	// The PEM parsing succeeds, but the mock's SaveCertChain returns "not implemented"
	err = svc.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{
		Backend:  "software",
		KeyID:    "chain-key",
		ChainPEM: []string{string(pem.EncodeToMemory(block1)), string(pem.EncodeToMemory(block2))},
	})
	require.Error(t, err)
}

func TestSaveCertificateChain_InvalidPEMInChain(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := createTestCert(t, "chain-cert", key)
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}

	err = svc.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{
		Backend:  "software",
		KeyID:    "chain-key",
		ChainPEM: []string{string(pem.EncodeToMemory(block)), "not-valid-pem"},
	})
	require.Error(t, err)
}

func TestSaveCertificateChain_EmptyKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{
		Backend:  "software",
		KeyID:    "",
		ChainPEM: []string{"something"},
	})
	require.Error(t, err)
}

func TestSaveCertificateChain_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SaveCertificateChain(context.Background(), &transport.SaveCertificateChainRequest{
		Backend:  "nonexistent",
		KeyID:    "key",
		ChainPEM: []string{"something"},
	})
	require.Error(t, err)
}

func TestGetCertificateChain_EmptyKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetCertificateChain(context.Background(), "software", "")
	require.Error(t, err)
}

func TestGetCertificateChain_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetCertificateChain(context.Background(), "nonexistent", "key")
	require.Error(t, err)
}

func TestGetTLSCertificate_EmptyKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetTLSCertificate(context.Background(), "software", "")
	require.Error(t, err)
}

func TestGetTLSCertificate_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetTLSCertificate(context.Background(), "nonexistent", "key")
	require.Error(t, err)
}

func TestGetCertificate_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetCertificate(context.Background(), "nonexistent", "key")
	require.Error(t, err)
}

func TestDeleteCertificate_EmptyKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.DeleteCertificate(context.Background(), "software", "")
	require.Error(t, err)
}

func TestDeleteCertificate_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.DeleteCertificate(context.Background(), "nonexistent", "key")
	require.Error(t, err)
}

func TestCertificateExists_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CertificateExists(context.Background(), "nonexistent", "key")
	require.Error(t, err)
}

func TestListCertificates_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ListCertificates(context.Background(), "nonexistent")
	require.Error(t, err)
}

func TestSaveCertificate_NonExistentBackend(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{
		Backend:        "nonexistent",
		KeyID:          "key",
		CertificatePEM: "something",
	})
	require.Error(t, err)
}

func TestSaveCertificate_EmptyKeyID(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{
		Backend:        "software",
		KeyID:          "",
		CertificatePEM: "something",
	})
	require.Error(t, err)
}

// --- certFromPEM wrong block type ---

func TestCertFromPEM_WrongBlockType(t *testing.T) {
	// Create a PEM block with the wrong type (not CERTIFICATE)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("fake-data"),
	}
	pemStr := string(pem.EncodeToMemory(block))
	_, err := certFromPEM(pemStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CERTIFICATE")
}

// --- GetCertificateChain success path ---

func TestGetCertificateChain_BackendNotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetCertificateChain(context.Background(), "nonexistent", "my-key")
	require.Error(t, err)
}

func TestGetCertificateChain_EmptyKeyID_Validation(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetCertificateChain(context.Background(), "software", "")
	require.Error(t, err)
}

// --- GetTLSCertificate additional coverage ---

func TestGetTLSCertificate_BackendNotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetTLSCertificate(context.Background(), "nonexistent", "my-key")
	require.Error(t, err)
}

func TestGetTLSCertificate_EmptyKeyID_Servicer(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetTLSCertificate(context.Background(), "software", "")
	require.Error(t, err)
}

// --- CertificateExists additional coverage ---

func TestCertificateExists_EmptyKeyID_Servicer(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CertificateExists(context.Background(), "software", "")
	require.Error(t, err)
}
