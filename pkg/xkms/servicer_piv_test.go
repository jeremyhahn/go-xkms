package xkms

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PIV methods delegate to package-level functions using the pivManager singleton.
// When pivManager is nil (not initialized), ErrPIVNotInitialized is returned.

func TestListPIVSlots_NotInitialized(t *testing.T) {
	ResetPIV()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{
		Backend: "software",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

func TestGetPIVCertificate_NotInitialized(t *testing.T) {
	ResetPIV()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

func TestStorePIVCertificate_NotInitialized(t *testing.T) {
	ResetPIV()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.StorePIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

func TestDeletePIVCertificate_NotInitialized(t *testing.T) {
	ResetPIV()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.DeletePIVCertificate(context.Background(), &transport.DeletePIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

func TestGeneratePIVKey_NotInitialized(t *testing.T) {
	ResetPIV()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GeneratePIVKey(context.Background(), &transport.GeneratePIVKeyRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

func TestImportPIVCertificate_NotInitialized(t *testing.T) {
	ResetPIV()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.ImportPIVCertificate(context.Background(), &transport.StorePIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

func TestExportPIVCertificate_NotInitialized(t *testing.T) {
	ResetPIV()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ExportPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

func TestGeneratePIVCSR_NotInitialized(t *testing.T) {
	ResetPIV()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GeneratePIVCSR(context.Background(), &transport.GeneratePIVCSRRequest{
		Backend: "software",
		Slot:    "9a",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVNotInitialized)
}

// --- PIV with initialized manager but missing backend ---

func TestListPIVSlots_BackendNotFound(t *testing.T) {
	ResetPIV()
	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)
	t.Cleanup(ResetPIV)

	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{
		Backend: "nonexistent",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVBackendNotFound)
}

func TestGetPIVCertificate_BackendNotFound(t *testing.T) {
	ResetPIV()
	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)
	t.Cleanup(ResetPIV)

	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "nonexistent",
		Slot:    "9a",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPIVBackendNotFound)
}

// ============================================================
// InitPIVBackendResolver — resolver closure invocation
// ============================================================

func TestInitPIVBackendResolver_ResolvesRegisteredBackend(t *testing.T) {
	ResetPIV()
	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)
	t.Cleanup(ResetPIV)

	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.InitPIVBackendResolver()
	require.NoError(t, err)

	gen, err := pivBackend("software")
	require.NoError(t, err)
	assert.NotNil(t, gen)
}

func TestInitPIVBackendResolver_UnknownBackendPropagatesError(t *testing.T) {
	ResetPIV()
	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)
	t.Cleanup(ResetPIV)

	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.InitPIVBackendResolver()
	require.NoError(t, err)

	_, err = pivBackend("nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

// ============================================================
// InitPIVCASignFunc
// ============================================================

func TestInitPIVCASignFunc_NoCAConfigured(t *testing.T) {
	ResetPIV()
	t.Cleanup(ResetPIV)

	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// No CA wired: getCA() fails and InitPIVCASignFunc treats this as "no
	// ca-signed support" rather than a hard error.
	err = svc.InitPIVCASignFunc()
	require.NoError(t, err)
}

func TestInitPIVCASignFunc_WithCA_SignsAndBuildsChain(t *testing.T) {
	ResetPIV()
	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)
	t.Cleanup(ResetPIV)

	leafCert := createSelfSignedCert(t)
	caCert := createSelfSignedCert(t)
	ca := &mockCA{signCSRCert: leafCert, cert: caCert}
	svc := setupServiceWithCA(t, ca)

	err = svc.InitPIVCASignFunc()
	require.NoError(t, err)
	require.NotNil(t, pivManager)

	certPEM, chainPEM, err := pivManager.caSignFunc(context.Background(), []byte("dummy-csr"), "piv-authentication", 30)
	require.NoError(t, err)
	assert.Contains(t, string(certPEM), "BEGIN CERTIFICATE")
	assert.Contains(t, string(chainPEM), "BEGIN CERTIFICATE")
}

func TestInitPIVCASignFunc_CACertificateErrorLeavesChainEmpty(t *testing.T) {
	ResetPIV()
	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)
	t.Cleanup(ResetPIV)

	leafCert := createSelfSignedCert(t)
	ca := &mockCA{signCSRCert: leafCert, certErr: errors.New("no ca certificate configured")}
	svc := setupServiceWithCA(t, ca)

	err = svc.InitPIVCASignFunc()
	require.NoError(t, err)

	certPEM, chainPEM, err := pivManager.caSignFunc(context.Background(), []byte("dummy-csr"), "piv-authentication", 30)
	require.NoError(t, err)
	assert.NotEmpty(t, certPEM)
	assert.Empty(t, chainPEM)
}

func TestInitPIVCASignFunc_SignCSRErrorPropagates(t *testing.T) {
	ResetPIV()
	err := InitializePIV(&PIVManagerConfig{})
	require.NoError(t, err)
	t.Cleanup(ResetPIV)

	ca := &mockCA{signCSRErr: errors.New("csr rejected")}
	svc := setupServiceWithCA(t, ca)

	err = svc.InitPIVCASignFunc()
	require.NoError(t, err)

	certPEM, chainPEM, err := pivManager.caSignFunc(context.Background(), []byte("dummy-csr"), "piv-authentication", 30)
	require.Error(t, err)
	assert.Nil(t, certPEM)
	assert.Nil(t, chainPEM)
}
