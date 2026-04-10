package xkms

import (
	"context"
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
