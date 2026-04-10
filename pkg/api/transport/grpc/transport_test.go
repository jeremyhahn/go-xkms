// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package grpc

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Constructor tests ---

func TestNew_DefaultConfig(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.NotNil(t, tr.config)
}

func TestNew_WithAddress(t *testing.T) {
	tr, err := New(transport.WithAddress("localhost:50051"))
	require.NoError(t, err)
	assert.Equal(t, "localhost:50051", tr.config.Address)
}

func TestNew_InvalidOption(t *testing.T) {
	_, err := New(transport.WithAddress(""))
	require.Error(t, err)
}

func TestNewWithConfig_NilConfig(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.NotNil(t, tr.config)
}

func TestNewWithConfig_CustomConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "custom:50051"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "custom:50051", tr.config.Address)
}

// --- Close without connection ---

func TestClose_NilConn(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.NoError(t, tr.Close())
	assert.False(t, tr.connected)
}

// --- Conn ---

func TestConn_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.Nil(t, tr.Conn())
}

// --- Client ---

func TestClient_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.Nil(t, tr.Client())
}

// --- Config ---

func TestConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "test:50051"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test:50051", tr.Config().Address)
}

// --- NotConnected error paths ---

func TestHealth_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Health(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListBackends_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ListBackends(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetBackend_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetBackend(context.Background(), "software")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGenerateKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListKeys_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ListKeys(context.Background(), "sw")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetKey(context.Background(), "sw", "k")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeleteKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.DeleteKey(context.Background(), "sw", "k")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSign_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Sign(context.Background(), &transport.SignRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestVerify_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Verify(context.Background(), &transport.VerifyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestEncrypt_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Encrypt(context.Background(), &transport.EncryptRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDecrypt_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Decrypt(context.Background(), &transport.DecryptRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestEncryptAsym_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.EncryptAsym(context.Background(), &transport.EncryptAsymRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSeal_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Seal(context.Background(), &transport.SealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUnseal_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Unseal(context.Background(), &transport.UnsealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestCanSeal_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.CanSeal(context.Background(), "sw")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestImportKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ImportKey(context.Background(), &transport.ImportKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestExportKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ExportKey(context.Background(), &transport.ExportKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRotateKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.RotateKey(context.Background(), &transport.RotateKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetCertificate_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetCertificate(context.Background(), "sw", "k")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSaveCertificate_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.SaveCertificate(context.Background(), &transport.SaveCertificateRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeleteCertificate_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.DeleteCertificate(context.Background(), "sw", "k")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestCertificateExists_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.CertificateExists(context.Background(), "sw", "k")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetImportParameters_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GetImportParameters(context.Background(), &transport.GetImportParametersRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestWrapKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.WrapKey(context.Background(), &transport.WrapKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUnwrapKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.UnwrapKey(context.Background(), &transport.UnwrapKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestCopyKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.CopyKey(context.Background(), &transport.CopyKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeriveKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.DeriveKey(context.Background(), &transport.DeriveKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDeriveKeyECDH_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.DeriveKeyECDH(context.Background(), &transport.DeriveKeyECDHRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierStatus_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.BarrierStatus(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierInitialize_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.BarrierInitialize(context.Background(), &transport.BarrierInitializeRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierUnseal_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierSeal_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.BarrierSeal(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}
