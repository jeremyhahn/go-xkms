// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/ca/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTCGCA implements provider.TCGCA (extends provider.CA) for testing TCG methods.
type mockTCGCA struct {
	mockCA // embeds CA methods

	ekCertDER []byte
	ekCertErr error
	akCertDER []byte
	akCertErr error
	iakDER    []byte
	idevidDER []byte
	signErr   error
	enrollIAK []byte
	enrollDev []byte
	credBlob  []byte
	encSecret []byte
	plainSec  []byte
	enrollErr error
}

func (m *mockTCGCA) IssueEKCertificateRaw(commonName, organization string, ekPubDER []byte) ([]byte, error) {
	return m.ekCertDER, m.ekCertErr
}

func (m *mockTCGCA) IssueAKCertificateRaw(commonName, organization string, pubDER []byte) ([]byte, error) {
	return m.akCertDER, m.akCertErr
}

func (m *mockTCGCA) SignTCGCSRIDevIDRaw(commonName, organization string, packedCSR []byte) ([]byte, []byte, error) {
	return m.iakDER, m.idevidDER, m.signErr
}

func (m *mockTCGCA) EnrollDeviceRaw(commonName, organization string, packedCSR []byte) ([]byte, []byte, []byte, []byte, []byte, error) {
	return m.enrollIAK, m.enrollDev, m.credBlob, m.encSecret, m.plainSec, m.enrollErr
}

// createTestCertDER generates a self-signed certificate and returns its DER bytes.
func createTestCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(99999),
		Subject:               pkix.Name{CommonName: "Test TCG Cert"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return certDER
}

// setupServiceWithTCGCA wires a provider.TCGCA (which also satisfies provider.CA).
func setupServiceWithTCGCA(t *testing.T, ca provider.CA) *XKMSService {
	t.Helper()
	return setupServiceWithCA(t, ca)
}

// ========================================================================
// getTCGCA
// ========================================================================

func TestGetTCGCA_Success(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)

	result, err := svc.getTCGCA()
	require.NoError(t, err)
	assert.Equal(t, tcg, result)
}

func TestGetTCGCA_NoCA(t *testing.T) {
	svc := setupServiceWithTCGCA(t, nil)

	result, err := svc.getTCGCA()
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestGetTCGCA_NonTCGCA(t *testing.T) {
	// A plain mockCA satisfies provider.CA but NOT provider.TCGCA.
	plainCA := &mockCA{}
	svc := setupServiceWithCA(t, plainCA)

	result, err := svc.getTCGCA()
	assert.Nil(t, result)
	assert.ErrorIs(t, err, ErrNotSupported)
}

// ========================================================================
// serialFromDER
// ========================================================================

func TestSerialFromDER_Valid(t *testing.T) {
	certDER := createTestCertDER(t)
	serial := serialFromDER(certDER)

	// Parse the DER to get expected serial.
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	expected := cert.SerialNumber.Text(16)
	assert.Equal(t, expected, serial)
}

func TestSerialFromDER_InvalidDER(t *testing.T) {
	serial := serialFromDER([]byte("not-a-certificate"))
	assert.Equal(t, "", serial)
}

func TestSerialFromDER_EmptyDER(t *testing.T) {
	serial := serialFromDER(nil)
	assert.Equal(t, "", serial)
}

// ========================================================================
// IssueEKCertificate
// ========================================================================

func TestIssueEKCertificate_Success(t *testing.T) {
	certDER := createTestCertDER(t)
	tcg := &mockTCGCA{ekCertDER: certDER}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{
		CommonName:   "device-ek",
		Organization: "Test Org",
		EKPublicKey:  []byte("fake-ek-pub-der"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, certDER, resp.CertificateDER)
	assert.NotEmpty(t, resp.CertificatePEM)
	assert.NotEmpty(t, resp.SerialNumber)
}

func TestIssueEKCertificate_NilRequest(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.IssueEKCertificate(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestIssueEKCertificate_EmptyCommonName(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{
		CommonName:  "",
		EKPublicKey: []byte("fake-ek-pub"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	assert.Contains(t, err.Error(), "common name required")
}

func TestIssueEKCertificate_EmptyEKPublicKey(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{
		CommonName:  "device-ek",
		EKPublicKey: nil,
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilData)
	assert.Contains(t, err.Error(), "EK public key required")
}

func TestIssueEKCertificate_NoCA(t *testing.T) {
	svc := setupServiceWithTCGCA(t, nil)
	ctx := context.Background()

	resp, err := svc.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{
		CommonName:  "device-ek",
		EKPublicKey: []byte("fake-ek-pub"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestIssueEKCertificate_NonTCGCA(t *testing.T) {
	plainCA := &mockCA{}
	svc := setupServiceWithCA(t, plainCA)
	ctx := context.Background()

	resp, err := svc.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{
		CommonName:  "device-ek",
		EKPublicKey: []byte("fake-ek-pub"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestIssueEKCertificate_CAError(t *testing.T) {
	caErr := errors.New("ca: ek issuance failed")
	tcg := &mockTCGCA{ekCertErr: caErr}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.IssueEKCertificate(ctx, &transport.IssueEKCertificateRequest{
		CommonName:  "device-ek",
		EKPublicKey: []byte("fake-ek-pub"),
	})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, caErr)
	assert.Contains(t, err.Error(), "ca: issue ek certificate")
}

// ========================================================================
// IssueAKCertificate
// ========================================================================

func TestIssueAKCertificate_Success(t *testing.T) {
	certDER := createTestCertDER(t)
	tcg := &mockTCGCA{akCertDER: certDER}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{
		CommonName:   "device-ak",
		Organization: "Test Org",
		PublicKey:    []byte("fake-ak-pub-der"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, certDER, resp.CertificateDER)
	assert.NotEmpty(t, resp.CertificatePEM)
	assert.NotEmpty(t, resp.SerialNumber)
}

func TestIssueAKCertificate_NilRequest(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.IssueAKCertificate(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestIssueAKCertificate_EmptyCommonName(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{
		CommonName: "",
		PublicKey:  []byte("fake-ak-pub"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	assert.Contains(t, err.Error(), "common name required")
}

func TestIssueAKCertificate_EmptyPublicKey(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{
		CommonName: "device-ak",
		PublicKey:  nil,
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilData)
	assert.Contains(t, err.Error(), "public key required")
}

func TestIssueAKCertificate_NoCA(t *testing.T) {
	svc := setupServiceWithTCGCA(t, nil)
	ctx := context.Background()

	resp, err := svc.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{
		CommonName: "device-ak",
		PublicKey:  []byte("fake-ak-pub"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestIssueAKCertificate_NonTCGCA(t *testing.T) {
	plainCA := &mockCA{}
	svc := setupServiceWithCA(t, plainCA)
	ctx := context.Background()

	resp, err := svc.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{
		CommonName: "device-ak",
		PublicKey:  []byte("fake-ak-pub"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestIssueAKCertificate_CAError(t *testing.T) {
	caErr := errors.New("ca: ak issuance failed")
	tcg := &mockTCGCA{akCertErr: caErr}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.IssueAKCertificate(ctx, &transport.IssueAKCertificateRequest{
		CommonName: "device-ak",
		PublicKey:  []byte("fake-ak-pub"),
	})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, caErr)
	assert.Contains(t, err.Error(), "ca: issue ak certificate")
}

// ========================================================================
// SignTCGCSR
// ========================================================================

func TestSignTCGCSR_Success(t *testing.T) {
	iakDER := []byte("fake-iak-der")
	idevidDER := []byte("fake-idevid-der")
	tcg := &mockTCGCA{iakDER: iakDER, idevidDER: idevidDER}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{
		CommonName:   "device-001",
		Organization: "Test Org",
		TCGCSR:       []byte("fake-tcg-csr-bytes"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, iakDER, resp.IAKCertDER)
	assert.Equal(t, idevidDER, resp.IDevIDCertDER)
}

func TestSignTCGCSR_NilRequest(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.SignTCGCSR(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestSignTCGCSR_EmptyCommonName(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{
		CommonName: "",
		TCGCSR:     []byte("fake-tcg-csr"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	assert.Contains(t, err.Error(), "common name required")
}

func TestSignTCGCSR_EmptyTCGCSR(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{
		CommonName: "device-001",
		TCGCSR:     nil,
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilData)
	assert.Contains(t, err.Error(), "TCG CSR required")
}

func TestSignTCGCSR_NoCA(t *testing.T) {
	svc := setupServiceWithTCGCA(t, nil)
	ctx := context.Background()

	resp, err := svc.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{
		CommonName: "device-001",
		TCGCSR:     []byte("fake-tcg-csr"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestSignTCGCSR_NonTCGCA(t *testing.T) {
	plainCA := &mockCA{}
	svc := setupServiceWithCA(t, plainCA)
	ctx := context.Background()

	resp, err := svc.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{
		CommonName: "device-001",
		TCGCSR:     []byte("fake-tcg-csr"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestSignTCGCSR_CAError(t *testing.T) {
	caErr := errors.New("ca: tcg csr signing failed")
	tcg := &mockTCGCA{signErr: caErr}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.SignTCGCSR(ctx, &transport.SignTCGCSRRequest{
		CommonName: "device-001",
		TCGCSR:     []byte("fake-tcg-csr"),
	})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, caErr)
	assert.Contains(t, err.Error(), "ca: sign tcg csr")
}

// ========================================================================
// EnrollDevice
// ========================================================================

func TestEnrollDevice_Success(t *testing.T) {
	tcg := &mockTCGCA{
		enrollIAK: []byte("iak-cert-der"),
		enrollDev: []byte("idevid-cert-der"),
		credBlob:  []byte("cred-blob"),
		encSecret: []byte("enc-secret"),
		plainSec:  []byte("plain-secret"),
	}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.EnrollDevice(ctx, &transport.EnrollDeviceRequest{
		CommonName:   "device-001",
		Organization: "Test Org",
		PackedCSR:    []byte("fake-packed-csr"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, []byte("iak-cert-der"), resp.IAKCertDER)
	assert.Equal(t, []byte("idevid-cert-der"), resp.IDevIDCertDER)
	assert.Equal(t, []byte("cred-blob"), resp.CredentialBlob)
	assert.Equal(t, []byte("enc-secret"), resp.EncryptedSecret)
	assert.Equal(t, []byte("plain-secret"), resp.PlainSecret)
}

func TestEnrollDevice_NilRequest(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.EnrollDevice(ctx, nil)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilRequest)
}

func TestEnrollDevice_EmptyCommonName(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.EnrollDevice(ctx, &transport.EnrollDeviceRequest{
		CommonName: "",
		PackedCSR:  []byte("fake-packed-csr"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrInvalidKeyAttributes)
	assert.Contains(t, err.Error(), "common name required")
}

func TestEnrollDevice_EmptyPackedCSR(t *testing.T) {
	tcg := &mockTCGCA{}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.EnrollDevice(ctx, &transport.EnrollDeviceRequest{
		CommonName: "device-001",
		PackedCSR:  nil,
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNilData)
	assert.Contains(t, err.Error(), "packed CSR required")
}

func TestEnrollDevice_NoCA(t *testing.T) {
	svc := setupServiceWithTCGCA(t, nil)
	ctx := context.Background()

	resp, err := svc.EnrollDevice(ctx, &transport.EnrollDeviceRequest{
		CommonName: "device-001",
		PackedCSR:  []byte("fake-packed-csr"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestEnrollDevice_NonTCGCA(t *testing.T) {
	plainCA := &mockCA{}
	svc := setupServiceWithCA(t, plainCA)
	ctx := context.Background()

	resp, err := svc.EnrollDevice(ctx, &transport.EnrollDeviceRequest{
		CommonName: "device-001",
		PackedCSR:  []byte("fake-packed-csr"),
	})
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestEnrollDevice_CAError(t *testing.T) {
	caErr := errors.New("ca: enrollment failed")
	tcg := &mockTCGCA{enrollErr: caErr}
	svc := setupServiceWithTCGCA(t, tcg)
	ctx := context.Background()

	resp, err := svc.EnrollDevice(ctx, &transport.EnrollDeviceRequest{
		CommonName: "device-001",
		PackedCSR:  []byte("fake-packed-csr"),
	})
	assert.Nil(t, resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, caErr)
	assert.Contains(t, err.Error(), "ca: enroll device")
}
