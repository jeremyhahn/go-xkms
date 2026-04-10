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

//go:build integration && pkcs11

package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requirePKCS11PIV sets up a PKCS11 backend for PIV testing.
// Fails the test immediately if PKCS11 environment is not available.
func requirePKCS11PIV(t *testing.T) func() {
	t.Helper()

	library := os.Getenv("PKCS11_LIBRARY")
	softhsmConf := os.Getenv("SOFTHSM2_CONF")
	if library == "" || softhsmConf == "" {
		t.Fatal("PKCS11 not available (set PKCS11_LIBRARY and SOFTHSM2_CONF)")
	}

	// Reset global singletons
	xkms.ResetPIV()
	xkms.Reset()

	slot := 0
	p11Backend, err := pkcs11backend.NewBackend(&pkcs11backend.Config{
		Library:       library,
		LibraryConfig: softhsmConf,
		PIN:           "1234",
		Slot:          &slot,
		KeyStorage:    storage.New(),
	})
	require.NoError(t, err, "failed to create PKCS11 backend")

	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     p11Backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err, "failed to create xkms PKCS11 backend")

	err = xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			pivBackendPKCS11: ks,
		},
		DefaultBackend: pivBackendPKCS11,
	})
	require.NoError(t, err, "failed to initialize XKMS service")

	p11PivStore := newPIVCertStore(t)

	err = xkms.InitializePIV(&xkms.PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			pivBackendPKCS11: p11PivStore,
		},
	})
	require.NoError(t, err, "failed to initialize PIV manager")

	// Wire the backend resolver
	svc, err := xkms.Get()
	require.NoError(t, err, "failed to get XKMS service")
	err = svc.InitPIVBackendResolver()
	require.NoError(t, err, "failed to init PIV backend resolver")

	return func() {
		xkms.ResetPIV()
		xkms.Reset()
	}
}

// TestIntegration_PIV_PKCS11_GenerateECDSA generates an ECDSA P-256 key
// using the PKCS11/SoftHSM backend for slot 9a.
func TestIntegration_PIV_PKCS11_GenerateECDSA(t *testing.T) {
	cleanup := requirePKCS11PIV(t)
	defer cleanup()

	ctx := context.Background()

	resp, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
		Backend:   pivBackendPKCS11,
		Slot:      "9a",
		Algorithm: "ecdsap256",
		Subject:   "PKCS11 ECDSA PIV Test",
	})
	require.NoError(t, err, "GeneratePIVKey failed")
	require.NotNil(t, resp)

	cert := parsePEMCertificate(t, resp.Certificate)
	assert.Equal(t, "PKCS11 ECDSA PIV Test", cert.Subject.CommonName)
	assert.Equal(t, x509.ECDSA, cert.PublicKeyAlgorithm)

	pub := parsePEMPublicKey(t, resp.PublicKey)
	_, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok, "expected ECDSA public key")
}

// TestIntegration_PIV_PKCS11_GenerateRSA generates an RSA 2048 key using
// the PKCS11/SoftHSM backend for slot 9c.
func TestIntegration_PIV_PKCS11_GenerateRSA(t *testing.T) {
	cleanup := requirePKCS11PIV(t)
	defer cleanup()

	ctx := context.Background()

	resp, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
		Backend:   pivBackendPKCS11,
		Slot:      "9c",
		Algorithm: "rsa2048",
		Subject:   "PKCS11 RSA PIV Test",
	})
	require.NoError(t, err, "GeneratePIVKey failed")
	require.NotNil(t, resp)

	cert := parsePEMCertificate(t, resp.Certificate)
	assert.Equal(t, "PKCS11 RSA PIV Test", cert.Subject.CommonName)
	assert.Equal(t, x509.RSA, cert.PublicKeyAlgorithm)

	pub := parsePEMPublicKey(t, resp.PublicKey)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok, "expected RSA public key")
	assert.Equal(t, 2048, rsaPub.N.BitLen())
}

// TestIntegration_PIV_PKCS11_CSR generates a key using PKCS11, creates a CSR,
// and verifies the CSR.
func TestIntegration_PIV_PKCS11_CSR(t *testing.T) {
	cleanup := requirePKCS11PIV(t)
	defer cleanup()

	ctx := context.Background()
	slot := "9d"

	// Generate key
	_, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
		Backend:   pivBackendPKCS11,
		Slot:      slot,
		Algorithm: "ecdsap384",
		Subject:   "PKCS11 CSR Key",
	})
	require.NoError(t, err, "GeneratePIVKey failed")

	// Generate CSR
	csrResp, err := xkms.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{
		Backend: pivBackendPKCS11,
		Slot:    slot,
		Subject: "PKCS11 CSR Subject",
	})
	require.NoError(t, err, "GeneratePIVCSR failed")
	require.NotNil(t, csrResp)

	block, _ := pem.Decode(csrResp.CSR)
	require.NotNil(t, block)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "PKCS11 CSR Subject", csr.Subject.CommonName)

	err = csr.CheckSignature()
	require.NoError(t, err, "PKCS11 CSR signature verification failed")
}
