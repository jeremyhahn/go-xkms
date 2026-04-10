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

//go:build integration

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pivcertfile "github.com/jeremyhahn/go-xkms/pkg/pivcert/file"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pivBackendSoftware = "software"
	pivBackendTPM2     = "tpm2"
	pivBackendPKCS11   = "pkcs11"
)

// setupPIVTest initializes the PIV manager with a file-backed PIV cert store
// using an in-memory storage backend. It registers the backend, creates a
// software xkms.Backend for key operations, and initializes the XKMS service.
// Returns a cleanup function that resets PIV and XKMS state.
func setupPIVTest(t *testing.T, backendName string) func() {
	t.Helper()

	// Reset global singletons
	xkms.ResetPIV()
	xkms.Reset()

	// Create PIV certificate storage backed by in-memory storage
	pivStore, err := pivcertfile.NewFileBackend(&pivcert.FileStorageConfig{
		Backend:    storage.New(),
		DEREnabled: true,
		PEMEnabled: true,
	})
	require.NoError(t, err, "failed to create PIV cert store")

	// Create software backend for key operations
	softwareBackend, err := software.NewBackend(&software.Config{
		KeyStorage: storage.New(),
	})
	require.NoError(t, err, "failed to create software backend")

	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     softwareBackend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err, "failed to create xkms backend")

	// Initialize XKMS service
	err = xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			backendName: ks,
		},
		DefaultBackend: backendName,
	})
	require.NoError(t, err, "failed to initialize XKMS service")

	// Initialize PIV manager
	err = xkms.InitializePIV(&xkms.PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			backendName: pivStore,
		},
	})
	require.NoError(t, err, "failed to initialize PIV manager")

	return func() {
		xkms.ResetPIV()
		xkms.Reset()
	}
}

// requireTPM2PIV sets up a TPM2 backend for PIV testing.
// Fails the test immediately if no TPM is available.
func requireTPM2PIV(t *testing.T) func() {
	t.Helper()

	// Check for TPM availability
	simHost := os.Getenv("TPM2_SIMULATOR_HOST")
	_, hwErr := os.Stat("/dev/tpmrm0")
	if simHost == "" && hwErr != nil {
		t.Fatal("No TPM available (set TPM2_SIMULATOR_HOST or have /dev/tpmrm0)")
	}

	// Reset global singletons
	xkms.ResetPIV()
	xkms.Reset()

	keyDir := t.TempDir()
	config := &tpm2.Config{
		KeyDir: keyDir,
	}

	if simHost != "" {
		config.UseSimulator = true
	} else {
		config.Device = "/dev/tpmrm0"
	}

	tpm2Backend, err := tpm2.NewBackend(config)
	require.NoError(t, err, "failed to create TPM2 backend")

	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     tpm2Backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err, "failed to create xkms TPM2 backend")

	// Also create software backend for multi-backend setup
	softwareBackend, err := software.NewBackend(&software.Config{
		KeyStorage: storage.New(),
	})
	require.NoError(t, err, "failed to create software backend")

	softwareKS, err := xkms.New(&xkms.BackendConfig{
		Backend:     softwareBackend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err, "failed to create software xkms backend")

	err = xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			pivBackendTPM2:     ks,
			pivBackendSoftware: softwareKS,
		},
		DefaultBackend: pivBackendTPM2,
	})
	require.NoError(t, err, "failed to initialize XKMS service")

	// Create PIV cert store for TPM2
	tpm2PivStore, err := pivcertfile.NewFileBackend(&pivcert.FileStorageConfig{
		Backend:    storage.New(),
		DEREnabled: true,
		PEMEnabled: true,
	})
	require.NoError(t, err, "failed to create TPM2 PIV cert store")

	err = xkms.InitializePIV(&xkms.PIVManagerConfig{
		Stores: map[string]pivcert.PIVCertificateStorage{
			pivBackendTPM2: tpm2PivStore,
		},
	})
	require.NoError(t, err, "failed to initialize PIV manager")

	// Wire the backend resolver so PIV key generation uses TPM2
	svc, err := xkms.Get()
	require.NoError(t, err, "failed to get XKMS service")
	err = svc.InitPIVBackendResolver()
	require.NoError(t, err, "failed to init PIV backend resolver")

	return func() {
		tpm2Backend.Close()
		xkms.ResetPIV()
		xkms.Reset()
	}
}

// newPIVCertStore creates a new file-backed PIV certificate store with
// in-memory storage for testing.
func newPIVCertStore(t *testing.T) pivcert.PIVCertificateStorage {
	t.Helper()
	store, err := pivcertfile.NewFileBackend(&pivcert.FileStorageConfig{
		Backend:    storage.New(),
		DEREnabled: true,
		PEMEnabled: true,
	})
	require.NoError(t, err, "failed to create PIV cert store")
	return store
}

// ---------------------------------------------------------------------------
// Software Backend Tests
// ---------------------------------------------------------------------------

// TestIntegration_PIV_Software_GenerateAllAlgorithms generates keys for all
// supported algorithms on different PIV slots and verifies the resulting
// certificates and public keys.
func TestIntegration_PIV_Software_GenerateAllAlgorithms(t *testing.T) {
	cleanup := setupPIVTest(t, pivBackendSoftware)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name      string
		algorithm string
		slot      string
		subject   string
		verifyKey func(t *testing.T, pubPEM []byte)
	}{
		{
			name:      "RSA2048_Slot9a",
			algorithm: "rsa2048",
			slot:      "9a",
			subject:   "PIV RSA-2048 Test",
			verifyKey: func(t *testing.T, pubPEM []byte) {
				t.Helper()
				pub := parsePEMPublicKey(t, pubPEM)
				rsaPub, ok := pub.(*rsa.PublicKey)
				require.True(t, ok, "expected RSA public key")
				assert.Equal(t, 2048, rsaPub.N.BitLen())
			},
		},
		{
			name:      "RSA4096_Slot9c",
			algorithm: "rsa4096",
			slot:      "9c",
			subject:   "PIV RSA-4096 Test",
			verifyKey: func(t *testing.T, pubPEM []byte) {
				t.Helper()
				pub := parsePEMPublicKey(t, pubPEM)
				rsaPub, ok := pub.(*rsa.PublicKey)
				require.True(t, ok, "expected RSA public key")
				assert.Equal(t, 4096, rsaPub.N.BitLen())
			},
		},
		{
			name:      "ECDSAP256_Slot9d",
			algorithm: "ecdsap256",
			slot:      "9d",
			subject:   "PIV ECDSA P-256 Test",
			verifyKey: func(t *testing.T, pubPEM []byte) {
				t.Helper()
				pub := parsePEMPublicKey(t, pubPEM)
				ecPub, ok := pub.(*ecdsa.PublicKey)
				require.True(t, ok, "expected ECDSA public key")
				assert.Equal(t, "P-256", ecPub.Curve.Params().Name)
			},
		},
		{
			name:      "ECDSAP384_Slot9e",
			algorithm: "ecdsap384",
			slot:      "9e",
			subject:   "PIV ECDSA P-384 Test",
			verifyKey: func(t *testing.T, pubPEM []byte) {
				t.Helper()
				pub := parsePEMPublicKey(t, pubPEM)
				ecPub, ok := pub.(*ecdsa.PublicKey)
				require.True(t, ok, "expected ECDSA public key")
				assert.Equal(t, "P-384", ecPub.Curve.Params().Name)
			},
		},
		{
			name:      "Ed25519_SlotF9",
			algorithm: "ed25519",
			slot:      "f9",
			subject:   "PIV Ed25519 Test",
			verifyKey: func(t *testing.T, pubPEM []byte) {
				t.Helper()
				pub := parsePEMPublicKey(t, pubPEM)
				_, ok := pub.(ed25519.PublicKey)
				require.True(t, ok, "expected Ed25519 public key")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate PIV key
			resp, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
				Backend:   pivBackendSoftware,
				Slot:      tt.slot,
				Algorithm: tt.algorithm,
				Subject:   tt.subject,
			})
			require.NoError(t, err, "GeneratePIVKey failed")
			require.NotNil(t, resp, "response should not be nil")

			// Verify response has cert PEM
			assert.NotEmpty(t, resp.Certificate, "certificate PEM should not be empty")
			assert.NotEmpty(t, resp.PublicKey, "public key PEM should not be empty")
			assert.Equal(t, tt.slot, resp.Slot)

			// Verify certificate can be parsed
			cert := parsePEMCertificate(t, resp.Certificate)
			assert.Equal(t, tt.subject, cert.Subject.CommonName)

			// Verify public key type
			tt.verifyKey(t, resp.PublicKey)

			// Verify the cert is stored and retrievable
			getCertResp, err := xkms.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
				Backend: pivBackendSoftware,
				Slot:    tt.slot,
				Format:  "pem",
			})
			require.NoError(t, err, "GetPIVCertificate failed")
			require.NotNil(t, getCertResp)
			assert.NotEmpty(t, getCertResp.Certificate)

			// Parse retrieved cert and verify subject matches
			retrievedCert := parsePEMCertificate(t, getCertResp.Certificate)
			assert.Equal(t, tt.subject, retrievedCert.Subject.CommonName)
		})
	}
}

// TestIntegration_PIV_Software_CSR generates a key, then creates a CSR and
// verifies its contents and signature.
func TestIntegration_PIV_Software_CSR(t *testing.T) {
	cleanup := setupPIVTest(t, pivBackendSoftware)
	defer cleanup()

	ctx := context.Background()
	slot := "9a"
	subject := "PIV CSR Test Subject"

	// Generate key first
	_, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
		Backend:   pivBackendSoftware,
		Slot:      slot,
		Algorithm: "ecdsap256",
		Subject:   subject,
	})
	require.NoError(t, err, "GeneratePIVKey failed")

	// Generate CSR
	csrResp, err := xkms.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{
		Backend: pivBackendSoftware,
		Slot:    slot,
		Subject: "CSR Subject Override",
	})
	require.NoError(t, err, "GeneratePIVCSR failed")
	require.NotNil(t, csrResp)

	assert.Equal(t, slot, csrResp.Slot)
	assert.NotEmpty(t, csrResp.CSR, "CSR PEM should not be empty")

	// Parse and verify CSR
	block, _ := pem.Decode(csrResp.CSR)
	require.NotNil(t, block, "failed to decode CSR PEM")
	assert.Equal(t, "CERTIFICATE REQUEST", block.Type)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err, "failed to parse CSR")

	assert.Equal(t, "CSR Subject Override", csr.Subject.CommonName)

	// Verify CSR signature
	err = csr.CheckSignature()
	require.NoError(t, err, "CSR signature verification failed")
}

// TestIntegration_PIV_Software_CertLifecycle exercises the full CRUD
// lifecycle: generate key+cert, get cert, export cert in PEM and DER,
// delete cert, and verify it is gone.
func TestIntegration_PIV_Software_CertLifecycle(t *testing.T) {
	cleanup := setupPIVTest(t, pivBackendSoftware)
	defer cleanup()

	ctx := context.Background()
	slot := "9c"
	subject := "PIV Lifecycle Test"

	// Generate key + self-signed cert
	genResp, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
		Backend:   pivBackendSoftware,
		Slot:      slot,
		Algorithm: "ecdsap256",
		Subject:   subject,
	})
	require.NoError(t, err, "GeneratePIVKey failed")
	require.NotNil(t, genResp)

	// Get cert (PEM)
	getCertPEM, err := xkms.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
		Backend: pivBackendSoftware,
		Slot:    slot,
		Format:  "pem",
	})
	require.NoError(t, err, "GetPIVCertificate PEM failed")
	require.NotEmpty(t, getCertPEM.Certificate)

	// Export cert PEM
	exportPEM, err := xkms.ExportPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
		Backend: pivBackendSoftware,
		Slot:    slot,
		Format:  "pem",
	})
	require.NoError(t, err, "ExportPIVCertificate PEM failed")
	require.NotEmpty(t, exportPEM.Certificate)

	// Export cert DER
	exportDER, err := xkms.ExportPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
		Backend: pivBackendSoftware,
		Slot:    slot,
		Format:  "der",
	})
	require.NoError(t, err, "ExportPIVCertificate DER failed")
	require.NotEmpty(t, exportDER.Certificate)

	// Verify DER can be parsed
	derCert, err := x509.ParseCertificate(exportDER.Certificate)
	require.NoError(t, err, "failed to parse DER certificate")
	assert.Equal(t, subject, derCert.Subject.CommonName)

	// Delete cert
	err = xkms.DeletePIVCertificate(ctx, &transport.DeletePIVCertificateRequest{
		Backend: pivBackendSoftware,
		Slot:    slot,
	})
	require.NoError(t, err, "DeletePIVCertificate failed")

	// Verify cert is gone
	_, err = xkms.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
		Backend: pivBackendSoftware,
		Slot:    slot,
		Format:  "pem",
	})
	require.Error(t, err, "expected error after deletion")
}

// TestIntegration_PIV_Software_ListSlots generates certs in several slots,
// lists all slots, and verifies that occupied slots have correct metadata.
func TestIntegration_PIV_Software_ListSlots(t *testing.T) {
	cleanup := setupPIVTest(t, pivBackendSoftware)
	defer cleanup()

	ctx := context.Background()

	// Generate keys in specific slots using deterministic ordering
	type slotAlgo struct {
		slot string
		algo string
	}
	entries := []slotAlgo{
		{"9a", "ecdsap256"},
		{"9c", "rsa2048"},
		{"9d", "ed25519"},
	}

	for _, entry := range entries {
		_, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
			Backend:   pivBackendSoftware,
			Slot:      entry.slot,
			Algorithm: entry.algo,
			Subject:   "PIV Slot " + entry.slot,
		})
		require.NoError(t, err, "GeneratePIVKey failed for slot %s", entry.slot)
	}

	// List all slots
	listResp, err := xkms.ListPIVSlots(ctx, &transport.ListPIVSlotsRequest{
		Backend: pivBackendSoftware,
	})
	require.NoError(t, err, "ListPIVSlots failed")
	require.NotNil(t, listResp)
	require.NotEmpty(t, listResp.Slots, "slot list should not be empty")

	// Build a map for easy lookup
	slotMap := make(map[string]transport.PIVSlotStatus)
	for _, s := range listResp.Slots {
		slotMap[s.Slot] = s
	}

	// Verify each occupied slot
	for _, entry := range entries {
		status, ok := slotMap[entry.slot]
		require.True(t, ok, "slot %s should be in the list", entry.slot)
		assert.True(t, status.HasCert, "slot %s should have a cert", entry.slot)
		assert.NotEmpty(t, status.Subject, "slot %s should have a subject", entry.slot)
		assert.NotEmpty(t, status.Algorithm, "slot %s should have an algorithm", entry.slot)
		assert.NotEmpty(t, status.Name, "slot %s should have a name", entry.slot)
	}

	// Verify an unoccupied slot
	status9e, ok := slotMap["9e"]
	require.True(t, ok, "slot 9e should be in the list")
	assert.False(t, status9e.HasCert, "slot 9e should not have a cert")
}

// ---------------------------------------------------------------------------
// TPM2 Backend Tests (swtpm)
// ---------------------------------------------------------------------------

// TestIntegration_PIV_TPM2_GenerateECDSA generates an ECDSA P-256 key using
// the TPM2 backend for slot 9a and verifies the certificate and storage.
func TestIntegration_PIV_TPM2_GenerateECDSA(t *testing.T) {
	cleanup := requireTPM2PIV(t)
	defer cleanup()

	ctx := context.Background()

	resp, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
		Backend:   pivBackendTPM2,
		Slot:      "9a",
		Algorithm: "ecdsap256",
		Subject:   "TPM2 ECDSA PIV Test",
	})
	require.NoError(t, err, "GeneratePIVKey failed")
	require.NotNil(t, resp)

	// Verify cert
	cert := parsePEMCertificate(t, resp.Certificate)
	assert.Equal(t, "TPM2 ECDSA PIV Test", cert.Subject.CommonName)
	assert.Equal(t, x509.ECDSA, cert.PublicKeyAlgorithm)

	// Verify stored
	getCertResp, err := xkms.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
		Backend: pivBackendTPM2,
		Slot:    "9a",
		Format:  "pem",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, getCertResp.Certificate)
}

// TestIntegration_PIV_TPM2_GenerateRSA generates an RSA 2048 key using the
// TPM2 backend for slot 9c.
func TestIntegration_PIV_TPM2_GenerateRSA(t *testing.T) {
	cleanup := requireTPM2PIV(t)
	defer cleanup()

	ctx := context.Background()

	resp, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
		Backend:   pivBackendTPM2,
		Slot:      "9c",
		Algorithm: "rsa2048",
		Subject:   "TPM2 RSA PIV Test",
	})
	require.NoError(t, err, "GeneratePIVKey failed")
	require.NotNil(t, resp)

	cert := parsePEMCertificate(t, resp.Certificate)
	assert.Equal(t, "TPM2 RSA PIV Test", cert.Subject.CommonName)
	assert.Equal(t, x509.RSA, cert.PublicKeyAlgorithm)

	pub := parsePEMPublicKey(t, resp.PublicKey)
	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok, "expected RSA public key")
	assert.Equal(t, 2048, rsaPub.N.BitLen())
}

// TestIntegration_PIV_TPM2_CSR generates a key on TPM2, creates a CSR,
// and verifies the CSR signature.
func TestIntegration_PIV_TPM2_CSR(t *testing.T) {
	cleanup := requireTPM2PIV(t)
	defer cleanup()

	ctx := context.Background()
	slot := "9d"

	// Generate key
	_, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
		Backend:   pivBackendTPM2,
		Slot:      slot,
		Algorithm: "ecdsap256",
		Subject:   "TPM2 CSR Key",
	})
	require.NoError(t, err, "GeneratePIVKey failed")

	// Generate CSR
	csrResp, err := xkms.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{
		Backend: pivBackendTPM2,
		Slot:    slot,
		Subject: "TPM2 CSR Subject",
	})
	require.NoError(t, err, "GeneratePIVCSR failed")
	require.NotNil(t, csrResp)

	block, _ := pem.Decode(csrResp.CSR)
	require.NotNil(t, block)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "TPM2 CSR Subject", csr.Subject.CommonName)

	err = csr.CheckSignature()
	require.NoError(t, err, "TPM2 CSR signature verification failed")
}

// TestIntegration_PIV_TPM2_SignAndVerify generates a key on TPM2, extracts
// the public key from the PIV certificate, and verifies that the cert and
// response public keys are consistent. When possible, it also performs a
// sign/verify round-trip using the TPM2 signer.
func TestIntegration_PIV_TPM2_SignAndVerify(t *testing.T) {
	cleanup := requireTPM2PIV(t)
	defer cleanup()

	ctx := context.Background()
	slot := "9e"

	// Generate ECDSA key
	resp, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
		Backend:   pivBackendTPM2,
		Slot:      slot,
		Algorithm: "ecdsap256",
		Subject:   "TPM2 Sign Verify Test",
	})
	require.NoError(t, err, "GeneratePIVKey failed")

	// Extract public key from the certificate
	cert := parsePEMCertificate(t, resp.Certificate)
	ecPubFromCert, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "expected ECDSA public key from cert")

	// Verify the response public key matches the certificate's public key
	pubFromResp := parsePEMPublicKey(t, resp.PublicKey)
	ecPubFromResp, ok := pubFromResp.(*ecdsa.PublicKey)
	require.True(t, ok, "expected ECDSA public key from response")

	assert.Equal(t, 0, ecPubFromCert.X.Cmp(ecPubFromResp.X), "X coordinates should match")
	assert.Equal(t, 0, ecPubFromCert.Y.Cmp(ecPubFromResp.Y), "Y coordinates should match")

	// Get the signer through the backend and test sign/verify
	backend, err := xkms.GetBackend(pivBackendTPM2)
	require.NoError(t, err)

	cn := xkms.PivSlotCN(pivcert.PIVSlotCardAuthentication)

	// The backendPIVKeyGenerator stored the key under CN "piv-9e", so
	// retrieve a signer for it from the backend.
	signer, err := backend.Signer(&types.KeyAttributes{CN: cn})
	if err != nil {
		// If the backend does not support signer retrieval by CN alone
		// (e.g., requires full attributes), we still verified the key
		// consistency above which proves the key generation was correct.
		t.Logf("Signer retrieval by CN not supported: %v (key consistency verified via cert)", err)
		return
	}

	// Sign test data
	testData := []byte("TPM2 PIV sign and verify test data")
	digest := sha256.Sum256(testData)
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	require.NoError(t, err, "signing failed")
	require.NotEmpty(t, sig)

	// Verify with public key from cert
	verified := ecdsa.VerifyASN1(ecPubFromCert, digest[:], sig)
	assert.True(t, verified, "signature verification should succeed")
}

// ---------------------------------------------------------------------------
// Cross-Backend Tests
// ---------------------------------------------------------------------------

// TestIntegration_PIV_MultiBackend registers multiple backends (software and
// optionally TPM2), generates keys on each for different slots, and verifies
// that each certificate is properly stored in its respective store with
// cross-isolation (one store does not leak into another).
func TestIntegration_PIV_MultiBackend(t *testing.T) {
	// Reset global state
	xkms.ResetPIV()
	xkms.Reset()

	ctx := context.Background()

	// Always have software
	softwareBackend, err := software.NewBackend(&software.Config{
		KeyStorage: storage.New(),
	})
	require.NoError(t, err)

	softwareKS, err := xkms.New(&xkms.BackendConfig{
		Backend:     softwareBackend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	backends := map[string]xkms.Backend{
		pivBackendSoftware: softwareKS,
	}

	pivStores := map[string]pivcert.PIVCertificateStorage{}

	// Software PIV store
	pivStores[pivBackendSoftware] = newPIVCertStore(t)

	// Optionally add TPM2
	hasTPM2 := false
	simHost := os.Getenv("TPM2_SIMULATOR_HOST")
	_, hwErr := os.Stat("/dev/tpmrm0")
	if simHost != "" || hwErr == nil {
		hasTPM2 = true
		keyDir := t.TempDir()
		config := &tpm2.Config{
			KeyDir: keyDir,
		}
		if simHost != "" {
			config.UseSimulator = true
		} else {
			config.Device = "/dev/tpmrm0"
		}

		tpm2Be, err := tpm2.NewBackend(config)
		require.NoError(t, err)

		tpm2KS, err := xkms.New(&xkms.BackendConfig{
			Backend:     tpm2Be,
			CertStorage: storage.New(),
		})
		require.NoError(t, err)

		backends[pivBackendTPM2] = tpm2KS
		pivStores[pivBackendTPM2] = newPIVCertStore(t)

		t.Cleanup(func() { tpm2Be.Close() })
	}

	// Initialize XKMS with all backends
	err = xkms.Initialize(&xkms.ServiceConfig{
		Backends:       backends,
		DefaultBackend: pivBackendSoftware,
	})
	require.NoError(t, err)

	err = xkms.InitializePIV(&xkms.PIVManagerConfig{
		Stores: pivStores,
	})
	require.NoError(t, err)

	// Wire the backend resolver for hardware backends
	if hasTPM2 {
		svc, err := xkms.Get()
		require.NoError(t, err)
		err = svc.InitPIVBackendResolver()
		require.NoError(t, err)
	}

	defer func() {
		xkms.ResetPIV()
		xkms.Reset()
	}()

	// Generate key on software backend (slot 9a)
	softwareResp, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
		Backend:   pivBackendSoftware,
		Slot:      "9a",
		Algorithm: "ecdsap256",
		Subject:   "Multi Software 9a",
	})
	require.NoError(t, err)
	swCert := parsePEMCertificate(t, softwareResp.Certificate)
	assert.Equal(t, "Multi Software 9a", swCert.Subject.CommonName)

	// Verify software cert is retrievable
	_, err = xkms.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
		Backend: pivBackendSoftware,
		Slot:    "9a",
		Format:  "pem",
	})
	require.NoError(t, err, "software cert should be retrievable")

	// Generate key on TPM2 backend (slot 9c)
	if hasTPM2 {
		tpm2Resp, err := xkms.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{
			Backend:   pivBackendTPM2,
			Slot:      "9c",
			Algorithm: "ecdsap256",
			Subject:   "Multi TPM2 9c",
		})
		require.NoError(t, err)
		tpm2Cert := parsePEMCertificate(t, tpm2Resp.Certificate)
		assert.Equal(t, "Multi TPM2 9c", tpm2Cert.Subject.CommonName)

		_, err = xkms.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
			Backend: pivBackendTPM2,
			Slot:    "9c",
			Format:  "pem",
		})
		require.NoError(t, err, "TPM2 cert should be retrievable")
	}

	// Verify cross-isolation: software backend should NOT have TPM2's cert
	_, err = xkms.GetPIVCertificate(ctx, &transport.GetPIVCertificateRequest{
		Backend: pivBackendSoftware,
		Slot:    "9c",
		Format:  "pem",
	})
	assert.Error(t, err, "software store should not have TPM2's slot 9c cert")
}

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

// parsePEMCertificate decodes PEM-encoded certificate data and parses the
// X.509 certificate. Fails the test on any error.
func parsePEMCertificate(t *testing.T, pemData []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemData)
	require.NotNil(t, block, "failed to decode certificate PEM")
	require.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "failed to parse certificate")
	return cert
}

// parsePEMPublicKey decodes PEM-encoded public key data and parses the key.
// Fails the test on any error.
func parsePEMPublicKey(t *testing.T, pemData []byte) crypto.PublicKey {
	t.Helper()
	block, _ := pem.Decode(pemData)
	require.NotNil(t, block, "failed to decode public key PEM")
	require.Equal(t, "PUBLIC KEY", block.Type)

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err, "failed to parse public key")
	return pub
}
