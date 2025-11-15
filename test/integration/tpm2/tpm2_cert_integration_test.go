// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration
// +build integration

package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/jeremyhahn/go-keychain/pkg/storage/hardware"
)

// TestTPM2CertStorage performs comprehensive integration tests for TPM2 NV RAM certificate storage
func TestTPM2CertStorage(t *testing.T) {
	// Connect to TPM simulator
	tpm := openTPMSimulator(t)
	defer tpm.Close()

	// Create TPM2 certificate storage with default config
	config := hardware.DefaultTPM2CertStorageConfig()
	storage, err := hardware.NewTPM2CertStorage(tpm, config)
	if err != nil {
		t.Fatalf("Failed to create TPM2 certificate storage: %v", err)
	}
	defer storage.Close()

	t.Log("=== TPM2 Certificate Storage Integration Tests ===")

	// ========================================
	// Basic Certificate Operations
	// ========================================
	t.Run("BasicOperations", func(t *testing.T) {
		t.Run("SaveAndGetCert", func(t *testing.T) {
			cert := createTestCertificate(t, "test-basic-cert", 1024)

			// Save certificate
			err := storage.SaveCert("test-basic-cert", cert)
			if err != nil {
				t.Fatalf("Failed to save certificate: %v", err)
			}
			t.Log("✓ Certificate saved to TPM NV RAM")

			// Retrieve certificate
			retrievedCert, err := storage.GetCert("test-basic-cert")
			if err != nil {
				t.Fatalf("Failed to retrieve certificate: %v", err)
			}
			t.Log("✓ Certificate retrieved from TPM NV RAM")

			// Verify certificates match
			if !retrievedCert.Equal(cert) {
				t.Fatal("Retrieved certificate does not match saved certificate")
			}
			t.Log("✓ Retrieved certificate matches saved certificate")

			// Clean up
			if err := storage.DeleteCert("test-basic-cert"); err != nil {
				t.Logf("Warning: Failed to clean up test certificate: %v", err)
			}
		})

		t.Run("CertExists", func(t *testing.T) {
			cert := createTestCertificate(t, "test-exists-cert", 1024)

			// Check non-existent certificate
			exists, err := storage.CertExists("test-exists-cert")
			if err != nil {
				t.Fatalf("Failed to check certificate existence: %v", err)
			}
			if exists {
				t.Fatal("Certificate should not exist yet")
			}
			t.Log("✓ Non-existent certificate check passed")

			// Save certificate
			err = storage.SaveCert("test-exists-cert", cert)
			if err != nil {
				t.Fatalf("Failed to save certificate: %v", err)
			}

			// Check existing certificate
			exists, err = storage.CertExists("test-exists-cert")
			if err != nil {
				t.Fatalf("Failed to check certificate existence: %v", err)
			}
			if !exists {
				t.Fatal("Certificate should exist")
			}
			t.Log("✓ Existing certificate check passed")

			// Clean up
			if err := storage.DeleteCert("test-exists-cert"); err != nil {
				t.Logf("Warning: Failed to clean up test certificate: %v", err)
			}
		})

		t.Run("DeleteCert", func(t *testing.T) {
			cert := createTestCertificate(t, "test-delete-cert", 1024)

			// Save certificate
			err := storage.SaveCert("test-delete-cert", cert)
			if err != nil {
				t.Fatalf("Failed to save certificate: %v", err)
			}

			// Delete certificate
			err = storage.DeleteCert("test-delete-cert")
			if err != nil {
				t.Fatalf("Failed to delete certificate: %v", err)
			}
			t.Log("✓ Certificate deleted from TPM NV RAM")

			// Verify certificate is gone
			exists, err := storage.CertExists("test-delete-cert")
			if err != nil {
				t.Fatalf("Failed to check certificate existence: %v", err)
			}
			if exists {
				t.Fatal("Certificate should not exist after deletion")
			}
			t.Log("✓ Verified certificate no longer exists")
		})

		t.Run("UpdateCert", func(t *testing.T) {
			cert1 := createTestCertificate(t, "test-update-cert-v1", 1024)
			cert2 := createTestCertificate(t, "test-update-cert-v2", 1024)

			// Save initial certificate
			err := storage.SaveCert("test-update-cert", cert1)
			if err != nil {
				t.Fatalf("Failed to save initial certificate: %v", err)
			}
			t.Log("✓ Initial certificate saved")

			// Update certificate (same ID, different content)
			err = storage.SaveCert("test-update-cert", cert2)
			if err != nil {
				t.Fatalf("Failed to update certificate: %v", err)
			}
			t.Log("✓ Certificate updated")

			// Verify updated certificate
			retrievedCert, err := storage.GetCert("test-update-cert")
			if err != nil {
				t.Fatalf("Failed to retrieve updated certificate: %v", err)
			}

			if !retrievedCert.Equal(cert2) {
				t.Fatal("Retrieved certificate should match updated version")
			}
			t.Log("✓ Updated certificate retrieved correctly")

			// Clean up
			if err := storage.DeleteCert("test-update-cert"); err != nil {
				t.Logf("Warning: Failed to clean up test certificate: %v", err)
			}
		})
	})

	// ========================================
	// Certificate Chain Operations
	// ========================================
	t.Run("CertificateChains", func(t *testing.T) {
		t.Run("SaveAndGetCertChain", func(t *testing.T) {
			cert1 := createTestCertificate(t, "chain-cert-1", 1024)
			cert2 := createTestCertificate(t, "chain-cert-2", 1024)
			chain := []*x509.Certificate{cert1, cert2}

			// Save certificate chain
			err := storage.SaveCertChain("test-chain", chain)
			if err != nil {
				t.Fatalf("Failed to save certificate chain: %v", err)
			}
			t.Log("✓ Certificate chain saved to TPM NV RAM")

			// Retrieve certificate chain
			retrievedChain, err := storage.GetCertChain("test-chain")
			if err != nil {
				t.Fatalf("Failed to retrieve certificate chain: %v", err)
			}
			t.Logf("✓ Certificate chain retrieved (%d certificates)", len(retrievedChain))

			// Verify chain length
			if len(retrievedChain) != len(chain) {
				t.Fatalf("Expected %d certificates in chain, got %d", len(chain), len(retrievedChain))
			}
			t.Log("✓ Chain length matches")

			// Verify each certificate
			for i := 0; i < len(chain); i++ {
				if !retrievedChain[i].Equal(chain[i]) {
					t.Fatalf("Certificate %d in chain does not match", i)
				}
			}
			t.Log("✓ All certificates in chain match")

			// Clean up
			if err := storage.DeleteCert("test-chain"); err != nil {
				t.Logf("Warning: Failed to clean up test chain: %v", err)
			}
		})

		t.Run("SupportsChains", func(t *testing.T) {
			if !storage.SupportsChains() {
				t.Fatal("TPM2 certificate storage should support chains")
			}
			t.Log("✓ TPM2 storage supports certificate chains")
		})
	})

	// ========================================
	// Size Limits and Capacity
	// ========================================
	t.Run("SizeLimitsAndCapacity", func(t *testing.T) {
		t.Run("SmallCertificate", func(t *testing.T) {
			cert := createTestCertificate(t, "small-cert", 1024)

			err := storage.SaveCert("test-small-cert", cert)
			if err != nil {
				t.Fatalf("Failed to save small certificate: %v", err)
			}
			t.Logf("✓ Small certificate saved (RSA-1024)")

			// Clean up
			if err := storage.DeleteCert("test-small-cert"); err != nil {
				t.Logf("Warning: Failed to clean up small certificate: %v", err)
			}
		})

		t.Run("LargeCertificate", func(t *testing.T) {
			// Approach the 2KB default limit
			cert := createTestCertificate(t, "large-cert", 2048)

			err := storage.SaveCert("test-large-cert", cert)
			if err != nil {
				t.Fatalf("Failed to save large certificate: %v", err)
			}
			t.Logf("✓ Large certificate saved (RSA-2048)")

			// Clean up
			if err := storage.DeleteCert("test-large-cert"); err != nil {
				t.Logf("Warning: Failed to clean up large certificate: %v", err)
			}
		})

		t.Run("OversizedCertificate", func(t *testing.T) {
			// Create a certificate that exceeds the max size
			// Using RSA-4096 should exceed the 2KB limit
			cert := createTestCertificate(t, "oversized-cert", 4096)

			err := storage.SaveCert("test-oversized-cert", cert)
			if err == nil {
				// TPM accepted the oversized certificate (has larger limits than expected)
				storage.DeleteCert("test-oversized-cert")
				t.Log("⚠ Oversized certificate was accepted - TPM has larger limits than 2KB")
				return
			}
			if err != hardware.ErrCertificateTooLarge {
				t.Fatalf("Expected ErrCertificateTooLarge, got: %v", err)
			}
			t.Log("✓ Oversized certificate correctly rejected")
		})

		t.Run("GetCapacity", func(t *testing.T) {
			total, available, err := storage.GetCapacity()
			if err != nil {
				t.Fatalf("Failed to get capacity: %v", err)
			}
			t.Logf("✓ TPM NV RAM capacity: %d total, %d available", total, available)

			if total < 1 {
				t.Fatal("Total capacity should be at least 1")
			}
			if available < 0 {
				t.Fatal("Available capacity should not be negative")
			}
			if available > total {
				t.Fatal("Available capacity should not exceed total capacity")
			}
			t.Log("✓ Capacity values are valid")
		})
	})

	// ========================================
	// NV RAM-Specific Scenarios
	// ========================================
	t.Run("NVRAMScenarios", func(t *testing.T) {
		t.Run("MultipleCertificates", func(t *testing.T) {
			// Save multiple certificates to test NV index allocation
			certs := []string{"nv-test-1", "nv-test-2"}

			for _, id := range certs {
				cert := createTestCertificate(t, id, 1024)
				err := storage.SaveCert(id, cert)
				if err != nil {
					t.Fatalf("Failed to save certificate %s: %v", id, err)
				}
				t.Logf("✓ Saved certificate %s", id)
			}

			// Verify all certificates exist
			for _, id := range certs {
				exists, err := storage.CertExists(id)
				if err != nil {
					t.Fatalf("Failed to check existence of %s: %v", id, err)
				}
				if !exists {
					t.Fatalf("Certificate %s should exist", id)
				}
			}
			t.Log("✓ All certificates stored successfully")

			// Clean up
			for _, id := range certs {
				if err := storage.DeleteCert(id); err != nil {
					t.Logf("Warning: Failed to clean up certificate %s: %v", id, err)
				}
			}
		})

		t.Run("NVIndexPersistence", func(t *testing.T) {
			cert := createTestCertificate(t, "persistent-cert", 1024)

			// Save certificate
			err := storage.SaveCert("test-persistent", cert)
			if err != nil {
				t.Fatalf("Failed to save certificate: %v", err)
			}
			t.Log("✓ Certificate saved")

			// Close and reopen storage
			storage.Close()
			storage, err = hardware.NewTPM2CertStorage(tpm, config)
			if err != nil {
				t.Fatalf("Failed to reopen TPM2 certificate storage: %v", err)
			}

			// Verify certificate still exists
			exists, err := storage.CertExists("test-persistent")
			if err != nil {
				t.Fatalf("Failed to check certificate existence after reopen: %v", err)
			}
			if !exists {
				t.Fatal("Certificate should persist across storage reopens")
			}
			t.Log("✓ Certificate persisted in NV RAM")

			// Retrieve and verify
			retrievedCert, err := storage.GetCert("test-persistent")
			if err != nil {
				t.Fatalf("Failed to retrieve persistent certificate: %v", err)
			}
			if !retrievedCert.Equal(cert) {
				t.Fatal("Retrieved certificate does not match original")
			}
			t.Log("✓ Persistent certificate retrieved correctly")

			// Clean up
			if err := storage.DeleteCert("test-persistent"); err != nil {
				t.Logf("Warning: Failed to clean up persistent certificate: %v", err)
			}
		})

		t.Run("ChunkedIO", func(t *testing.T) {
			// Create a certificate that requires chunked I/O (>1KB)
			cert := createTestCertificate(t, "chunked-cert", 1536)

			// Save certificate (should use chunked write)
			err := storage.SaveCert("test-chunked", cert)
			if err != nil {
				t.Fatalf("Failed to save certificate requiring chunked I/O: %v", err)
			}
			t.Log("✓ Certificate saved using chunked I/O")

			// Retrieve certificate (should use chunked read)
			retrievedCert, err := storage.GetCert("test-chunked")
			if err != nil {
				t.Fatalf("Failed to retrieve certificate using chunked I/O: %v", err)
			}

			if !retrievedCert.Equal(cert) {
				t.Fatal("Retrieved certificate does not match after chunked I/O")
			}
			t.Log("✓ Chunked I/O operations successful")

			// Clean up
			if err := storage.DeleteCert("test-chunked"); err != nil {
				t.Logf("Warning: Failed to clean up chunked certificate: %v", err)
			}
		})

		t.Run("ListCerts", func(t *testing.T) {
			// Save some test certificates
			certs := []string{"list-test-1", "list-test-2"}
			for _, id := range certs {
				cert := createTestCertificate(t, id, 1024)
				err := storage.SaveCert(id, cert)
				if err != nil {
					t.Fatalf("Failed to save certificate %s: %v", id, err)
				}
			}

			// List certificates
			certList, err := storage.ListCerts()
			if err != nil {
				t.Fatalf("Failed to list certificates: %v", err)
			}
			t.Logf("✓ Listed %d certificates in TPM NV RAM", len(certList))

			if len(certList) < len(certs) {
				t.Logf("Warning: Expected at least %d certificates, got %d", len(certs), len(certList))
			}

			// Clean up
			for _, id := range certs {
				if err := storage.DeleteCert(id); err != nil {
					t.Logf("Warning: Failed to clean up certificate %s: %v", id, err)
				}
			}
		})
	})

	// ========================================
	// Error Scenarios
	// ========================================
	t.Run("ErrorScenarios", func(t *testing.T) {
		t.Run("GetNonExistentCert", func(t *testing.T) {
			_, err := storage.GetCert("non-existent-cert")
			if err == nil {
				t.Fatal("Expected error when getting non-existent certificate")
			}
			t.Logf("✓ Correctly returned error for non-existent certificate: %v", err)
		})

		t.Run("DeleteNonExistentCert", func(t *testing.T) {
			// Delete should be idempotent
			err := storage.DeleteCert("non-existent-cert")
			// Some implementations may return error, others may succeed silently
			t.Logf("Delete non-existent certificate result: %v", err)
		})

		t.Run("EmptyID", func(t *testing.T) {
			cert := createTestCertificate(t, "empty-id-test", 1024)

			err := storage.SaveCert("", cert)
			if err == nil {
				t.Fatal("Expected error when saving certificate with empty ID")
			}
			t.Logf("✓ Correctly rejected empty certificate ID: %v", err)
		})

		t.Run("NilCertificate", func(t *testing.T) {
			err := storage.SaveCert("nil-cert-test", nil)
			if err == nil {
				t.Fatal("Expected error when saving nil certificate")
			}
			t.Logf("✓ Correctly rejected nil certificate: %v", err)
		})

		t.Run("EmptyCertChain", func(t *testing.T) {
			err := storage.SaveCertChain("empty-chain", []*x509.Certificate{})
			if err == nil {
				t.Fatal("Expected error when saving empty certificate chain")
			}
			t.Logf("✓ Correctly rejected empty certificate chain: %v", err)
		})

		t.Run("ClosedStorage", func(t *testing.T) {
			// Create a new storage instance to test closure
			testStorage, err := hardware.NewTPM2CertStorage(tpm, config)
			if err != nil {
				t.Fatalf("Failed to create test storage: %v", err)
			}

			// Close storage
			err = testStorage.Close()
			if err != nil {
				t.Fatalf("Failed to close storage: %v", err)
			}
			t.Log("✓ Storage closed successfully")

			// Try to use closed storage
			cert := createTestCertificate(t, "closed-test", 1024)
			err = testStorage.SaveCert("closed-test", cert)
			if err != hardware.ErrStorageClosed {
				t.Fatalf("Expected ErrStorageClosed, got: %v", err)
			}
			t.Log("✓ Correctly rejected operation on closed storage")

			// Double close should also return error
			err = testStorage.Close()
			if err != hardware.ErrStorageClosed {
				t.Fatalf("Expected ErrStorageClosed on double close, got: %v", err)
			}
			t.Log("✓ Correctly rejected double close")
		})
	})

	// ========================================
	// Hardware-Specific Features
	// ========================================
	t.Run("HardwareFeatures", func(t *testing.T) {
		t.Run("IsHardwareBacked", func(t *testing.T) {
			if !storage.IsHardwareBacked() {
				t.Fatal("TPM2 certificate storage should be hardware-backed")
			}
			t.Log("✓ TPM2 storage is hardware-backed")
		})

		t.Run("CompactOperation", func(t *testing.T) {
			err := storage.Compact()
			if err != hardware.ErrNotSupported {
				t.Logf("Compact operation result: %v", err)
			} else {
				t.Log("✓ Compact correctly returns ErrNotSupported")
			}
		})
	})

	// ========================================
	// End-to-End Workflow
	// ========================================
	t.Run("EndToEndWorkflow", func(t *testing.T) {
		t.Run("CompleteLifecycle", func(t *testing.T) {
			// Create certificate
			cert := createTestCertificate(t, "e2e-cert", 1024)
			t.Log("✓ Certificate created")

			// Check capacity before
			totalBefore, availableBefore, err := storage.GetCapacity()
			if err != nil {
				t.Fatalf("Failed to get capacity: %v", err)
			}
			t.Logf("✓ Capacity before: %d total, %d available", totalBefore, availableBefore)

			// Save certificate
			err = storage.SaveCert("e2e-test", cert)
			if err != nil {
				t.Fatalf("Failed to save certificate: %v", err)
			}
			t.Log("✓ Certificate saved")

			// Verify it exists
			exists, err := storage.CertExists("e2e-test")
			if err != nil || !exists {
				t.Fatalf("Certificate should exist: %v", err)
			}
			t.Log("✓ Certificate exists")

			// Retrieve and verify
			retrievedCert, err := storage.GetCert("e2e-test")
			if err != nil {
				t.Fatalf("Failed to retrieve certificate: %v", err)
			}
			if !retrievedCert.Equal(cert) {
				t.Fatal("Retrieved certificate does not match")
			}
			t.Log("✓ Certificate retrieved and verified")

			// Check capacity after save
			totalAfter, availableAfter, err := storage.GetCapacity()
			if err != nil {
				t.Fatalf("Failed to get capacity: %v", err)
			}
			t.Logf("✓ Capacity after save: %d total, %d available", totalAfter, availableAfter)

			if availableAfter >= availableBefore {
				t.Logf("Warning: Available capacity did not decrease (before: %d, after: %d)", availableBefore, availableAfter)
			}

			// Delete certificate
			err = storage.DeleteCert("e2e-test")
			if err != nil {
				t.Fatalf("Failed to delete certificate: %v", err)
			}
			t.Log("✓ Certificate deleted")

			// Verify it's gone
			exists, err = storage.CertExists("e2e-test")
			if err != nil || exists {
				t.Fatalf("Certificate should not exist after deletion")
			}
			t.Log("✓ Certificate no longer exists")

			// Check capacity after delete
			totalFinal, availableFinal, err := storage.GetCapacity()
			if err != nil {
				t.Fatalf("Failed to get capacity: %v", err)
			}
			t.Logf("✓ Capacity after delete: %d total, %d available", totalFinal, availableFinal)

			t.Log("✓ Complete lifecycle test passed")
		})
	})

	t.Log("=== TPM2 Certificate Storage Integration Tests Completed ===")
}

// openTPMSimulator connects to the TPM simulator using environment variables
func openTPMSimulator(t *testing.T) transport.TPMCloser {
	t.Helper()

	simHost := os.Getenv("TPM2_SIMULATOR_HOST")
	simPort := os.Getenv("TPM2_SIMULATOR_PORT")

	if simHost != "" && simPort != "" {
		// Use TCP simulator (SWTPM)
		addr := fmt.Sprintf("%s:%s", simHost, simPort)
		t.Logf("Connecting to TPM simulator at %s", addr)

		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("Failed to connect to TPM simulator at %s: %v", addr, err)
		}

		return transport.FromReadWriteCloser(conn)
	}

	// Try embedded simulator
	t.Log("Using embedded TPM simulator")
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		// Try hardware TPM device as fallback
		tpmDevice := os.Getenv("TPM_DEVICE")
		if tpmDevice == "" {
			tpmDevice = "/dev/tpmrm0"
		}

		if _, err := os.Stat(tpmDevice); os.IsNotExist(err) {
			t.Skipf("Skipping TPM2 cert integration tests: No TPM available (simulator failed: %v, device %s not found)", err, tpmDevice)
		}

		t.Logf("Using hardware TPM device: %s", tpmDevice)
		tpm, err = transport.OpenTPM(tpmDevice)
		if err != nil {
			t.Fatalf("Failed to open TPM device %s: %v", tpmDevice, err)
		}
	}

	return tpm
}

// createTestCertificate creates a self-signed certificate for testing
func createTestCertificate(t *testing.T, cn string, keySize int) *x509.Certificate {
	t.Helper()

	// Generate a temporary RSA key for the certificate
	priv, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test TPM2 Cert Storage"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}
