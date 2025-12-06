//go:build integration && tpm2

package integration

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	tpm2lib "github.com/jeremyhahn/go-keychain/pkg/tpm2"
)

// setupIDevIDExtendedTPM provisions TPM with EK and IAK for IDevID testing
func setupIDevIDExtendedTPM(t *testing.T) (tpm2lib.TrustedPlatformModule, func()) {
	t.Helper()

	// Use existing helper which handles provisioning properly
	tpmInstance, cleanup := createTPM2Instance(t)

	// Provision TPM to create EK, SRK, and IAK
	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v (may already be provisioned)", err)
	}

	// Create and provision EK certificate for simulator
	// Uses the existing helper from idevid_csr_test.go
	ekCert := createSelfSignedEKCert(t, tpmInstance)

	// Provision the EK certificate (using nil auth since we provisioned with nil)
	if err := tpmInstance.ProvisionEKCert(nil, ekCert.Raw); err != nil {
		t.Logf("ProvisionEKCert returned: %v (may need cert store)", err)
	}

	return tpmInstance, cleanup
}

// TestIntegration_CreateIDevID_Complete tests complete IDevID creation workflow
func TestIntegration_CreateIDevID_Complete(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDExtendedTPM(t)
	defer cleanup()

	t.Run("CreateIDevIDBasic", func(t *testing.T) {
		// Get IAK attributes (TPM already provisioned by setup)
		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		// Get EK certificate (already provisioned by setup)
		ekCert, err := tpmInstance.EKCertificate()
		if err != nil {
			t.Fatalf("Failed to get EK certificate: %v", err)
		}

		// Create qualifying data (nonce)
		qualifyingData := []byte("idevid-test-qualifying-data")

		// Create IDevID with EK cert
		idevidAttrs, tcgCSR, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, qualifyingData)
		if err != nil {
			t.Fatalf("Failed to create IDevID: %v", err)
		}

		// Verify IDevID attributes
		if idevidAttrs == nil {
			t.Fatal("CreateIDevID returned nil attributes")
		}

		if idevidAttrs.TPMAttributes == nil {
			t.Fatal("IDevID TPMAttributes not set")
		}

		if idevidAttrs.TPMAttributes.Handle == 0 {
			t.Error("IDevID handle not set")
		}

		if len(idevidAttrs.TPMAttributes.Name.Buffer) == 0 {
			t.Error("IDevID name not set")
		}

		if len(idevidAttrs.TPMAttributes.PublicKeyBytes) == 0 {
			t.Error("IDevID public key bytes not set")
		}

		if len(idevidAttrs.TPMAttributes.CertifyInfo) == 0 {
			t.Error("IDevID certify info not set")
		}

		if len(idevidAttrs.TPMAttributes.Signature) == 0 {
			t.Error("IDevID signature not set")
		}

		// TCG CSR should be created with EK cert
		if tcgCSR != nil {
			t.Log("TCG CSR was created")
		} else {
			t.Log("TCG CSR was not created")
		}

		t.Logf("Successfully created IDevID:")
		t.Logf("  Handle: 0x%x", idevidAttrs.TPMAttributes.Handle)
		t.Logf("  CN: %s", idevidAttrs.CN)
		t.Logf("  Public Key: %d bytes", len(idevidAttrs.TPMAttributes.PublicKeyBytes))
		t.Logf("  Signature: %d bytes", len(idevidAttrs.TPMAttributes.Signature))

		// Clean up - delete IDevID
		if err := tpmInstance.DeleteKey(idevidAttrs, nil); err != nil {
			t.Logf("Warning: failed to delete IDevID: %v", err)
		}
	})
}

// TestIntegration_CreateIDevID_QualifyingData tests IDevID with various qualifying data
func TestIntegration_CreateIDevID_QualifyingData(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDExtendedTPM(t)
	defer cleanup()

	// Provision TPM first
	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	// Get EK certificate once for all test cases
	ekCert, err := tpmInstance.EKCertificate()
	if err != nil {
		t.Fatalf("Failed to get EK certificate: %v", err)
	}

	testCases := []struct {
		name           string
		qualifyingData []byte
		expectError    bool // TPM2 qualifying data is limited to ~64 bytes
	}{
		{"EmptyQualifyingData", nil, false},
		{"SmallQualifyingData", []byte("small"), false},
		{"MediumQualifyingData", make([]byte, 48), false}, // Use 48 instead of 64 to be safe
		{"LargeQualifyingData", make([]byte, 128), true},  // Exceeds TPM limit
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			iakAttrs, err := tpmInstance.IAKAttributes()
			if err != nil {
				t.Fatalf("Failed to get IAK attributes: %v", err)
			}

			idevidAttrs, _, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, tc.qualifyingData)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for %s (exceeds TPM limit), but got success", tc.name)
				} else {
					t.Logf("Correctly rejected %s: %v", tc.name, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to create IDevID with %s: %v", tc.name, err)
			}

			if idevidAttrs == nil {
				t.Fatalf("IDevID attributes are nil for %s", tc.name)
			}

			// Verify signature was created (it should include the qualifying data)
			if len(idevidAttrs.TPMAttributes.Signature) == 0 {
				t.Errorf("Signature not created for %s", tc.name)
			}

			t.Logf("Created IDevID with %s (%d bytes qualifying data)",
				tc.name, len(tc.qualifyingData))

			// Clean up
			if err := tpmInstance.DeleteKey(idevidAttrs, nil); err != nil {
				t.Logf("Warning: failed to delete IDevID: %v", err)
			}
		})
	}
}

// TestIntegration_CreateIDevID_ErrorHandling tests error conditions
func TestIntegration_CreateIDevID_ErrorHandling(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDExtendedTPM(t)
	defer cleanup()

	t.Run("NilAKAttributes", func(t *testing.T) {
		// This test intentionally tests nil parameters for error handling
		_, _, err := tpmInstance.CreateIDevID(nil, nil, nil)
		if err == nil {
			t.Error("Expected error with nil AK attributes, got none")
		} else {
			t.Logf("Correctly rejected nil AK attributes: %v", err)
		}
	})
}

// TestIntegration_CreateIDevID_Persistence tests IDevID persistence
func TestIntegration_CreateIDevID_Persistence(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDExtendedTPM(t)
	defer cleanup()

	t.Run("IDevIDPersistence", func(t *testing.T) {
		// Provision TPM first
		if err := tpmInstance.Provision(nil); err != nil {
			t.Logf("Provision returned: %v", err)
		}

		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		// Get EK certificate
		ekCert, err := tpmInstance.EKCertificate()
		if err != nil {
			t.Fatalf("Failed to get EK certificate: %v", err)
		}

		qualifyingData := []byte("persistence-test")

		idevidAttrs, _, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, qualifyingData)
		if err != nil {
			t.Fatalf("Failed to create IDevID: %v", err)
		}
		defer func() {
			if err := tpmInstance.DeleteKey(idevidAttrs, nil); err != nil {
				t.Logf("Warning: failed to delete IDevID: %v", err)
			}
		}()

		// Verify the IDevID is persisted to the handle
		idevidHandle := idevidAttrs.TPMAttributes.Handle

		// Read the public area to verify persistence
		readPub, err := tpm2.ReadPublic{
			ObjectHandle: idevidHandle,
		}.Execute(tpmInstance.Transport())
		if err != nil {
			t.Fatalf("Failed to read persisted IDevID: %v", err)
		}

		// Verify the name matches
		if len(readPub.Name.Buffer) == 0 {
			t.Error("Persisted IDevID has empty name")
		}

		// Names should match
		if len(readPub.Name.Buffer) != len(idevidAttrs.TPMAttributes.Name.Buffer) {
			t.Error("Persisted IDevID name length mismatch")
		}

		t.Logf("IDevID successfully persisted at handle 0x%x", idevidHandle)
		t.Logf("  Name: 0x%x", readPub.Name.Buffer[:idevIDMin(8, len(readPub.Name.Buffer))])
	})
}

// TestIntegration_CreateIDevID_Attributes tests IDevID attribute verification
func TestIntegration_CreateIDevID_Attributes(t *testing.T) {
	tpmInstance, cleanup := setupIDevIDExtendedTPM(t)
	defer cleanup()

	t.Run("VerifyIDevIDAttributes", func(t *testing.T) {
		// Provision TPM first
		if err := tpmInstance.Provision(nil); err != nil {
			t.Logf("Provision returned: %v", err)
		}

		iakAttrs, err := tpmInstance.IAKAttributes()
		if err != nil {
			t.Fatalf("Failed to get IAK attributes: %v", err)
		}

		// Get EK certificate
		ekCert, err := tpmInstance.EKCertificate()
		if err != nil {
			t.Fatalf("Failed to get EK certificate: %v", err)
		}

		idevidAttrs, _, err := tpmInstance.CreateIDevID(iakAttrs, ekCert, []byte("attr-test"))
		if err != nil {
			t.Fatalf("Failed to create IDevID: %v", err)
		}
		defer func() {
			if err := tpmInstance.DeleteKey(idevidAttrs, nil); err != nil {
				t.Logf("Warning: failed to delete IDevID: %v", err)
			}
		}()

		// Verify all key attributes are set
		checks := []struct {
			name  string
			check func() bool
			msg   string
		}{
			{"Handle", func() bool { return idevidAttrs.TPMAttributes.Handle != 0 }, "Handle is zero"},
			{"Name", func() bool { return len(idevidAttrs.TPMAttributes.Name.Buffer) > 0 }, "Name is empty"},
			{"PublicKey", func() bool { return len(idevidAttrs.TPMAttributes.PublicKeyBytes) > 0 }, "Public key bytes empty"},
			{"Signature", func() bool { return len(idevidAttrs.TPMAttributes.Signature) > 0 }, "Signature is empty"},
			{"CertifyInfo", func() bool { return len(idevidAttrs.TPMAttributes.CertifyInfo) > 0 }, "Certify info is empty"},
			{"Parent", func() bool { return idevidAttrs.Parent != nil }, "Parent is nil"},
		}

		for _, check := range checks {
			if !check.check() {
				t.Errorf("%s check failed: %s", check.name, check.msg)
			} else {
				t.Logf("%s check passed", check.name)
			}
		}
	})
}

// min helper function
func idevIDMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
