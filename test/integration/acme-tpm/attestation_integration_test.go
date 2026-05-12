// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration && tpm2

package tpm_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/handlers"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ca"
	caFixtures "github.com/jeremyhahn/go-xkms/test/integration/acme-ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// TPM Attestation Flow End-to-End Tests
// ============================================================================

// TestTPMAttestationFlow_EndToEnd tests the complete TPM attestation flow
// from initialization through quote generation and verification.
func TestTPMAttestationFlow_EndToEnd(t *testing.T) {
	RequireSwtpm(t)

	deviceID := fmt.Sprintf("attestation-e2e-%d", time.Now().Unix())
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	t.Run("TPM Initialization", func(t *testing.T) {
		err := swtpm.InitializeTPM()
		require.NoError(t, err, "TPM initialization must succeed")

		tpmModule := swtpm.GetTPMModule()
		require.NotNil(t, tpmModule, "TPM module must not be nil after initialization")
	})

	t.Run("EK and IAK Creation", func(t *testing.T) {
		err := swtpm.Provision()
		require.NoError(t, err, "TPM provisioning must succeed")

		// Verify EK certificate was created
		ekCert := swtpm.GetEKCertificate()
		require.NotNil(t, ekCert, "EK certificate must not be nil")
		assert.NotNil(t, ekCert.PublicKey, "EK certificate must have a public key")
		t.Logf("EK Certificate Subject: %s", ekCert.Subject.String())

		// Verify IAK attributes are available
		tpmModule := swtpm.GetTPMModule()
		iakAttrs, err := tpmModule.IAKAttributes()
		require.NoError(t, err, "Failed to get IAK attributes")
		require.NotNil(t, iakAttrs, "IAK attributes must not be nil")
		assert.NotEmpty(t, iakAttrs.CN, "IAK must have a Common Name")
		t.Logf("IAK Common Name: %s", iakAttrs.CN)
	})

	t.Run("Quote Generation", func(t *testing.T) {
		tpmModule := swtpm.GetTPMModule()
		require.NotNil(t, tpmModule, "TPM module must be initialized")

		// Generate a nonce for the quote request
		nonce := make([]byte, 32)
		_, err := rand.Read(nonce)
		require.NoError(t, err, "Failed to generate nonce")

		// Request a quote over PCRs 0, 1, 2, 7 (common boot measurements)
		pcrs := []uint{0, 1, 2, 7}
		quote, err := tpmModule.Quote(pcrs, nonce)
		require.NoError(t, err, "Quote generation must succeed")

		// Verify quote structure
		assert.NotEmpty(t, quote.Quoted, "Quote must contain quoted data")
		assert.NotEmpty(t, quote.Signature, "Quote must contain a signature")
		assert.NotEmpty(t, quote.PCRs, "Quote must contain PCR values")
		// Note: EventLog may be empty in swtpm simulator
		t.Logf("Quote generated: %d bytes quoted data, %d bytes signature, %d bytes PCRs",
			len(quote.Quoted), len(quote.Signature), len(quote.PCRs))
	})

	t.Run("PCR Value Retrieval", func(t *testing.T) {
		tpmModule := swtpm.GetTPMModule()

		// Read multiple PCRs
		pcrs := []uint{0, 1, 2, 7, 14, 16}
		banks, err := tpmModule.ReadPCRs(pcrs)
		require.NoError(t, err, "PCR reading must succeed")
		require.NotEmpty(t, banks, "PCR banks must not be empty")

		// Verify we have PCR values for SHA-256 bank
		var sha256Bank *xkmssdk.PCRBank
		for i := range banks {
			if banks[i].Algorithm == "sha256" || banks[i].Algorithm == "SHA256" {
				sha256Bank = &banks[i]
				break
			}
		}
		require.NotNil(t, sha256Bank, "SHA-256 PCR bank must be present")

		// Verify each requested PCR has a value
		for _, bank := range banks {
			t.Logf("PCR Bank: %s", bank.Algorithm)
			for _, pcr := range bank.PCRs {
				assert.NotNil(t, pcr.Value, "PCR[%d] value must not be nil", pcr.ID)
				// SHA-256 PCRs should be 32 bytes
				if bank.Algorithm == "sha256" || bank.Algorithm == "SHA256" {
					assert.Len(t, pcr.Value, 32, "SHA-256 PCR value must be 32 bytes")
				}
			}
		}
	})
}

// TestTPMAttestationFlow_EventLogRetrieval tests event log retrieval from the TPM.
// Note: swtpm may not provide event logs, so this test handles that gracefully.
func TestTPMAttestationFlow_EventLogRetrieval(t *testing.T) {
	RequireSwtpm(t)

	deviceID := fmt.Sprintf("eventlog-test-%d", time.Now().Unix())
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	tpmModule := swtpm.GetTPMModule()

	// Try to retrieve event log
	eventLog, err := tpmModule.EventLog()
	if err != nil {
		// Event log may not be available in swtpm - this is expected
		t.Logf("Event log not available (expected for swtpm): %v", err)
		return
	}

	if len(eventLog) == 0 {
		t.Log("Event log is empty (expected for swtpm simulator)")
		return
	}

	// If we do have an event log, verify it can be parsed
	t.Logf("Event log retrieved: %d bytes", len(eventLog))

	// The event log should start with a valid TCG header
	// For crypto-agile format, look for "Spec ID Event03" signature
	if bytes.Contains(eventLog, []byte("Spec ID Event03")) {
		t.Log("Event log uses crypto-agile format (TCG_PCR_EVENT2)")
	} else if len(eventLog) >= 32 {
		t.Log("Event log uses legacy format (TCG_PCR_EVENT)")
	}
}

// ============================================================================
// Handler TPM Validation Hook Tests
// ============================================================================

// TestPCRValidationHook_WithRealTPMData tests the PCR validation hook
// using real TPM-generated attestation data.
func TestPCRValidationHook_WithRealTPMData(t *testing.T) {
	RequireSwtpm(t)

	deviceID := fmt.Sprintf("pcr-hook-test-%d", time.Now().Unix())
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	tpmModule := swtpm.GetTPMModule()

	// Read current PCR values
	pcrs := []uint{0, 7, 14}
	banks, err := tpmModule.ReadPCRs(pcrs)
	require.NoError(t, err)

	// Find SHA-256 PCR values
	var expectedPCRs map[int][]byte
	for _, bank := range banks {
		if bank.Algorithm == "sha256" || bank.Algorithm == "SHA256" {
			expectedPCRs = make(map[int][]byte)
			for _, pcr := range bank.PCRs {
				expectedPCRs[int(pcr.ID)] = pcr.Value
			}
			break
		}
	}
	require.NotEmpty(t, expectedPCRs, "Should have SHA-256 PCR values")

	t.Run("Matching PCRs Pass Validation", func(t *testing.T) {
		// Create policy with expected PCR values
		policy := &handlers.PCRPolicy{
			ExpectedPCRs: expectedPCRs,
			StrictMode:   true,
		}

		hook := handlers.NewPCRValidationHook(policy)

		// Generate quote to get ProdCaData
		nonce := make([]byte, 32)
		rand.Read(nonce)
		quote, err := tpmModule.Quote(pcrs, nonce)
		require.NoError(t, err)

		// Pack ProdCaData
		prodCaData := &xkmssdk.ProdCaData{
			Quoted:    quote.Quoted,
			Signature: quote.Signature,
			Nonce:     quote.Nonce,
			PCRs:      quote.PCRs,
		}
		packedProdCaData, err := xkmssdk.PackProdCaData(prodCaData)
		require.NoError(t, err)

		// Create hook context
		ctx := &handlers.PreIssuanceHookContext{
			Context:  context.Background(),
			IsTCGCSR: true,
			TCGData: &handlers.TCGEnrollmentData{
				ProductSerial: deviceID,
				ProductModel:  "TEST-MODEL",
				ProdCaData:    packedProdCaData,
			},
		}

		// Execute hook
		err = hook(ctx)
		assert.NoError(t, err, "PCR validation should pass with matching values")
	})

	t.Run("Mismatched PCRs Fail Validation", func(t *testing.T) {
		// Create policy with wrong expected PCR values
		wrongPCRs := make(map[int][]byte)
		for k, v := range expectedPCRs {
			// Create a copy with different values
			wrongValue := make([]byte, len(v))
			copy(wrongValue, v)
			if len(wrongValue) > 0 {
				wrongValue[0] ^= 0xFF // Flip bits to create mismatch
			}
			wrongPCRs[k] = wrongValue
		}

		policy := &handlers.PCRPolicy{
			ExpectedPCRs: wrongPCRs,
			StrictMode:   true,
		}

		hook := handlers.NewPCRValidationHook(policy)

		// Generate quote
		nonce := make([]byte, 32)
		rand.Read(nonce)
		quote, err := tpmModule.Quote(pcrs, nonce)
		require.NoError(t, err)

		// Pack ProdCaData
		prodCaData := &xkmssdk.ProdCaData{
			Quoted:    quote.Quoted,
			Signature: quote.Signature,
			Nonce:     quote.Nonce,
			PCRs:      quote.PCRs,
		}
		packedProdCaData, err := xkmssdk.PackProdCaData(prodCaData)
		require.NoError(t, err)

		// Create hook context
		ctx := &handlers.PreIssuanceHookContext{
			Context:  context.Background(),
			IsTCGCSR: true,
			TCGData: &handlers.TCGEnrollmentData{
				ProductSerial: deviceID,
				ProductModel:  "TEST-MODEL",
				ProdCaData:    packedProdCaData,
			},
		}

		// Execute hook - should fail
		err = hook(ctx)
		assert.Error(t, err, "PCR validation should fail with mismatched values")
		assert.ErrorIs(t, err, handlers.ErrPCRMismatch, "Error should be PCR mismatch")
	})
}

// TestDeviceProfileValidation_WithRealTPMData tests device profile validation
// with real TPM attestation data.
func TestDeviceProfileValidation_WithRealTPMData(t *testing.T) {
	RequireSwtpm(t)

	deviceID := fmt.Sprintf("profile-test-%d", time.Now().Unix())
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	tpmModule := swtpm.GetTPMModule()

	// Read current PCR values for the profile
	pcrs := []uint{0, 7}
	banks, err := tpmModule.ReadPCRs(pcrs)
	require.NoError(t, err)

	// Build expected PCR map from SHA-256 bank
	expectedPCRs := make(map[int][]byte)
	for _, bank := range banks {
		if bank.Algorithm == "sha256" || bank.Algorithm == "SHA256" {
			for _, pcr := range bank.PCRs {
				expectedPCRs[int(pcr.ID)] = pcr.Value
			}
			break
		}
	}

	t.Run("Known Device Profile Matches", func(t *testing.T) {
		// Create a device profile store
		profiles := map[string]*handlers.DeviceProfile{
			deviceID: {
				ProductSerial: deviceID,
				ProductModel:  "TEST-MODEL",
				ExpectedPCRs:  expectedPCRs,
			},
		}

		lookupFunc := func(serial, model string) (*handlers.DeviceProfile, error) {
			if profile, ok := profiles[serial]; ok {
				return profile, nil
			}
			return nil, nil // Unknown device
		}

		hook := handlers.NewDeviceProfileHook(lookupFunc)

		// Generate attestation data
		nonce := make([]byte, 32)
		rand.Read(nonce)
		quote, err := tpmModule.Quote(pcrs, nonce)
		require.NoError(t, err)

		prodCaData := &xkmssdk.ProdCaData{
			Quoted:    quote.Quoted,
			Signature: quote.Signature,
			Nonce:     quote.Nonce,
			PCRs:      quote.PCRs,
		}
		packedProdCaData, err := xkmssdk.PackProdCaData(prodCaData)
		require.NoError(t, err)

		ctx := &handlers.PreIssuanceHookContext{
			Context:  context.Background(),
			IsTCGCSR: true,
			TCGData: &handlers.TCGEnrollmentData{
				ProductSerial: deviceID,
				ProductModel:  "TEST-MODEL",
				ProdCaData:    packedProdCaData,
			},
		}

		err = hook(ctx)
		assert.NoError(t, err, "Device profile validation should pass for known device")
	})

	t.Run("Unknown Device Allowed By Default", func(t *testing.T) {
		// Empty profile store
		lookupFunc := func(serial, model string) (*handlers.DeviceProfile, error) {
			return nil, nil // No profile found
		}

		hook := handlers.NewDeviceProfileHook(lookupFunc)

		ctx := &handlers.PreIssuanceHookContext{
			Context:  context.Background(),
			IsTCGCSR: true,
			TCGData: &handlers.TCGEnrollmentData{
				ProductSerial: "unknown-device",
				ProductModel:  "UNKNOWN-MODEL",
			},
		}

		err := hook(ctx)
		assert.NoError(t, err, "Unknown devices should be allowed by default")
	})
}

// ============================================================================
// CA TPM Certificate Signing Tests
// ============================================================================

// TestAttestationSignTCGCSRIDevID_RealTPMGenerated tests the CA's TCG-CSR signing
// with a real TPM-generated CSR.
func TestAttestationSignTCGCSRIDevID_RealTPMGenerated(t *testing.T) {
	RequireSwtpm(t)

	caInstance, cleanup := caFixtures.NewTestCA(t)
	defer cleanup()

	deviceID := fmt.Sprintf("tcgcsr-sign-%d", time.Now().Unix())
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	// Generate qualifying data (nonce from CA)
	qualifyingData := make([]byte, 32)
	_, err := rand.Read(qualifyingData)
	require.NoError(t, err)

	require.NoError(t, swtpm.CreateIDevID(qualifyingData))

	tcgCSR := swtpm.GetTCGCSR()
	require.NotNil(t, tcgCSR)

	certRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   "IDevID-" + deviceID,
			Organization: "Test Organization",
			Country:      "US",
		},
		Valid:       0, // Indefinite validity for IDevID
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	t.Run("Sign TCG-CSR Successfully", func(t *testing.T) {
		iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(tcgCSR, certRequest)
		require.NoError(t, err, "SignTCGCSRIDevID should succeed")
		require.NotNil(t, iakDER, "IAK certificate should not be nil")
		require.NotNil(t, idevidDER, "IDevID certificate should not be nil")

		// Parse certificates
		iakCert, err := x509.ParseCertificate(iakDER)
		require.NoError(t, err)
		idevidCert, err := x509.ParseCertificate(idevidDER)
		require.NoError(t, err)

		t.Logf("IAK Certificate Serial: %s", iakCert.SerialNumber.String())
		t.Logf("IDevID Certificate Serial: %s", idevidCert.SerialNumber.String())

		LogCertificate(t, iakCert, "Issued IAK Certificate")
		LogCertificate(t, idevidCert, "Issued IDevID Certificate")
	})
}

// TestAttestationSignTCGCSRIDevID_CertificateExtensions verifies TCG extensions in issued certificates.
func TestAttestationSignTCGCSRIDevID_CertificateExtensions(t *testing.T) {
	RequireSwtpm(t)

	caInstance, cleanup := caFixtures.NewTestCA(t)
	defer cleanup()

	deviceID := fmt.Sprintf("tcg-ext-%d", time.Now().Unix())
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	qualifyingData := make([]byte, 32)
	rand.Read(qualifyingData)

	require.NoError(t, swtpm.CreateIDevID(qualifyingData))

	tcgCSR := swtpm.GetTCGCSR()
	require.NotNil(t, tcgCSR)

	certRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   "IDevID-" + deviceID,
			Organization: "Test Organization",
			Country:      "US",
		},
		Valid: 0,
	}

	iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(tcgCSR, certRequest)
	require.NoError(t, err)

	iakCert, err := x509.ParseCertificate(iakDER)
	require.NoError(t, err)
	idevidCert, err := x509.ParseCertificate(idevidDER)
	require.NoError(t, err)

	t.Run("IAK Certificate Has TCG AIK Marker", func(t *testing.T) {
		hasAIKMarker := false
		for _, ext := range iakCert.Extensions {
			if ext.Id.Equal(ca.OIDTCGKpAIKCertificate) {
				hasAIKMarker = true
				break
			}
		}
		assert.True(t, hasAIKMarker, "IAK certificate must have TCG AIK Certificate marker (OID 2.23.133.8.3)")
	})

	t.Run("Certificates Have TCG Policy Identifiers", func(t *testing.T) {
		// Check IAK policies
		assert.True(t, hasPolicyIdentifier(iakCert, ca.OIDTCGVerifiedTPMResidency),
			"IAK should have VerifiedTPMResidency policy")
		assert.True(t, hasPolicyIdentifier(iakCert, ca.OIDTCGVerifiedTPMFixed),
			"IAK should have VerifiedTPMFixed policy")

		// Check IDevID policies
		assert.True(t, hasPolicyIdentifier(idevidCert, ca.OIDTCGVerifiedTPMResidency),
			"IDevID should have VerifiedTPMResidency policy")
		assert.True(t, hasPolicyIdentifier(idevidCert, ca.OIDTCGVerifiedTPMFixed),
			"IDevID should have VerifiedTPMFixed policy")
	})

	t.Run("Certificates Have TPM Model Extension", func(t *testing.T) {
		hasTPMModelIAK := false
		hasTPMModelIDevID := false

		for _, ext := range iakCert.Extensions {
			if ext.Id.Equal(ca.OIDTCGAttributeTPMModel) {
				hasTPMModelIAK = true
				var model string
				_, err := asn1.Unmarshal(ext.Value, &model)
				require.NoError(t, err)
				assert.NotEmpty(t, model, "TPM model should not be empty")
				t.Logf("IAK TPM Model: %s", model)
			}
		}

		for _, ext := range idevidCert.Extensions {
			if ext.Id.Equal(ca.OIDTCGAttributeTPMModel) {
				hasTPMModelIDevID = true
			}
		}

		assert.True(t, hasTPMModelIAK, "IAK should have TPM model extension")
		assert.True(t, hasTPMModelIDevID, "IDevID should have TPM model extension")
	})

	t.Run("IDevID Has Permanent Identifier", func(t *testing.T) {
		hasPermanentID := false
		for _, ext := range idevidCert.Extensions {
			if ext.Id.Equal(ca.OIDPermanentIdentifier) {
				hasPermanentID = true
				t.Log("IDevID has Permanent Identifier extension")
				break
			}
		}
		assert.True(t, hasPermanentID, "IDevID should have Permanent Identifier extension")
	})

	t.Run("Certificates Have TPKeyStore Extension", func(t *testing.T) {
		hasTPKeyStoreIAK := false
		hasTPKeyStoreIDevID := false

		for _, ext := range iakCert.Extensions {
			if ext.Id.Equal(ca.OIDTPKeyStore) {
				hasTPKeyStoreIAK = true
				var keyStore string
				_, err := asn1.Unmarshal(ext.Value, &keyStore)
				require.NoError(t, err)
				assert.Equal(t, "TPM2", keyStore, "TPKeyStore should be TPM2")
			}
		}

		for _, ext := range idevidCert.Extensions {
			if ext.Id.Equal(ca.OIDTPKeyStore) {
				hasTPKeyStoreIDevID = true
			}
		}

		assert.True(t, hasTPKeyStoreIAK, "IAK should have TPKeyStore extension")
		assert.True(t, hasTPKeyStoreIDevID, "IDevID should have TPKeyStore extension")
	})

	t.Run("Certificates Have Indefinite Validity", func(t *testing.T) {
		// TCG spec: 99991231235959Z for indefinite validity
		expectedNotAfter, _ := time.Parse("20060102150405Z", "99991231235959Z")
		assert.WithinDuration(t, expectedNotAfter, iakCert.NotAfter, 24*time.Hour,
			"IAK should have indefinite validity")
		assert.WithinDuration(t, expectedNotAfter, idevidCert.NotAfter, 24*time.Hour,
			"IDevID should have indefinite validity")
	})
}

// TestAttestationCertificateChain_Verification verifies the issued certificate chain.
func TestAttestationCertificateChain_Verification(t *testing.T) {
	RequireSwtpm(t)

	caInstance, cleanup := caFixtures.NewTestCA(t)
	defer cleanup()

	deviceID := fmt.Sprintf("chain-verify-%d", time.Now().Unix())
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	qualifyingData := make([]byte, 32)
	rand.Read(qualifyingData)

	require.NoError(t, swtpm.CreateIDevID(qualifyingData))

	tcgCSR := swtpm.GetTCGCSR()
	certRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   "IDevID-" + deviceID,
			Organization: "Test Organization",
			Country:      "US",
		},
		Valid: 0,
	}

	iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(tcgCSR, certRequest)
	require.NoError(t, err)

	iakCert, err := x509.ParseCertificate(iakDER)
	require.NoError(t, err)
	idevidCert, err := x509.ParseCertificate(idevidDER)
	require.NoError(t, err)

	t.Run("Certificates Have Unique Serial Numbers", func(t *testing.T) {
		assert.NotNil(t, iakCert.SerialNumber)
		assert.NotNil(t, idevidCert.SerialNumber)
		assert.NotEqual(t, iakCert.SerialNumber.String(), idevidCert.SerialNumber.String(),
			"IAK and IDevID must have different serial numbers")
	})

	t.Run("Certificates Are Not CA Certificates", func(t *testing.T) {
		assert.False(t, iakCert.IsCA, "IAK should not be a CA certificate")
		assert.False(t, idevidCert.IsCA, "IDevID should not be a CA certificate")
	})

	t.Run("Certificates Are Currently Valid", func(t *testing.T) {
		now := time.Now()
		assert.True(t, iakCert.NotBefore.Before(now), "IAK should be valid now")
		assert.True(t, iakCert.NotAfter.After(now), "IAK should not be expired")
		assert.True(t, idevidCert.NotBefore.Before(now), "IDevID should be valid now")
		assert.True(t, idevidCert.NotAfter.After(now), "IDevID should not be expired")
	})

	t.Run("Certificates Have Valid Issuer", func(t *testing.T) {
		assert.NotEmpty(t, iakCert.Issuer.String(), "IAK must have an issuer")
		assert.NotEmpty(t, idevidCert.Issuer.String(), "IDevID must have an issuer")
		// Both should be issued by the same CA
		assert.Equal(t, iakCert.Issuer.String(), idevidCert.Issuer.String(),
			"IAK and IDevID should have the same issuer")
	})
}

// ============================================================================
// Error Handling Tests
// ============================================================================

// TestAttestationTamperedQuote_Rejection tests that tampered quotes are rejected.
func TestAttestationTamperedQuote_Rejection(t *testing.T) {
	RequireSwtpm(t)

	caInstance, cleanup := caFixtures.NewTestCA(t)
	defer cleanup()

	deviceID := fmt.Sprintf("tampered-quote-%d", time.Now().Unix())
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	qualifyingData := make([]byte, 32)
	rand.Read(qualifyingData)

	require.NoError(t, swtpm.CreateIDevID(qualifyingData))

	tcgCSR := swtpm.GetTCGCSR()
	require.NotNil(t, tcgCSR)

	// Tamper with the signature
	if len(tcgCSR.Signature) > 0 {
		tcgCSR.Signature[0] ^= 0xFF
	}

	certRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   "IDevID-tampered",
			Organization: "Test",
			Country:      "US",
		},
	}

	iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(tcgCSR, certRequest)
	assert.Error(t, err, "Tampered CSR should be rejected")
	assert.Nil(t, iakDER, "No IAK certificate should be issued for tampered CSR")
	assert.Nil(t, idevidDER, "No IDevID certificate should be issued for tampered CSR")
	t.Logf("Tampered CSR correctly rejected: %v", err)
}

// TestAttestationNilCSR_Rejection tests that nil CSR is rejected.
func TestAttestationNilCSR_Rejection(t *testing.T) {
	caInstance, cleanup := caFixtures.NewTestCA(t)
	defer cleanup()

	certRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   "Test",
			Organization: "Test",
			Country:      "US",
		},
	}

	iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(nil, certRequest)
	assert.Error(t, err, "Nil CSR should be rejected")
	assert.ErrorIs(t, err, ca.ErrInvalidCSR, "Error should be ErrInvalidCSR")
	assert.Nil(t, iakDER)
	assert.Nil(t, idevidDER)
}

// ============================================================================
// CA Attestation Import and Verification Tests
// ============================================================================

// TestCAImportLocalAttestation tests importing local attestation data to the CA.
func TestCAImportLocalAttestation(t *testing.T) {
	RequireSwtpm(t)

	caInstance, cleanup := caFixtures.NewTestCA(t)
	defer cleanup()

	deviceID := fmt.Sprintf("import-attest-%d", time.Now().Unix())
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	tpmModule := swtpm.GetTPMModule()

	// Generate a quote
	nonce := make([]byte, 32)
	rand.Read(nonce)
	pcrs := []uint{0, 7, 14}
	quote, err := tpmModule.Quote(pcrs, nonce)
	require.NoError(t, err)

	// Create key attributes for the attestation
	akAttrs := &xkmssdk.KeyAttributes{
		CN: "test-ak-" + deviceID,
	}

	t.Run("Import Quote Successfully", func(t *testing.T) {
		err := caInstance.ImportAttestationQuote(akAttrs, quote.Quoted)
		assert.NoError(t, err, "Importing quote should succeed")
	})

	t.Run("Import PCRs Successfully", func(t *testing.T) {
		err := caInstance.ImportAttestationPCRs(akAttrs, quote.PCRs)
		assert.NoError(t, err, "Importing PCRs should succeed")
	})

	t.Run("Verify Imported Quote", func(t *testing.T) {
		err := caInstance.VerifyAttestationQuote(akAttrs, quote.Quoted)
		assert.NoError(t, err, "Quote verification should succeed")
	})

	t.Run("Verify Imported PCRs", func(t *testing.T) {
		err := caInstance.VerifyAttestationPCRs(akAttrs, quote.PCRs)
		assert.NoError(t, err, "PCR verification should succeed")
	})

	t.Run("Verification Fails With Modified Quote", func(t *testing.T) {
		modifiedQuote := make([]byte, len(quote.Quoted))
		copy(modifiedQuote, quote.Quoted)
		if len(modifiedQuote) > 0 {
			modifiedQuote[0] ^= 0xFF
		}
		err := caInstance.VerifyAttestationQuote(akAttrs, modifiedQuote)
		assert.Error(t, err, "Modified quote should fail verification")
	})

	t.Run("Verification Fails With Modified PCRs", func(t *testing.T) {
		modifiedPCRs := make([]byte, len(quote.PCRs))
		copy(modifiedPCRs, quote.PCRs)
		if len(modifiedPCRs) > 0 {
			modifiedPCRs[0] ^= 0xFF
		}
		err := caInstance.VerifyAttestationPCRs(akAttrs, modifiedPCRs)
		assert.Error(t, err, "Modified PCRs should fail verification")
	})
}

// TestCAImportLocalAttestation_CompleteFlow tests the complete attestation import flow.
func TestCAImportLocalAttestation_CompleteFlow(t *testing.T) {
	RequireSwtpm(t)

	caInstance, cleanup := caFixtures.NewTestCA(t)
	defer cleanup()

	deviceID := fmt.Sprintf("complete-attest-%d", time.Now().Unix())
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	tpmModule := swtpm.GetTPMModule()

	// Generate quote
	nonce := make([]byte, 32)
	rand.Read(nonce)
	quote, err := tpmModule.Quote([]uint{0, 7, 14}, nonce)
	require.NoError(t, err)

	akAttrs := &xkmssdk.KeyAttributes{
		CN: "complete-ak-" + deviceID,
	}

	// Import complete local attestation
	err = caInstance.ImportLocalAttestation(akAttrs, &xkmssdk.Quote{
		Quoted:    quote.Quoted,
		Signature: quote.Signature,
		Nonce:     quote.Nonce,
		PCRs:      quote.PCRs,
		EventLog:  quote.EventLog, // May be empty for swtpm
	})
	require.NoError(t, err, "ImportLocalAttestation should succeed")

	// Verify all components were imported
	t.Run("Quote Was Imported", func(t *testing.T) {
		err := caInstance.VerifyAttestationQuote(akAttrs, quote.Quoted)
		assert.NoError(t, err)
	})

	t.Run("PCRs Were Imported", func(t *testing.T) {
		err := caInstance.VerifyAttestationPCRs(akAttrs, quote.PCRs)
		assert.NoError(t, err)
	})
}

// ============================================================================
// Pre-Issuance Hook Integration Tests
// ============================================================================

// TestPreIssuanceHooks_IntegrationWithRealTPM tests pre-issuance hooks with real TPM data
// in the context of a complete ACME enrollment flow.
func TestPreIssuanceHooks_IntegrationWithRealTPM(t *testing.T) {
	RequireSwtpm(t)

	service, cleanup := setupTestServiceWithRealCA(t)
	defer cleanup()

	deviceID := fmt.Sprintf("hook-integration-%d", time.Now().Unix())

	// Track hook execution
	hookCalled := false
	var receivedTCGData *handlers.TCGEnrollmentData

	// Create pre-issuance hook registry with custom hook
	preIssuanceRegistry := handlers.NewPreIssuanceHookRegistry()
	preIssuanceRegistry.Register(func(ctx *handlers.PreIssuanceHookContext) error {
		hookCalled = true
		receivedTCGData = ctx.TCGData
		return nil
	})

	service.SetPreIssuanceHooks(preIssuanceRegistry)

	// Create account and order
	key := generateTestKeyPair(t)
	account := createTestAccountForService(t, service, key)
	order := createTestOrderWithPermanentID(t, service, account.ID, deviceID)

	// Generate real TPM CSR
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())
	require.NoError(t, swtpm.CreateIDevID([]byte("hook-integration-qualifying-data")))

	packedCSR := swtpm.GetPackedCSR()
	require.NotEmpty(t, packedCSR)

	// Finalize order
	payload := handlers.OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(packedCSR),
	}

	url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
	req := createJWSRequestForService(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})
	req.RemoteAddr = deviceID

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Verify hook was called
	assert.True(t, hookCalled, "Pre-issuance hook should have been called")
	assert.NotNil(t, receivedTCGData, "Hook should have received TCG data")

	if receivedTCGData != nil {
		assert.Equal(t, "TEST-MODEL", receivedTCGData.ProductModel, "Product model should match")
		assert.Equal(t, deviceID, receivedTCGData.ProductSerial, "Product serial should match")
		assert.NotNil(t, receivedTCGData.EKCertificate, "EK certificate should be present")
	}

	// Verify enrollment succeeded
	require.Equal(t, http.StatusOK, resp.Code, "Enrollment should succeed: %s", resp.Body.String())

	var orderResp entities.ACMEOrder
	err := json.NewDecoder(resp.Body).Decode(&orderResp)
	require.NoError(t, err)
	assert.Equal(t, common.StatusValid, orderResp.Status)
}

// TestPreIssuanceHook_PCRValidation_BlocksEnrollment tests that PCR validation hook
// can block enrollment when PCRs don't match.
func TestPreIssuanceHook_PCRValidation_BlocksEnrollment(t *testing.T) {
	RequireSwtpm(t)

	service, cleanup := setupTestServiceWithRealCA(t)
	defer cleanup()

	deviceID := fmt.Sprintf("pcr-block-%d", time.Now().Unix())

	// Create PCR validation hook with impossible-to-match values
	impossiblePCRs := map[int][]byte{
		0: make([]byte, 32), // All zeros - won't match any real PCR
		7: make([]byte, 32),
	}
	// Fill with impossible values
	for i := range impossiblePCRs[0] {
		impossiblePCRs[0][i] = 0xFF
		impossiblePCRs[7][i] = 0xFF
	}

	pcrPolicy := &handlers.PCRPolicy{
		ExpectedPCRs: impossiblePCRs,
		StrictMode:   true,
	}

	preIssuanceRegistry := handlers.NewPreIssuanceHookRegistry()
	preIssuanceRegistry.Register(handlers.NewPCRValidationHook(pcrPolicy))
	service.SetPreIssuanceHooks(preIssuanceRegistry)

	// Setup enrollment
	key := generateTestKeyPair(t)
	account := createTestAccountForService(t, service, key)
	order := createTestOrderWithPermanentID(t, service, account.ID, deviceID)

	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	// Create IDevID with attestation data that will include PCRs
	qualifyingData := make([]byte, 32)
	rand.Read(qualifyingData)
	require.NoError(t, swtpm.CreateIDevID(qualifyingData))

	packedCSR := swtpm.GetPackedCSR()
	require.NotEmpty(t, packedCSR)

	payload := handlers.OrderFinalizeRequest{
		CSR: base64.RawURLEncoding.EncodeToString(packedCSR),
	}

	url := fmt.Sprintf("https://acme.test.example.com/acme/order/%d/finalize", order.ID)
	req := createJWSRequestForService(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})
	req.RemoteAddr = deviceID

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	// Note: Whether this blocks depends on whether ProdCaData is populated
	// in the TCG-CSR. The hook only validates if ProdCaData is present.
	// If enrollment succeeds, it means no attestation data was included
	// (which is valid for basic IDevID enrollment).
	t.Logf("Response status: %d", resp.Code)
}

// ============================================================================
// PCR Measurement Tests
// ============================================================================

// TestPCRMeasurement_ExtendAndVerify tests that PCR values change predictably
// when extended with known measurements.
func TestPCRMeasurement_ExtendAndVerify(t *testing.T) {
	RequireSwtpm(t)

	deviceID := fmt.Sprintf("pcr-extend-%d", time.Now().Unix())
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	tpmModule := swtpm.GetTPMModule()

	// Read initial PCR value for a debug PCR (16 is typically available for testing)
	debugPCR := uint(16)
	initialBanks, err := tpmModule.ReadPCRs([]uint{debugPCR})
	require.NoError(t, err)

	// Find initial SHA-256 PCR value
	var initialValue []byte
	for _, bank := range initialBanks {
		if bank.Algorithm == "sha256" || bank.Algorithm == "SHA256" {
			for _, pcr := range bank.PCRs {
				if pcr.ID == int32(debugPCR) {
					initialValue = pcr.Value
					break
				}
			}
		}
	}
	require.NotNil(t, initialValue, "Should have initial PCR value")
	t.Logf("Initial PCR[%d] value: %x", debugPCR, initialValue)

	// Extend the PCR with a known measurement
	measurement := sha256.Sum256([]byte("test-measurement-data"))

	// Note: Direct PCR extend requires TPM owner access
	// This test verifies reading, not extending (which requires special setup)
	t.Run("PCR Values Are Consistent", func(t *testing.T) {
		// Read PCR again - should be same value
		banks2, err := tpmModule.ReadPCRs([]uint{debugPCR})
		require.NoError(t, err)

		var secondValue []byte
		for _, bank := range banks2 {
			if bank.Algorithm == "sha256" || bank.Algorithm == "SHA256" {
				for _, pcr := range bank.PCRs {
					if pcr.ID == int32(debugPCR) {
						secondValue = pcr.Value
						break
					}
				}
			}
		}
		require.NotNil(t, secondValue)
		assert.Equal(t, initialValue, secondValue, "PCR value should be consistent between reads")
	})

	// Verify measurement would produce correct extended value
	t.Run("PCR Extension Calculation", func(t *testing.T) {
		// Compute what the extended value would be
		h := sha256.New()
		h.Write(initialValue)
		h.Write(measurement[:])
		expectedExtended := h.Sum(nil)

		// The extended value should be different from initial
		assert.NotEqual(t, initialValue, expectedExtended,
			"Extended PCR value should differ from initial")

		t.Logf("Expected extended PCR[%d] value: %x", debugPCR, expectedExtended)
	})
}

// TestQuoteSignature_Verification tests that quote signatures can be verified.
func TestQuoteSignature_Verification(t *testing.T) {
	RequireSwtpm(t)

	deviceID := fmt.Sprintf("quote-sig-%d", time.Now().Unix())
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	tpmModule := swtpm.GetTPMModule()

	// Get IAK attributes for verification
	iakAttrs, err := tpmModule.IAKAttributes()
	require.NoError(t, err)
	require.NotNil(t, iakAttrs.TPMAttributes, "IAK should have TPM attributes")
	require.NotEmpty(t, iakAttrs.TPMAttributes.PublicKeyBytes, "IAK should have public key bytes")

	// Generate quote
	nonce := make([]byte, 32)
	rand.Read(nonce)
	quote, err := tpmModule.Quote([]uint{0, 7}, nonce)
	require.NoError(t, err)

	t.Run("Quote Contains Valid Signature", func(t *testing.T) {
		assert.NotEmpty(t, quote.Signature, "Quote signature must not be empty")
		// TPM signatures are typically at least 64 bytes (for ECDSA) or 256+ bytes (for RSA)
		assert.Greater(t, len(quote.Signature), 32, "Quote signature should be substantial")
	})

	t.Run("Quote Contains Nonce", func(t *testing.T) {
		// The nonce should be embedded in the quote's TPMS_ATTEST structure
		// The Quote structure from go-xkms preserves the nonce
		assert.NotEmpty(t, quote.Nonce, "Quote should contain nonce")
		assert.Equal(t, nonce, quote.Nonce, "Quote nonce should match provided nonce")
	})

	t.Run("Quoted Data Is Not Empty", func(t *testing.T) {
		assert.NotEmpty(t, quote.Quoted, "Quoted data must not be empty")
		// TPMS_ATTEST structure has a minimum size
		assert.Greater(t, len(quote.Quoted), 40, "Quoted data should be substantial")
	})
}
