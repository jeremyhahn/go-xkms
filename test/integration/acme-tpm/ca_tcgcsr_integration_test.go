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

//go:build integration && tpm2

package tpm_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OID for Certificate Policies extension (2.5.29.32)
var oidCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}

// hasPolicyIdentifier checks if a certificate has a specific policy identifier
// by examining the Certificate Policies extension directly.
func hasPolicyIdentifier(cert *x509.Certificate, policyOID asn1.ObjectIdentifier) bool {
	// Check the newer Policies field (Go 1.22+)
	for _, oid := range cert.Policies {
		if oid.EqualASN1OID(policyOID) {
			return true
		}
	}

	// Check the legacy PolicyIdentifiers field
	for _, oid := range cert.PolicyIdentifiers {
		if oid.Equal(policyOID) {
			return true
		}
	}

	// Fall back to manually parsing the Certificate Policies extension
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidCertificatePolicies) {
			var policyInfos []struct {
				PolicyIdentifier asn1.ObjectIdentifier
				PolicyQualifiers asn1.RawValue `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &policyInfos); err == nil {
				for _, pi := range policyInfos {
					if pi.PolicyIdentifier.Equal(policyOID) {
						return true
					}
				}
			}
		}
	}

	return false
}

// TestSignTCGCSRIDevID_ValidRSAEnrollment tests successful IDevID enrollment with RSA keys.
func TestSignTCGCSRIDevID_ValidRSAEnrollment(t *testing.T) {
	RequireSwtpm(t)

	ctx := context.Background()
	caInstance, caCleanup := newTestCA(t)
	defer caCleanup()

	deviceID := "test-device-rsa-001"
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM(), "Failed to initialize TPM")
	require.NoError(t, swtpm.Provision(), "Failed to provision TPM")

	qualifyingData := make([]byte, 32)
	_, err := rand.Read(qualifyingData)
	require.NoError(t, err, "Failed to generate qualifying data")

	require.NoError(t, swtpm.CreateIDevID(qualifyingData), "Failed to create IDevID")

	tcgCSR := swtpm.GetTCGCSR()
	require.NotNil(t, tcgCSR, "TCG-CSR should not be nil")

	certRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   "IDevID-" + deviceID,
			Organization: "Test Organization",
			Country:      "US",
		},
		Valid:       0,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(ctx, tcgCSR, certRequest)
	require.NoError(t, err, "SignTCGCSRIDevID should succeed")
	require.NotNil(t, iakDER, "IAK certificate should not be nil")
	require.NotNil(t, idevidDER, "IDevID certificate should not be nil")

	iakCert, err := x509.ParseCertificate(iakDER)
	require.NoError(t, err, "Failed to parse IAK certificate")

	// pkg/ca/tcg.go's IAKCommonName ("iak-<model>-<serial>") is the IAK's
	// subject regardless of certRequest.Subject.CommonName: unlike the
	// IDevID (which does carry the caller's subject, see below), the IAK's
	// identity is derived from the CSR's own attested ProdModel/ProdSerial
	// so it can never collide with the IDevID cert in the same certificate
	// store (both are keyed by common name).
	assert.Equal(t, ca.IAKCommonName("TEST-MODEL", deviceID), iakCert.Subject.CommonName)
	assert.Equal(t, x509.KeyUsageDigitalSignature, iakCert.KeyUsage&x509.KeyUsageDigitalSignature)
	assert.Contains(t, iakCert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	assert.Contains(t, iakCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

	// tcg-kp-AIKCertificate (2.23.133.8.3) is an Extended Key Usage purpose,
	// so it appears in UnknownExtKeyUsage rather than as a standalone
	// extension -- see WebAuthn L2 §8.3.1.
	hasAIKMarker := false
	for _, oid := range iakCert.UnknownExtKeyUsage {
		if oid.Equal(ca.OIDTCGKpAIKCertificate) {
			hasAIKMarker = true
			break
		}
	}
	assert.True(t, hasAIKMarker, "IAK certificate should have TCG AIK Certificate extended key usage")

	assert.True(t, hasPolicyIdentifier(iakCert, ca.OIDTCGVerifiedTPMResidency), "IAK should have VerifiedTPMResidency policy")
	// pkg/ca/profiles.go's NewTCGInitialAttestationKeyProfile stamps
	// tcgAttestationPolicies() on the IAK: Residency + Restricted, never
	// Fixed -- Fixed is reserved for the IDevID identity key
	// (tcgIdentityPolicies, see NewTCGDeviceIdentityProfile). Per the TCG
	// spec citation on tcgAttestationPolicies: "MUST NOT be combined with
	// TCG-CE-FixedTPM[-RestrictedKey]" -- Restricted already states the CA
	// verified both the fixedTPM and Restricted bits, so asserting Fixed too
	// on the IAK would assert a combination the spec forbids.
	assert.True(t, hasPolicyIdentifier(iakCert, ca.OIDTCGVerifiedTPMRestricted), "IAK should have VerifiedTPMRestricted policy")

	idevidCert, err := x509.ParseCertificate(idevidDER)
	require.NoError(t, err, "Failed to parse IDevID certificate")

	assert.Equal(t, certRequest.Subject.CommonName, idevidCert.Subject.CommonName)
	// pkg/ca/profiles.go's NewTCGDeviceIdentityProfile: "digitalSignature
	// (only) is RECOMMENDED" (TCG DevID v1 r12 Table 22) for a non-Combined
	// IDevID key -- this swtpm fixture's key has no TPM Decrypt attribute,
	// so the CA never adds keyEncipherment (asserting it "would advertise a
	// capability the key does not have"). certRequest.KeyUsage above
	// requests both bits, but IDevID key usage is derived from the key's
	// own TPM attributes, not honored verbatim from the request.
	assert.Equal(t, x509.KeyUsageDigitalSignature, idevidCert.KeyUsage&x509.KeyUsageDigitalSignature)
	assert.Contains(t, idevidCert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	assert.Contains(t, idevidCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

	assert.True(t, hasPolicyIdentifier(idevidCert, ca.OIDTCGVerifiedTPMResidency), "IDevID should have VerifiedTPMResidency policy")
	assert.True(t, hasPolicyIdentifier(idevidCert, ca.OIDTCGVerifiedTPMFixed), "IDevID should have VerifiedTPMFixed policy")

	expectedNotAfter, _ := time.Parse("20060102150405Z", "99991231235959Z")
	assert.WithinDuration(t, expectedNotAfter, iakCert.NotAfter, 24*time.Hour)
	assert.WithinDuration(t, expectedNotAfter, idevidCert.NotAfter, 24*time.Hour)

	_, iakIsRSA := iakCert.PublicKey.(*rsa.PublicKey)
	_, idevidIsRSA := idevidCert.PublicKey.(*rsa.PublicKey)
	assert.True(t, iakIsRSA, "IAK public key should be RSA")
	assert.True(t, idevidIsRSA, "IDevID public key should be RSA")

	t.Logf("Successfully signed TCG-CSR-IDEVID with RSA keys")
	t.Logf("IAK Serial: %s", iakCert.SerialNumber.String())
	t.Logf("IDevID Serial: %s", idevidCert.SerialNumber.String())
}

// TestSignTCGCSRIDevID_ValidECDSAEnrollment tests successful IDevID enrollment with ECDSA keys.
// This test requires swtpm support for ECDSA EK provisioning.
func TestSignTCGCSRIDevID_ValidECDSAEnrollment(t *testing.T) {
	RequireSwtpm(t)

	ctx := context.Background()
	caInstance, caCleanup := newTestCA(t)
	defer caCleanup()

	deviceID := "test-device-ecdsa-001"
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPMWithECDSA(), "Failed to initialize TPM with ECDSA")
	require.NoError(t, swtpm.Provision(), "Failed to provision TPM")

	qualifyingData := make([]byte, 32)
	_, err := rand.Read(qualifyingData)
	require.NoError(t, err, "Failed to generate qualifying data")

	require.NoError(t, swtpm.CreateIDevID(qualifyingData), "Failed to create IDevID")

	tcgCSR := swtpm.GetTCGCSR()
	require.NotNil(t, tcgCSR, "TCG-CSR should not be nil")

	certRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   "IDevID-" + deviceID,
			Organization: "Test Organization",
			Country:      "US",
		},
		Valid:       0,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(ctx, tcgCSR, certRequest)
	require.NoError(t, err, "SignTCGCSRIDevID should succeed with ECDSA")
	require.NotNil(t, iakDER, "IAK certificate should not be nil")
	require.NotNil(t, idevidDER, "IDevID certificate should not be nil")

	iakCert, err := x509.ParseCertificate(iakDER)
	require.NoError(t, err, "Failed to parse IAK certificate")

	idevidCert, err := x509.ParseCertificate(idevidDER)
	require.NoError(t, err, "Failed to parse IDevID certificate")

	_, iakIsECDSA := iakCert.PublicKey.(*ecdsa.PublicKey)
	_, idevidIsECDSA := idevidCert.PublicKey.(*ecdsa.PublicKey)

	assert.True(t, iakIsECDSA, "IAK public key should be ECDSA")
	assert.True(t, idevidIsECDSA, "IDevID public key should be ECDSA")

	t.Logf("Successfully signed TCG-CSR-IDEVID with ECDSA keys")
}

// TestSignTCGCSRIDevID_TPMExtensions verifies TPM-specific extensions in issued certificates.
func TestSignTCGCSRIDevID_TPMExtensions(t *testing.T) {
	RequireSwtpm(t)

	ctx := context.Background()
	caInstance, caCleanup := newTestCA(t)
	defer caCleanup()

	deviceID := "test-device-extensions-001"
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

	iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(ctx, tcgCSR, certRequest)
	require.NoError(t, err)

	iakCert, err := x509.ParseCertificate(iakDER)
	require.NoError(t, err)

	idevidCert, err := x509.ParseCertificate(idevidDER)
	require.NoError(t, err)

	t.Run("IAK TPM Extensions", func(t *testing.T) {
		hasTPMModel := false
		hasTPMVersion := false
		hasTPKeyStore := false

		// tcg-kp-AIKCertificate (2.23.133.8.3) is an Extended Key Usage
		// purpose (WebAuthn L2 §8.3.1), so it is read from UnknownExtKeyUsage
		// rather than the loop over standalone Extensions below.
		hasAIKMarker := false
		for _, oid := range iakCert.UnknownExtKeyUsage {
			if oid.Equal(ca.OIDTCGKpAIKCertificate) {
				hasAIKMarker = true
				break
			}
		}

		// pkg/ca/tcg.go writes the CSR's ProdModel field under
		// tcg-at-platformModel (2.23.133.2.5), never tcg-at-tpmModel
		// (2.23.133.2.2) -- see the identical note in
		// attestation_integration_test.go's "Certificates Have TPM Model
		// Extension" subtest.
		for _, ext := range iakCert.Extensions {
			switch {
			case ext.Id.Equal(ca.OIDTCGAttributePlatformModel):
				hasTPMModel = true
				var model string
				_, err := asn1.Unmarshal(ext.Value, &model)
				assert.NoError(t, err, "TPM model should be valid ASN.1")
				t.Logf("TPM Model: %s", model)
			case ext.Id.Equal(ca.OIDTCGAttributeTPMVersion):
				hasTPMVersion = true
				var version string
				_, err := asn1.Unmarshal(ext.Value, &version)
				assert.NoError(t, err, "TPM version should be valid ASN.1")
				t.Logf("TPM Version: %s", version)
			case ext.Id.Equal(ca.OIDTPKeyStore):
				hasTPKeyStore = true
				var keyStore string
				_, err := asn1.Unmarshal(ext.Value, &keyStore)
				assert.NoError(t, err, "TPM keystore should be valid ASN.1")
				assert.Equal(t, "TPM2", keyStore)
			}
		}

		assert.True(t, hasAIKMarker, "IAK should have AIK Certificate extended key usage")
		assert.True(t, hasTPMModel, "IAK should have TPM model extension")
		assert.True(t, hasTPMVersion, "IAK should have TPM version extension")
		assert.True(t, hasTPKeyStore, "IAK should have TPKeyStore extension")

		assert.True(t, hasPolicyIdentifier(iakCert, ca.OIDTCGVerifiedTPMResidency), "IAK should have VerifiedTPMResidency policy")
		// pkg/ca/profiles.go's NewTCGInitialAttestationKeyProfile stamps
		// tcgAttestationPolicies() on the IAK: Residency + Restricted, never
		// Fixed -- Fixed is reserved for the IDevID identity key
		// (tcgIdentityPolicies, see NewTCGDeviceIdentityProfile). Per the TCG
		// spec citation on tcgAttestationPolicies: "MUST NOT be combined with
		// TCG-CE-FixedTPM[-RestrictedKey]" -- Restricted already states the CA
		// verified both the fixedTPM and Restricted bits, so asserting Fixed too
		// on the IAK would assert a combination the spec forbids.
		assert.True(t, hasPolicyIdentifier(iakCert, ca.OIDTCGVerifiedTPMRestricted), "IAK should have VerifiedTPMRestricted policy")
	})

	t.Run("IDevID TPM Extensions", func(t *testing.T) {
		hasTPMModel := false
		hasTPMVersion := false
		hasPermanentID := false
		hasTPKeyStore := false

		for _, ext := range idevidCert.Extensions {
			switch {
			case ext.Id.Equal(ca.OIDTCGAttributePlatformModel):
				hasTPMModel = true
			case ext.Id.Equal(ca.OIDTCGAttributeTPMVersion):
				hasTPMVersion = true
			case ext.Id.Equal(ca.OIDPermanentIdentifier):
				hasPermanentID = true
				t.Logf("IDevID has Permanent Identifier extension")
			case ext.Id.Equal(ca.OIDTPKeyStore):
				hasTPKeyStore = true
			}
		}

		assert.True(t, hasTPMModel, "IDevID should have TPM model extension")
		assert.True(t, hasTPMVersion, "IDevID should have TPM version extension")
		assert.True(t, hasPermanentID, "IDevID should have Permanent Identifier extension")
		assert.True(t, hasTPKeyStore, "IDevID should have TPKeyStore extension")

		assert.True(t, hasPolicyIdentifier(idevidCert, ca.OIDTCGVerifiedTPMResidency), "IDevID should have VerifiedTPMResidency policy")
		assert.True(t, hasPolicyIdentifier(idevidCert, ca.OIDTCGVerifiedTPMFixed), "IDevID should have VerifiedTPMFixed policy")
	})
}

// TestSignTCGCSRIDevID_InvalidCSR tests error handling for invalid CSR inputs.
func TestSignTCGCSRIDevID_InvalidCSR(t *testing.T) {
	ctx := context.Background()
	caInstance, caCleanup := newTestCA(t)
	defer caCleanup()

	certRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   "Test",
			Organization: "Test",
			Country:      "US",
		},
	}

	t.Run("Nil CSR", func(t *testing.T) {
		iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(ctx, nil, certRequest)
		assert.Error(t, err, "Should reject nil CSR")
		assert.ErrorIs(t, err, ca.ErrInvalidCSR)
		assert.Nil(t, iakDER)
		assert.Nil(t, idevidDER)
	})

	t.Run("Empty CSR", func(t *testing.T) {
		emptyCSR := &xkmssdk.TCG_CSR_IDEVID{}
		iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(ctx, emptyCSR, certRequest)
		assert.Error(t, err, "Should reject empty CSR")
		assert.Nil(t, iakDER)
		assert.Nil(t, idevidDER)
	})
}

// TestSignTCGCSRIDevID_InvalidSignature tests rejection of CSRs with invalid signatures.
func TestSignTCGCSRIDevID_InvalidSignature(t *testing.T) {
	RequireSwtpm(t)

	ctx := context.Background()
	caInstance, caCleanup := newTestCA(t)
	defer caCleanup()

	deviceID := "test-device-invalid-sig-001"
	swtpm := NewSwtpmConnection(t, deviceID)
	defer swtpm.Close()

	require.NoError(t, swtpm.InitializeTPM())
	require.NoError(t, swtpm.Provision())

	qualifyingData := make([]byte, 32)
	rand.Read(qualifyingData)

	require.NoError(t, swtpm.CreateIDevID(qualifyingData))

	tcgCSR := swtpm.GetTCGCSR()
	require.NotNil(t, tcgCSR)

	if len(tcgCSR.Signature) > 0 {
		tcgCSR.Signature[0] ^= 0xFF
	}

	certRequest := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName:   "IDevID-invalid",
			Organization: "Test",
			Country:      "US",
		},
	}

	iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(ctx, tcgCSR, certRequest)
	assert.Error(t, err, "Should reject CSR with invalid signature")
	assert.Contains(t, err.Error(), "verification failed", "Error should mention verification failure")
	assert.Nil(t, iakDER)
	assert.Nil(t, idevidDER)

	t.Logf("Correctly rejected CSR with corrupted signature: %v", err)
}

// TestSignTCGCSRIDevID_MissingTPMData tests handling of malformed TCG CSR data.
func TestSignTCGCSRIDevID_MissingTPMData(t *testing.T) {
	RequireSwtpm(t)

	ctx := context.Background()
	caInstance, caCleanup := newTestCA(t)
	defer caCleanup()

	deviceID := "test-device-missing-data-001"
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
			CommonName:   "IDevID-missing-data",
			Organization: "Test",
			Country:      "US",
		},
	}

	t.Run("Missing CsrContents", func(t *testing.T) {
		invalidCSR := &xkmssdk.TCG_CSR_IDEVID{
			StructVer: tcgCSR.StructVer,
			Contents:  tcgCSR.Contents,
			SigSz:     tcgCSR.SigSz,
			Signature: tcgCSR.Signature,
		}

		iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(ctx, invalidCSR, certRequest)
		assert.Error(t, err, "Should reject CSR without proper CSR contents")
		assert.Nil(t, iakDER)
		assert.Nil(t, idevidDER)
	})
}

// TestSignTCGCSRIDevID_CertificateChainVerification verifies the issued certificates chain properly.
func TestSignTCGCSRIDevID_CertificateChainVerification(t *testing.T) {
	RequireSwtpm(t)

	ctx := context.Background()
	caInstance, caCleanup := newTestCA(t)
	defer caCleanup()

	deviceID := "test-device-chain-001"
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

	iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(ctx, tcgCSR, certRequest)
	require.NoError(t, err)

	iakCert, err := x509.ParseCertificate(iakDER)
	require.NoError(t, err)

	idevidCert, err := x509.ParseCertificate(idevidDER)
	require.NoError(t, err)

	t.Run("Certificate Attributes", func(t *testing.T) {
		assert.NotEmpty(t, iakCert.Subject.String())
		assert.NotEmpty(t, iakCert.Issuer.String())
		assert.NotEmpty(t, idevidCert.Subject.String())
		assert.NotEmpty(t, idevidCert.Issuer.String())

		assert.False(t, iakCert.IsCA)
		assert.False(t, idevidCert.IsCA)

		assert.NotNil(t, iakCert.SerialNumber)
		assert.NotNil(t, idevidCert.SerialNumber)
		assert.True(t, iakCert.SerialNumber.Cmp(idevidCert.SerialNumber) != 0,
			"Certificates should have unique serial numbers")
	})

	t.Run("Validity Period", func(t *testing.T) {
		now := time.Now()
		assert.True(t, iakCert.NotBefore.Before(now), "IAK should be valid now")
		assert.True(t, iakCert.NotAfter.After(now), "IAK should be valid in the future")
		assert.True(t, idevidCert.NotBefore.Before(now), "IDevID should be valid now")
		assert.True(t, idevidCert.NotAfter.After(now), "IDevID should be valid in the future")
	})
}

// TestSignTCGCSRIDevID_MultipleDevices tests enrolling multiple devices sequentially.
func TestSignTCGCSRIDevID_MultipleDevices(t *testing.T) {
	RequireSwtpm(t)

	ctx := context.Background()
	caInstance, caCleanup := newTestCA(t)
	defer caCleanup()

	deviceCount := 3
	certificates := make(map[string]struct {
		iakCert    *x509.Certificate
		idevidCert *x509.Certificate
	})

	for i := 0; i < deviceCount; i++ {
		deviceID := fmt.Sprintf("test-device-multi-%03d", i)

		swtpm := NewSwtpmConnection(t, deviceID)
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

		iakDER, idevidDER, err := caInstance.SignTCGCSRIDevID(ctx, tcgCSR, certRequest)
		require.NoError(t, err, "Failed to sign CSR for device %s", deviceID)

		iakCert, err := x509.ParseCertificate(iakDER)
		require.NoError(t, err)

		idevidCert, err := x509.ParseCertificate(idevidDER)
		require.NoError(t, err)

		certificates[deviceID] = struct {
			iakCert    *x509.Certificate
			idevidCert *x509.Certificate
		}{iakCert: iakCert, idevidCert: idevidCert}

		swtpm.Close()

		t.Logf("Device %s enrolled successfully", deviceID)
	}

	serialNumbers := make(map[string]bool)
	for deviceID, certs := range certificates {
		iakSerial := certs.iakCert.SerialNumber.String()
		idevidSerial := certs.idevidCert.SerialNumber.String()

		assert.False(t, serialNumbers[iakSerial],
			"IAK serial number should be unique for %s", deviceID)
		assert.False(t, serialNumbers[idevidSerial],
			"IDevID serial number should be unique for %s", deviceID)

		serialNumbers[iakSerial] = true
		serialNumbers[idevidSerial] = true
	}

	t.Logf("Successfully enrolled %d devices with unique certificates", deviceCount)
}
