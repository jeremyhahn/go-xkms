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

package ca

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
)

// =============================================================================
// OID Constant Tests
// =============================================================================

func TestOIDConstants_NonNil(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		oid         asn1.ObjectIdentifier
		expectedLen int
	}{
		// TCG Base
		{name: "OIDTCGBase", oid: OIDTCGBase, expectedLen: 3},

		// TCG Attribute Types (2.23.133.2.X)
		{name: "OIDTCGAttributeTPMManufacturer", oid: OIDTCGAttributeTPMManufacturer, expectedLen: 5},
		{name: "OIDTCGAttributeTPMModel", oid: OIDTCGAttributeTPMModel, expectedLen: 5},
		{name: "OIDTCGAttributeTPMVersion", oid: OIDTCGAttributeTPMVersion, expectedLen: 5},
		{name: "OIDTCGAttributePlatformManufacturer", oid: OIDTCGAttributePlatformManufacturer, expectedLen: 5},
		{name: "OIDTCGAttributePlatformModel", oid: OIDTCGAttributePlatformModel, expectedLen: 5},
		{name: "OIDTCGAttributePlatformVersion", oid: OIDTCGAttributePlatformVersion, expectedLen: 5},
		{name: "OIDTCGAttributeTPMIdLabel", oid: OIDTCGAttributeTPMIdLabel, expectedLen: 5},
		{name: "OIDTCGAttributeTPMSpecification", oid: OIDTCGAttributeTPMSpecification, expectedLen: 5},
		{name: "OIDTCGPlatformSpecification", oid: OIDTCGPlatformSpecification, expectedLen: 5},
		{name: "OIDTCGCredentialType", oid: OIDTCGCredentialType, expectedLen: 5},
		{name: "OIDTCGCredentialSpecification", oid: OIDTCGCredentialSpecification, expectedLen: 5},

		// TCG Certificate Types (2.23.133.8.X)
		{name: "OIDTCGKpEKCertificate", oid: OIDTCGKpEKCertificate, expectedLen: 5},
		{name: "OIDTCGKpPlatformCertificate", oid: OIDTCGKpPlatformCertificate, expectedLen: 5},
		{name: "OIDTCGKpAIKCertificate", oid: OIDTCGKpAIKCertificate, expectedLen: 5},

		// TCG Verified TPM Attributes (2.23.133.11.1.X)
		{name: "OIDTCGVerifiedTPMResidency", oid: OIDTCGVerifiedTPMResidency, expectedLen: 6},
		{name: "OIDTCGVerifiedTPMFixed", oid: OIDTCGVerifiedTPMFixed, expectedLen: 6},

		// Hardware Module / Permanent Identifier
		{name: "OIDHardwareModuleName", oid: OIDHardwareModuleName, expectedLen: 9},
		{name: "OIDPermanentIdentifier", oid: OIDPermanentIdentifier, expectedLen: 9},

		// Trusted Platform Enterprise OIDs
		{name: "OIDTPIssuerKeyStore", oid: OIDTPIssuerKeyStore, expectedLen: 9},
		{name: "OIDTPKeyStore", oid: OIDTPKeyStore, expectedLen: 9},
		{name: "OIDTPFIPS140", oid: OIDTPFIPS140, expectedLen: 9},

		// Quantum OIDs
		{name: "OIDQuantumAlgorithm", oid: OIDQuantumAlgorithm, expectedLen: 9},
		{name: "OIDQuantumSignature", oid: OIDQuantumSignature, expectedLen: 9},

		// Tenant ID
		{name: "OIDTPTenantID", oid: OIDTPTenantID, expectedLen: 9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.oid == nil {
				t.Fatalf("%s is nil", tt.name)
			}
			if len(tt.oid) != tt.expectedLen {
				t.Errorf("%s: expected length %d, got %d", tt.name, tt.expectedLen, len(tt.oid))
			}
		})
	}
}

func TestOIDConstants_LegacyAliases(t *testing.T) {
	t.Parallel()

	t.Run("OIDTCGSpecification_equals_OIDTCGAttributeTPMSpecification", func(t *testing.T) {
		t.Parallel()
		if !OIDTCGSpecification.Equal(OIDTCGAttributeTPMSpecification) {
			t.Errorf("OIDTCGSpecification should equal OIDTCGAttributeTPMSpecification")
		}
	})

	t.Run("OIDTCGEKCertificate_equals_OIDTCGKpEKCertificate", func(t *testing.T) {
		t.Parallel()
		if !OIDTCGEKCertificate.Equal(OIDTCGKpEKCertificate) {
			t.Errorf("OIDTCGEKCertificate should equal OIDTCGKpEKCertificate")
		}
	})

	t.Run("OIDTCGAIKCertificate_equals_OIDTCGKpAIKCertificate", func(t *testing.T) {
		t.Parallel()
		if !OIDTCGAIKCertificate.Equal(OIDTCGKpAIKCertificate) {
			t.Errorf("OIDTCGAIKCertificate should equal OIDTCGKpAIKCertificate")
		}
	})
}

func TestOIDConstants_TCGBasePrefix(t *testing.T) {
	t.Parallel()

	// All TCG attribute OIDs should share the 2.23.133 prefix
	tcgOIDs := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"OIDTCGAttributeTPMManufacturer", OIDTCGAttributeTPMManufacturer},
		{"OIDTCGAttributeTPMModel", OIDTCGAttributeTPMModel},
		{"OIDTCGAttributeTPMVersion", OIDTCGAttributeTPMVersion},
		{"OIDTCGAttributePlatformManufacturer", OIDTCGAttributePlatformManufacturer},
		{"OIDTCGAttributePlatformModel", OIDTCGAttributePlatformModel},
		{"OIDTCGAttributePlatformVersion", OIDTCGAttributePlatformVersion},
		{"OIDTCGKpEKCertificate", OIDTCGKpEKCertificate},
		{"OIDTCGKpPlatformCertificate", OIDTCGKpPlatformCertificate},
		{"OIDTCGKpAIKCertificate", OIDTCGKpAIKCertificate},
		{"OIDTCGVerifiedTPMResidency", OIDTCGVerifiedTPMResidency},
		{"OIDTCGVerifiedTPMFixed", OIDTCGVerifiedTPMFixed},
	}

	for _, tt := range tcgOIDs {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if len(tt.oid) < 3 {
				t.Fatalf("OID too short: %v", tt.oid)
			}
			if tt.oid[0] != 2 || tt.oid[1] != 23 || tt.oid[2] != 133 {
				t.Errorf("OID %v does not start with TCG base 2.23.133", tt.oid)
			}
		})
	}
}

// =============================================================================
// x509.OID Policy Variables Tests
// =============================================================================

func TestPolicyOIDs_Valid(t *testing.T) {
	t.Parallel()

	t.Run("TCGVerifiedTPMResidencyPolicy_string", func(t *testing.T) {
		t.Parallel()
		s := TCGVerifiedTPMResidencyPolicy.String()
		if s != "2.23.133.11.1.1" {
			t.Errorf("expected 2.23.133.11.1.1, got %s", s)
		}
	})

	t.Run("TCGVerifiedTPMFixedPolicy_string", func(t *testing.T) {
		t.Parallel()
		s := TCGVerifiedTPMFixedPolicy.String()
		if s != "2.23.133.11.1.2" {
			t.Errorf("expected 2.23.133.11.1.2, got %s", s)
		}
	})
}

// =============================================================================
// mustParseOID Tests
// =============================================================================

func TestMustParseOID_ValidOID(t *testing.T) {
	t.Parallel()

	oid := mustParseOID("1.2.3.4.5")
	if oid.String() != "1.2.3.4.5" {
		t.Errorf("expected 1.2.3.4.5, got %s", oid.String())
	}
}

func TestMustParseOID_InvalidOID_Panics(t *testing.T) {
	t.Parallel()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for invalid OID string, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected panic string, got %T: %v", r, r)
		}
		if !containsSubstring(msg, "failed to parse OID") {
			t.Errorf("panic message %q does not contain 'failed to parse OID'", msg)
		}
	}()

	mustParseOID("not-an-oid")
}

// =============================================================================
// TCG Type ASN.1 Marshal/Unmarshal Tests
// =============================================================================

func TestTCGHardwareModuleName_ASN1Roundtrip(t *testing.T) {
	t.Parallel()

	original := TCGHardwareModuleName{
		HWType:   asn1.ObjectIdentifier{2, 23, 133, 1, 2},
		HWSerial: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	data, err := asn1.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded TCGHardwareModuleName
	_, err = asn1.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !original.HWType.Equal(decoded.HWType) {
		t.Errorf("HWType mismatch: expected %v, got %v", original.HWType, decoded.HWType)
	}
	if !bytes.Equal(original.HWSerial, decoded.HWSerial) {
		t.Errorf("HWSerial mismatch: expected %x, got %x", original.HWSerial, decoded.HWSerial)
	}
}

func TestTCGHardwareModuleName_ASN1Unmarshal_InvalidData(t *testing.T) {
	t.Parallel()

	var decoded TCGHardwareModuleName
	_, err := asn1.Unmarshal([]byte{0xFF, 0xFF}, &decoded)
	if err == nil {
		t.Fatal("expected unmarshal error for invalid data, got nil")
	}
}

func TestTCGPermanentIdentifier_ASN1Roundtrip(t *testing.T) {
	t.Parallel()

	original := TCGPermanentIdentifier{
		IdentifierValue: "device-001",
		Assigner:        asn1.ObjectIdentifier{1, 2, 3, 4},
	}

	data, err := asn1.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded TCGPermanentIdentifier
	_, err = asn1.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if original.IdentifierValue != decoded.IdentifierValue {
		t.Errorf("IdentifierValue mismatch: expected %q, got %q", original.IdentifierValue, decoded.IdentifierValue)
	}
	if !original.Assigner.Equal(decoded.Assigner) {
		t.Errorf("Assigner mismatch: expected %v, got %v", original.Assigner, decoded.Assigner)
	}
}

func TestTCGPermanentIdentifier_ASN1Unmarshal_InvalidData(t *testing.T) {
	t.Parallel()

	var decoded TCGPermanentIdentifier
	_, err := asn1.Unmarshal([]byte{0xFF, 0xFF}, &decoded)
	if err == nil {
		t.Fatal("expected unmarshal error for invalid data, got nil")
	}
}

func TestTCGTPMSpecification_ASN1Roundtrip(t *testing.T) {
	t.Parallel()

	original := TCGTPMSpecification{
		Family:   "2.0",
		Level:    0,
		Revision: 164,
	}

	data, err := asn1.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded TCGTPMSpecification
	_, err = asn1.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if original.Family != decoded.Family {
		t.Errorf("Family mismatch: expected %q, got %q", original.Family, decoded.Family)
	}
	if original.Level != decoded.Level {
		t.Errorf("Level mismatch: expected %d, got %d", original.Level, decoded.Level)
	}
	if original.Revision != decoded.Revision {
		t.Errorf("Revision mismatch: expected %d, got %d", original.Revision, decoded.Revision)
	}
}

func TestTCGTPMSpecification_ASN1Unmarshal_InvalidData(t *testing.T) {
	t.Parallel()

	var decoded TCGTPMSpecification
	_, err := asn1.Unmarshal([]byte{0xFF, 0xFF}, &decoded)
	if err == nil {
		t.Fatal("expected unmarshal error for invalid data, got nil")
	}
}

func TestTCGAttribute_ASN1Roundtrip(t *testing.T) {
	t.Parallel()

	original := TCGAttribute{
		Type:  asn1.ObjectIdentifier{2, 23, 133, 2, 1},
		Value: "INTC",
	}

	data, err := asn1.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded TCGAttribute
	_, err = asn1.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if !original.Type.Equal(decoded.Type) {
		t.Errorf("Type mismatch: expected %v, got %v", original.Type, decoded.Type)
	}
	if original.Value != decoded.Value {
		t.Errorf("Value mismatch: expected %q, got %q", original.Value, decoded.Value)
	}
}

func TestTCGTenantID_ASN1Roundtrip(t *testing.T) {
	t.Parallel()

	original := TCGTenantID{
		ID: "tenant-acme-corp",
	}

	data, err := asn1.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded TCGTenantID
	_, err = asn1.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if original.ID != decoded.ID {
		t.Errorf("ID mismatch: expected %q, got %q", original.ID, decoded.ID)
	}
}

// =============================================================================
// Create Extension Tests - String-based Extensions
// =============================================================================

// requireValidExtension is a test helper that verifies basic extension properties.
func requireValidExtension(t *testing.T, ext pkix.Extension, expectedOID asn1.ObjectIdentifier) {
	t.Helper()
	if !ext.Id.Equal(expectedOID) {
		t.Errorf("OID mismatch: expected %v, got %v", expectedOID, ext.Id)
	}
	if ext.Critical {
		t.Error("extension should not be critical")
	}
	if len(ext.Value) == 0 {
		t.Error("extension value is empty")
	}
}

// requireStringExtensionValue is a test helper that unmarshals and verifies a string value.
func requireStringExtensionValue(t *testing.T, extValue []byte, expected string) {
	t.Helper()
	var decoded string
	_, err := asn1.Unmarshal(extValue, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal extension value: %v", err)
	}
	if decoded != expected {
		t.Errorf("value mismatch: expected %q, got %q", expected, decoded)
	}
}

// requireBoolExtensionValue is a test helper that unmarshals and verifies a bool value.
func requireBoolExtensionValue(t *testing.T, extValue []byte, expected bool) {
	t.Helper()
	var decoded bool
	_, err := asn1.Unmarshal(extValue, &decoded)
	if err != nil {
		t.Fatalf("failed to unmarshal extension value: %v", err)
	}
	if decoded != expected {
		t.Errorf("value mismatch: expected %v, got %v", expected, decoded)
	}
}

func TestCreateTPMManufacturerExtension_Success(t *testing.T) {
	t.Parallel()

	ext, err := CreateTPMManufacturerExtension("INTC")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGAttributeTPMManufacturer)
	requireStringExtensionValue(t, ext.Value, "INTC")
}

func TestCreateTPMManufacturerExtension_EmptyString(t *testing.T) {
	t.Parallel()

	// Empty string is valid ASN.1 UTF8String; function should succeed
	ext, err := CreateTPMManufacturerExtension("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValidExtension(t, ext, OIDTCGAttributeTPMManufacturer)
	requireStringExtensionValue(t, ext.Value, "")
}

func TestCreateTPMModelExtension_Success(t *testing.T) {
	t.Parallel()

	ext, err := CreateTPMModelExtension("SLB 9670")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGAttributeTPMModel)
	requireStringExtensionValue(t, ext.Value, "SLB 9670")
}

func TestCreateTPMModelExtension_LongString(t *testing.T) {
	t.Parallel()

	longModel := "Infineon SLB 9670 TPM 2.0 - Enterprise Grade Hardware Security Module v3"
	ext, err := CreateTPMModelExtension(longModel)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGAttributeTPMModel)
	requireStringExtensionValue(t, ext.Value, longModel)
}

func TestCreateTPMVersionExtension_Success(t *testing.T) {
	t.Parallel()

	ext, err := CreateTPMVersionExtension("7.85")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGAttributeTPMVersion)
	requireStringExtensionValue(t, ext.Value, "7.85")
}

func TestCreateTPMVersionExtension_EmptyString(t *testing.T) {
	t.Parallel()

	ext, err := CreateTPMVersionExtension("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValidExtension(t, ext, OIDTCGAttributeTPMVersion)
	requireStringExtensionValue(t, ext.Value, "")
}

func TestCreatePlatformManufacturerExtension_Success(t *testing.T) {
	t.Parallel()

	ext, err := CreatePlatformManufacturerExtension("Dell Inc.")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGAttributePlatformManufacturer)
	requireStringExtensionValue(t, ext.Value, "Dell Inc.")
}

func TestCreatePlatformManufacturerExtension_UnicodeString(t *testing.T) {
	t.Parallel()

	ext, err := CreatePlatformManufacturerExtension("Hersteller GmbH")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGAttributePlatformManufacturer)
	requireStringExtensionValue(t, ext.Value, "Hersteller GmbH")
}

func TestCreatePlatformModelExtension_Success(t *testing.T) {
	t.Parallel()

	ext, err := CreatePlatformModelExtension("PowerEdge R750")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGAttributePlatformModel)
	requireStringExtensionValue(t, ext.Value, "PowerEdge R750")
}

func TestCreatePlatformModelExtension_EmptyString(t *testing.T) {
	t.Parallel()

	ext, err := CreatePlatformModelExtension("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValidExtension(t, ext, OIDTCGAttributePlatformModel)
	requireStringExtensionValue(t, ext.Value, "")
}

func TestCreatePlatformVersionExtension_Success(t *testing.T) {
	t.Parallel()

	ext, err := CreatePlatformVersionExtension("1.0.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGAttributePlatformVersion)
	requireStringExtensionValue(t, ext.Value, "1.0.3")
}

func TestCreatePlatformVersionExtension_EmptyString(t *testing.T) {
	t.Parallel()

	ext, err := CreatePlatformVersionExtension("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValidExtension(t, ext, OIDTCGAttributePlatformVersion)
	requireStringExtensionValue(t, ext.Value, "")
}

// =============================================================================
// Create Extension Tests - TPM Specification
// =============================================================================

func TestCreateTPMSpecificationExtension_Success(t *testing.T) {
	t.Parallel()

	spec := TCGTPMSpecification{
		Family:   "2.0",
		Level:    0,
		Revision: 164,
	}

	ext, err := CreateTPMSpecificationExtension(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGAttributeTPMSpecification)

	// Round-trip: parse the value back
	parsed, err := ParseTPMSpecificationExtension(ext.Value)
	if err != nil {
		t.Fatalf("failed to parse extension: %v", err)
	}
	if parsed.Family != spec.Family {
		t.Errorf("Family mismatch: expected %q, got %q", spec.Family, parsed.Family)
	}
	if parsed.Level != spec.Level {
		t.Errorf("Level mismatch: expected %d, got %d", spec.Level, parsed.Level)
	}
	if parsed.Revision != spec.Revision {
		t.Errorf("Revision mismatch: expected %d, got %d", spec.Revision, parsed.Revision)
	}
}

func TestCreateTPMSpecificationExtension_ZeroValues(t *testing.T) {
	t.Parallel()

	spec := TCGTPMSpecification{}
	ext, err := CreateTPMSpecificationExtension(spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGAttributeTPMSpecification)

	parsed, err := ParseTPMSpecificationExtension(ext.Value)
	if err != nil {
		t.Fatalf("failed to parse extension: %v", err)
	}
	if parsed.Family != "" {
		t.Errorf("expected empty Family, got %q", parsed.Family)
	}
	if parsed.Level != 0 {
		t.Errorf("expected Level 0, got %d", parsed.Level)
	}
	if parsed.Revision != 0 {
		t.Errorf("expected Revision 0, got %d", parsed.Revision)
	}
}

// =============================================================================
// Create Extension Tests - Hardware Module Name
// =============================================================================

func TestCreateHardwareModuleNameExtension_Success(t *testing.T) {
	t.Parallel()

	hwType := asn1.ObjectIdentifier{2, 23, 133, 1, 2}
	serial := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	ext, err := CreateHardwareModuleNameExtension(hwType, serial)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDHardwareModuleName)

	// Round-trip
	parsed, err := ParseHardwareModuleNameExtension(ext.Value)
	if err != nil {
		t.Fatalf("failed to parse extension: %v", err)
	}
	if !parsed.HWType.Equal(hwType) {
		t.Errorf("HWType mismatch: expected %v, got %v", hwType, parsed.HWType)
	}
	if !bytes.Equal(parsed.HWSerial, serial) {
		t.Errorf("HWSerial mismatch: expected %x, got %x", serial, parsed.HWSerial)
	}
}

func TestCreateHardwareModuleNameExtension_EmptySerial(t *testing.T) {
	t.Parallel()

	hwType := asn1.ObjectIdentifier{2, 23, 133, 1, 2}

	ext, err := CreateHardwareModuleNameExtension(hwType, []byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDHardwareModuleName)

	parsed, err := ParseHardwareModuleNameExtension(ext.Value)
	if err != nil {
		t.Fatalf("failed to parse extension: %v", err)
	}
	if !parsed.HWType.Equal(hwType) {
		t.Errorf("HWType mismatch: expected %v, got %v", hwType, parsed.HWType)
	}
}

func TestCreateHardwareModuleNameExtension_LargeSerial(t *testing.T) {
	t.Parallel()

	hwType := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377}
	serial := make([]byte, 256)
	for i := range serial {
		serial[i] = byte(i)
	}

	ext, err := CreateHardwareModuleNameExtension(hwType, serial)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDHardwareModuleName)

	parsed, err := ParseHardwareModuleNameExtension(ext.Value)
	if err != nil {
		t.Fatalf("failed to parse extension: %v", err)
	}
	if !bytes.Equal(parsed.HWSerial, serial) {
		t.Errorf("HWSerial length mismatch: expected %d bytes, got %d bytes", len(serial), len(parsed.HWSerial))
	}
}

// =============================================================================
// Create Extension Tests - Permanent Identifier
// =============================================================================

func TestCreatePermanentIdentifierExtension_Success(t *testing.T) {
	t.Parallel()

	identifier := "device-serial-12345"
	assigner := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377}

	ext, err := CreatePermanentIdentifierExtension(identifier, assigner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDPermanentIdentifier)

	// Round-trip
	parsed, err := ParsePermanentIdentifierExtension(ext.Value)
	if err != nil {
		t.Fatalf("failed to parse extension: %v", err)
	}
	if parsed.IdentifierValue != identifier {
		t.Errorf("IdentifierValue mismatch: expected %q, got %q", identifier, parsed.IdentifierValue)
	}
	if !parsed.Assigner.Equal(assigner) {
		t.Errorf("Assigner mismatch: expected %v, got %v", assigner, parsed.Assigner)
	}
}

func TestCreatePermanentIdentifierExtension_EmptyIdentifier(t *testing.T) {
	t.Parallel()

	assigner := asn1.ObjectIdentifier{1, 2, 3}

	ext, err := CreatePermanentIdentifierExtension("", assigner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDPermanentIdentifier)

	parsed, err := ParsePermanentIdentifierExtension(ext.Value)
	if err != nil {
		t.Fatalf("failed to parse extension: %v", err)
	}
	if parsed.IdentifierValue != "" {
		t.Errorf("expected empty IdentifierValue, got %q", parsed.IdentifierValue)
	}
}

func TestCreatePermanentIdentifierExtension_NilAssigner(t *testing.T) {
	t.Parallel()

	ext, err := CreatePermanentIdentifierExtension("some-id", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDPermanentIdentifier)
}

// =============================================================================
// Create Extension Tests - Boolean Extensions
// =============================================================================

func TestCreateVerifiedTPMResidencyExtension_True(t *testing.T) {
	t.Parallel()

	ext, err := CreateVerifiedTPMResidencyExtension(true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGVerifiedTPMResidency)
	requireBoolExtensionValue(t, ext.Value, true)
}

func TestCreateVerifiedTPMResidencyExtension_False(t *testing.T) {
	t.Parallel()

	ext, err := CreateVerifiedTPMResidencyExtension(false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGVerifiedTPMResidency)
	requireBoolExtensionValue(t, ext.Value, false)
}

func TestCreateVerifiedTPMFixedExtension_True(t *testing.T) {
	t.Parallel()

	ext, err := CreateVerifiedTPMFixedExtension(true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGVerifiedTPMFixed)
	requireBoolExtensionValue(t, ext.Value, true)
}

func TestCreateVerifiedTPMFixedExtension_False(t *testing.T) {
	t.Parallel()

	ext, err := CreateVerifiedTPMFixedExtension(false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTCGVerifiedTPMFixed)
	requireBoolExtensionValue(t, ext.Value, false)
}

func TestCreateTPFIPS140Extension_True(t *testing.T) {
	t.Parallel()

	ext, err := CreateTPFIPS140Extension(true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTPFIPS140)
	requireBoolExtensionValue(t, ext.Value, true)
}

func TestCreateTPFIPS140Extension_False(t *testing.T) {
	t.Parallel()

	ext, err := CreateTPFIPS140Extension(false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTPFIPS140)
	requireBoolExtensionValue(t, ext.Value, false)
}

// =============================================================================
// Create Extension Tests - Key Store Extensions
// =============================================================================

func TestCreateTPKeyStoreExtension_Success(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		keystore string
	}{
		{name: "TPM2", keystore: "TPM2"},
		{name: "PKCS8", keystore: "PKCS8"},
		{name: "PKCS11", keystore: "PKCS11"},
		{name: "Software", keystore: "SOFTWARE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ext, err := CreateTPKeyStoreExtension(tt.keystore)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			requireValidExtension(t, ext, OIDTPKeyStore)
			requireStringExtensionValue(t, ext.Value, tt.keystore)
		})
	}
}

func TestCreateTPKeyStoreExtension_EmptyString(t *testing.T) {
	t.Parallel()

	ext, err := CreateTPKeyStoreExtension("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValidExtension(t, ext, OIDTPKeyStore)
	requireStringExtensionValue(t, ext.Value, "")
}

func TestCreateTPIssuerKeyStoreExtension_Success(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		keystore string
	}{
		{name: "TPM2", keystore: "TPM2"},
		{name: "PKCS8", keystore: "PKCS8"},
		{name: "PKCS11", keystore: "PKCS11"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ext, err := CreateTPIssuerKeyStoreExtension(tt.keystore)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			requireValidExtension(t, ext, OIDTPIssuerKeyStore)
			requireStringExtensionValue(t, ext.Value, tt.keystore)
		})
	}
}

func TestCreateTPIssuerKeyStoreExtension_EmptyString(t *testing.T) {
	t.Parallel()

	ext, err := CreateTPIssuerKeyStoreExtension("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireValidExtension(t, ext, OIDTPIssuerKeyStore)
	requireStringExtensionValue(t, ext.Value, "")
}

// =============================================================================
// Create Extension Tests - Tenant ID
// =============================================================================

func TestCreateTenantIDExtension_Success(t *testing.T) {
	t.Parallel()

	ext, err := CreateTenantIDExtension("tenant-acme-corp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireValidExtension(t, ext, OIDTPTenantID)

	// Unmarshal and verify the TCGTenantID struct
	var decoded TCGTenantID
	_, unmarshalErr := asn1.Unmarshal(ext.Value, &decoded)
	if unmarshalErr != nil {
		t.Fatalf("failed to unmarshal tenant ID: %v", unmarshalErr)
	}
	if decoded.ID != "tenant-acme-corp" {
		t.Errorf("ID mismatch: expected %q, got %q", "tenant-acme-corp", decoded.ID)
	}
}

func TestCreateTenantIDExtension_EmptyString_ReturnsError(t *testing.T) {
	t.Parallel()

	_, err := CreateTenantIDExtension("")
	if err == nil {
		t.Fatal("expected error for empty tenant ID, got nil")
	}
	if !errors.Is(err, ErrTCGTenantIDEmpty) {
		t.Errorf("expected ErrTCGTenantIDEmpty, got %v", err)
	}
}

func TestCreateTenantIDExtension_VariousTenantIDs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tenantID string
	}{
		{name: "UUID", tenantID: "550e8400-e29b-41d4-a716-446655440000"},
		{name: "ShortID", tenantID: "t1"},
		{name: "LongID", tenantID: "organization-12345-department-67890-team-alpha"},
		{name: "SpecialChars", tenantID: "tenant/division:subsystem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ext, err := CreateTenantIDExtension(tt.tenantID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			requireValidExtension(t, ext, OIDTPTenantID)

			var decoded TCGTenantID
			_, unmarshalErr := asn1.Unmarshal(ext.Value, &decoded)
			if unmarshalErr != nil {
				t.Fatalf("failed to unmarshal: %v", unmarshalErr)
			}
			if decoded.ID != tt.tenantID {
				t.Errorf("ID mismatch: expected %q, got %q", tt.tenantID, decoded.ID)
			}
		})
	}
}

// =============================================================================
// Parse Extension Tests - Round-trip Verification
// =============================================================================

func TestParseTPMSpecificationExtension_Roundtrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec TCGTPMSpecification
	}{
		{
			name: "TPM2.0_Rev164",
			spec: TCGTPMSpecification{Family: "2.0", Level: 0, Revision: 164},
		},
		{
			name: "TPM1.2_Rev116",
			spec: TCGTPMSpecification{Family: "1.2", Level: 2, Revision: 116},
		},
		{
			name: "ZeroValues",
			spec: TCGTPMSpecification{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ext, err := CreateTPMSpecificationExtension(tt.spec)
			if err != nil {
				t.Fatalf("create failed: %v", err)
			}

			parsed, parseErr := ParseTPMSpecificationExtension(ext.Value)
			if parseErr != nil {
				t.Fatalf("parse failed: %v", parseErr)
			}

			if parsed.Family != tt.spec.Family {
				t.Errorf("Family: expected %q, got %q", tt.spec.Family, parsed.Family)
			}
			if parsed.Level != tt.spec.Level {
				t.Errorf("Level: expected %d, got %d", tt.spec.Level, parsed.Level)
			}
			if parsed.Revision != tt.spec.Revision {
				t.Errorf("Revision: expected %d, got %d", tt.spec.Revision, parsed.Revision)
			}
		})
	}
}

func TestParseTPMSpecificationExtension_InvalidData(t *testing.T) {
	t.Parallel()

	_, err := ParseTPMSpecificationExtension([]byte{0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid ASN.1 data, got nil")
	}
	if !errors.Is(err, ErrTCGExtensionParsing) {
		t.Errorf("expected ErrTCGExtensionParsing, got %v", err)
	}
}

func TestParseTPMSpecificationExtension_EmptyData(t *testing.T) {
	t.Parallel()

	_, err := ParseTPMSpecificationExtension([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data, got nil")
	}
	if !errors.Is(err, ErrTCGExtensionParsing) {
		t.Errorf("expected ErrTCGExtensionParsing, got %v", err)
	}
}

func TestParseTPMSpecificationExtension_NilData(t *testing.T) {
	t.Parallel()

	_, err := ParseTPMSpecificationExtension(nil)
	if err == nil {
		t.Fatal("expected error for nil data, got nil")
	}
	if !errors.Is(err, ErrTCGExtensionParsing) {
		t.Errorf("expected ErrTCGExtensionParsing, got %v", err)
	}
}

func TestParseHardwareModuleNameExtension_Roundtrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		hwType asn1.ObjectIdentifier
		serial []byte
	}{
		{
			name:   "TCG_OID_with_serial",
			hwType: asn1.ObjectIdentifier{2, 23, 133, 1, 2},
			serial: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:   "TP_OID_with_long_serial",
			hwType: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377},
			serial: []byte("SERIAL-NUMBER-XYZ-12345"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ext, err := CreateHardwareModuleNameExtension(tt.hwType, tt.serial)
			if err != nil {
				t.Fatalf("create failed: %v", err)
			}

			parsed, parseErr := ParseHardwareModuleNameExtension(ext.Value)
			if parseErr != nil {
				t.Fatalf("parse failed: %v", parseErr)
			}

			if !parsed.HWType.Equal(tt.hwType) {
				t.Errorf("HWType: expected %v, got %v", tt.hwType, parsed.HWType)
			}
			if !bytes.Equal(parsed.HWSerial, tt.serial) {
				t.Errorf("HWSerial: expected %x, got %x", tt.serial, parsed.HWSerial)
			}
		})
	}
}

func TestParseHardwareModuleNameExtension_InvalidData(t *testing.T) {
	t.Parallel()

	_, err := ParseHardwareModuleNameExtension([]byte{0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid ASN.1 data, got nil")
	}
	if !errors.Is(err, ErrTCGExtensionParsing) {
		t.Errorf("expected ErrTCGExtensionParsing, got %v", err)
	}
}

func TestParseHardwareModuleNameExtension_EmptyData(t *testing.T) {
	t.Parallel()

	_, err := ParseHardwareModuleNameExtension([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data, got nil")
	}
	if !errors.Is(err, ErrTCGExtensionParsing) {
		t.Errorf("expected ErrTCGExtensionParsing, got %v", err)
	}
}

func TestParsePermanentIdentifierExtension_Roundtrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		identifier string
		assigner   asn1.ObjectIdentifier
	}{
		{
			name:       "full_identifier",
			identifier: "device-001-serial",
			assigner:   asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377},
		},
		{
			name:       "short_identifier",
			identifier: "d1",
			assigner:   asn1.ObjectIdentifier{2, 23, 133},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ext, err := CreatePermanentIdentifierExtension(tt.identifier, tt.assigner)
			if err != nil {
				t.Fatalf("create failed: %v", err)
			}

			parsed, parseErr := ParsePermanentIdentifierExtension(ext.Value)
			if parseErr != nil {
				t.Fatalf("parse failed: %v", parseErr)
			}

			if parsed.IdentifierValue != tt.identifier {
				t.Errorf("IdentifierValue: expected %q, got %q", tt.identifier, parsed.IdentifierValue)
			}
			if !parsed.Assigner.Equal(tt.assigner) {
				t.Errorf("Assigner: expected %v, got %v", tt.assigner, parsed.Assigner)
			}
		})
	}
}

func TestParsePermanentIdentifierExtension_InvalidData(t *testing.T) {
	t.Parallel()

	_, err := ParsePermanentIdentifierExtension([]byte{0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for invalid ASN.1 data, got nil")
	}
	if !errors.Is(err, ErrTCGExtensionParsing) {
		t.Errorf("expected ErrTCGExtensionParsing, got %v", err)
	}
}

func TestParsePermanentIdentifierExtension_EmptyData(t *testing.T) {
	t.Parallel()

	_, err := ParsePermanentIdentifierExtension([]byte{})
	if err == nil {
		t.Fatal("expected error for empty data, got nil")
	}
	if !errors.Is(err, ErrTCGExtensionParsing) {
		t.Errorf("expected ErrTCGExtensionParsing, got %v", err)
	}
}

// =============================================================================
// Extension Consistency Tests
// =============================================================================

func TestAllCreateExtensions_AreNonCritical(t *testing.T) {
	t.Parallel()

	// Build all extensions and verify none are marked critical
	spec := TCGTPMSpecification{Family: "2.0", Level: 0, Revision: 164}
	hwType := asn1.ObjectIdentifier{2, 23, 133, 1, 2}
	serial := []byte{0x01}
	assigner := asn1.ObjectIdentifier{1, 2, 3}

	type extensionBuilder struct {
		name    string
		builder func() (pkix.Extension, error)
	}

	builders := []extensionBuilder{
		{name: "TPMManufacturer", builder: func() (pkix.Extension, error) { return CreateTPMManufacturerExtension("INTC") }},
		{name: "TPMModel", builder: func() (pkix.Extension, error) { return CreateTPMModelExtension("SLB9670") }},
		{name: "TPMVersion", builder: func() (pkix.Extension, error) { return CreateTPMVersionExtension("7.85") }},
		{name: "TPMSpecification", builder: func() (pkix.Extension, error) { return CreateTPMSpecificationExtension(spec) }},
		{name: "PlatformManufacturer", builder: func() (pkix.Extension, error) { return CreatePlatformManufacturerExtension("Dell") }},
		{name: "PlatformModel", builder: func() (pkix.Extension, error) { return CreatePlatformModelExtension("R750") }},
		{name: "PlatformVersion", builder: func() (pkix.Extension, error) { return CreatePlatformVersionExtension("1.0") }},
		{name: "HardwareModuleName", builder: func() (pkix.Extension, error) { return CreateHardwareModuleNameExtension(hwType, serial) }},
		{name: "PermanentIdentifier", builder: func() (pkix.Extension, error) { return CreatePermanentIdentifierExtension("id", assigner) }},
		{name: "VerifiedTPMResidency", builder: func() (pkix.Extension, error) { return CreateVerifiedTPMResidencyExtension(true) }},
		{name: "VerifiedTPMFixed", builder: func() (pkix.Extension, error) { return CreateVerifiedTPMFixedExtension(true) }},
		{name: "TPKeyStore", builder: func() (pkix.Extension, error) { return CreateTPKeyStoreExtension("TPM2") }},
		{name: "TPIssuerKeyStore", builder: func() (pkix.Extension, error) { return CreateTPIssuerKeyStoreExtension("PKCS11") }},
		{name: "TPFIPS140", builder: func() (pkix.Extension, error) { return CreateTPFIPS140Extension(true) }},
		{name: "TenantID", builder: func() (pkix.Extension, error) { return CreateTenantIDExtension("tenant-1") }},
	}

	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()

			ext, err := b.builder()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ext.Critical {
				t.Errorf("extension %s should not be critical", b.name)
			}
			if len(ext.Value) == 0 {
				t.Errorf("extension %s has empty value", b.name)
			}
			if ext.Id == nil {
				t.Errorf("extension %s has nil OID", b.name)
			}
		})
	}
}

func TestAllCreateExtensions_HaveDistinctOIDs(t *testing.T) {
	t.Parallel()

	spec := TCGTPMSpecification{Family: "2.0", Level: 0, Revision: 164}
	hwType := asn1.ObjectIdentifier{2, 23, 133, 1, 2}
	serial := []byte{0x01}
	assigner := asn1.ObjectIdentifier{1, 2, 3}

	type namedExt struct {
		name string
		ext  pkix.Extension
	}

	var extensions []namedExt
	addExt := func(name string, ext pkix.Extension, err error) {
		if err != nil {
			t.Fatalf("failed to create %s: %v", name, err)
		}
		extensions = append(extensions, namedExt{name: name, ext: ext})
	}

	ext, err := CreateTPMManufacturerExtension("INTC")
	addExt("TPMManufacturer", ext, err)
	ext, err = CreateTPMModelExtension("SLB9670")
	addExt("TPMModel", ext, err)
	ext, err = CreateTPMVersionExtension("7.85")
	addExt("TPMVersion", ext, err)
	ext, err = CreateTPMSpecificationExtension(spec)
	addExt("TPMSpecification", ext, err)
	ext, err = CreatePlatformManufacturerExtension("Dell")
	addExt("PlatformManufacturer", ext, err)
	ext, err = CreatePlatformModelExtension("R750")
	addExt("PlatformModel", ext, err)
	ext, err = CreatePlatformVersionExtension("1.0")
	addExt("PlatformVersion", ext, err)
	ext, err = CreateHardwareModuleNameExtension(hwType, serial)
	addExt("HardwareModuleName", ext, err)
	ext, err = CreatePermanentIdentifierExtension("id", assigner)
	addExt("PermanentIdentifier", ext, err)
	ext, err = CreateVerifiedTPMResidencyExtension(true)
	addExt("VerifiedTPMResidency", ext, err)
	ext, err = CreateVerifiedTPMFixedExtension(true)
	addExt("VerifiedTPMFixed", ext, err)
	ext, err = CreateTPKeyStoreExtension("TPM2")
	addExt("TPKeyStore", ext, err)
	ext, err = CreateTPIssuerKeyStoreExtension("PKCS11")
	addExt("TPIssuerKeyStore", ext, err)
	ext, err = CreateTPFIPS140Extension(true)
	addExt("TPFIPS140", ext, err)
	ext, err = CreateTenantIDExtension("tenant-1")
	addExt("TenantID", ext, err)

	// Verify all OIDs are distinct
	seen := make(map[string]string)
	for _, ne := range extensions {
		oidStr := ne.ext.Id.String()
		if prev, exists := seen[oidStr]; exists {
			t.Errorf("duplicate OID %s: %s and %s", oidStr, prev, ne.name)
		}
		seen[oidStr] = ne.name
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestCreateTPMManufacturerExtension_SpecialCharacters(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		manufacturer string
	}{
		{name: "WithNewline", manufacturer: "INTC\nCorp"},
		{name: "WithTab", manufacturer: "INTC\tCorp"},
		{name: "WithNullByte", manufacturer: "INTC\x00Corp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ext, err := CreateTPMManufacturerExtension(tt.manufacturer)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			requireValidExtension(t, ext, OIDTCGAttributeTPMManufacturer)
		})
	}
}

func TestOIDTCGBase_Value(t *testing.T) {
	t.Parallel()

	expected := asn1.ObjectIdentifier{2, 23, 133}
	if !OIDTCGBase.Equal(expected) {
		t.Errorf("OIDTCGBase: expected %v, got %v", expected, OIDTCGBase)
	}
}

func TestOIDTrustedPlatform_EnterpriseNumberPrefix(t *testing.T) {
	t.Parallel()

	// All Trusted Platform OIDs should share the 1.3.6.1.4.1.29377.101 prefix
	tpOIDs := []struct {
		name string
		oid  asn1.ObjectIdentifier
	}{
		{"OIDTPIssuerKeyStore", OIDTPIssuerKeyStore},
		{"OIDTPKeyStore", OIDTPKeyStore},
		{"OIDTPFIPS140", OIDTPFIPS140},
		{"OIDQuantumAlgorithm", OIDQuantumAlgorithm},
		{"OIDQuantumSignature", OIDQuantumSignature},
		{"OIDTPTenantID", OIDTPTenantID},
	}

	for _, tt := range tpOIDs {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if len(tt.oid) < 8 {
				t.Fatalf("OID too short: %v", tt.oid)
			}
			// Verify the PEN prefix: 1.3.6.1.4.1.29377.101
			expectedPrefix := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101}
			for i, v := range expectedPrefix {
				if tt.oid[i] != v {
					t.Errorf("OID %v does not start with expected prefix %v at index %d: expected %d, got %d",
						tt.oid, expectedPrefix, i, v, tt.oid[i])
					break
				}
			}
		})
	}
}
