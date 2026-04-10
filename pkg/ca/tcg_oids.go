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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// TCG Object Identifiers for TPM certificate extensions
// Reference: TCG EK Credential Profile, TCG Platform Certificate Profile
// Reference: TCG TPM 2.0 Keys for Device Identity and Attestation

var (
	// TCG Base OID: 2.23.133
	OIDTCGBase = asn1.ObjectIdentifier{2, 23, 133}

	// TCG Attribute Types (2.23.133.2)
	OIDTCGAttributeTPMManufacturer      = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	OIDTCGAttributeTPMModel             = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	OIDTCGAttributeTPMVersion           = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	OIDTCGAttributePlatformManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 4}
	OIDTCGAttributePlatformModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 5}
	OIDTCGAttributePlatformVersion      = asn1.ObjectIdentifier{2, 23, 133, 2, 6}
	OIDTCGAttributeTPMIdLabel           = asn1.ObjectIdentifier{2, 23, 133, 2, 15}
	OIDTCGAttributeTPMSpecification     = asn1.ObjectIdentifier{2, 23, 133, 2, 16}
	OIDTCGPlatformSpecification         = asn1.ObjectIdentifier{2, 23, 133, 2, 17}
	OIDTCGCredentialType                = asn1.ObjectIdentifier{2, 23, 133, 2, 23}
	OIDTCGCredentialSpecification       = asn1.ObjectIdentifier{2, 23, 133, 2, 24}

	// TCG Certificate Types (2.23.133.8)
	OIDTCGKpEKCertificate       = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	OIDTCGKpPlatformCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 2}
	OIDTCGKpAIKCertificate      = asn1.ObjectIdentifier{2, 23, 133, 8, 3}

	// TCG Verified TPM Attributes (2.23.133.11.1)
	OIDTCGVerifiedTPMResidency = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 1}
	OIDTCGVerifiedTPMFixed     = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 2}

	// Hardware Module Name (for SAN extension)
	// id-on-hardwareModuleName OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
	//   dod(6) internet(1) security(5) mechanisms(5) pkix(7) on(8) 4 }
	OIDHardwareModuleName = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 4}

	// Permanent Identifier (for SAN extension)
	OIDPermanentIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}

	// Legacy aliases for backward compatibility
	OIDTCGSpecification  = OIDTCGAttributeTPMSpecification
	OIDTCGEKCertificate  = OIDTCGKpEKCertificate
	OIDTCGAIKCertificate = OIDTCGKpAIKCertificate

	// Trusted Platform OIDs (Private Enterprise Number: 29377)
	OIDTPIssuerKeyStore = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 1}
	OIDTPKeyStore       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 2}
	OIDTPFIPS140        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 3}

	// Quantum-Safe Cryptography OIDs
	OIDQuantumAlgorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 10}
	OIDQuantumSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 11}

	// Trusted Platform Enterprise OIDs
	OIDTPTenantID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 20}
)

// x509.OID versions for use with certificate Policies field (Go 1.24+).
// These are required because Go 1.24+ no longer marshals PolicyIdentifiers by default.
var (
	// TCGVerifiedTPMResidencyPolicy is the x509.OID version of OIDTCGVerifiedTPMResidency
	TCGVerifiedTPMResidencyPolicy = mustParseOID("2.23.133.11.1.1")
	// TCGVerifiedTPMFixedPolicy is the x509.OID version of OIDTCGVerifiedTPMFixed
	TCGVerifiedTPMFixedPolicy = mustParseOID("2.23.133.11.1.2")
)

// mustParseOID parses an OID string and panics on error (for static initialization).
func mustParseOID(s string) x509.OID {
	oid, err := x509.ParseOID(s)
	if err != nil {
		panic("failed to parse OID: " + s)
	}
	return oid
}

// TCGHardwareModuleName represents the structure for OIDHardwareModuleName
// as defined in RFC 4108 Section 5.
type TCGHardwareModuleName struct {
	HWType   asn1.ObjectIdentifier
	HWSerial []byte
}

// TCGPermanentIdentifier represents the structure for OIDPermanentIdentifier
// as defined in RFC 4043.
type TCGPermanentIdentifier struct {
	IdentifierValue string                `asn1:"optional,utf8"`
	Assigner        asn1.ObjectIdentifier `asn1:"optional"`
}

// TCGTPMSpecification represents TPM specification version information.
type TCGTPMSpecification struct {
	Family   string
	Level    int
	Revision int
}

// TCGAttribute represents a single TCG attribute for certificate extensions.
type TCGAttribute struct {
	Type  asn1.ObjectIdentifier
	Value string `asn1:"utf8"`
}

// TCGTenantID represents a tenant binding in multi-tenant deployments.
// This extension binds a device identity certificate to a specific tenant.
type TCGTenantID struct {
	ID string `asn1:"utf8"`
}

// CreateTPMManufacturerExtension creates an X.509 extension for TPM manufacturer.
func CreateTPMManufacturerExtension(manufacturer string) (pkix.Extension, error) {
	value, err := asn1.Marshal(manufacturer)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTCGAttributeTPMManufacturer,
		Critical: false,
		Value:    value,
	}, nil
}

// CreateTPMModelExtension creates an X.509 extension for TPM model.
func CreateTPMModelExtension(model string) (pkix.Extension, error) {
	value, err := asn1.Marshal(model)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTCGAttributeTPMModel,
		Critical: false,
		Value:    value,
	}, nil
}

// CreateTPMVersionExtension creates an X.509 extension for TPM version.
func CreateTPMVersionExtension(version string) (pkix.Extension, error) {
	value, err := asn1.Marshal(version)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTCGAttributeTPMVersion,
		Critical: false,
		Value:    value,
	}, nil
}

// CreateTPMSpecificationExtension creates an X.509 extension for TPM specification.
func CreateTPMSpecificationExtension(spec TCGTPMSpecification) (pkix.Extension, error) {
	value, err := asn1.Marshal(spec)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTCGAttributeTPMSpecification,
		Critical: false,
		Value:    value,
	}, nil
}

// CreatePlatformManufacturerExtension creates an X.509 extension for platform manufacturer.
func CreatePlatformManufacturerExtension(manufacturer string) (pkix.Extension, error) {
	value, err := asn1.Marshal(manufacturer)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTCGAttributePlatformManufacturer,
		Critical: false,
		Value:    value,
	}, nil
}

// CreatePlatformModelExtension creates an X.509 extension for platform model.
func CreatePlatformModelExtension(model string) (pkix.Extension, error) {
	value, err := asn1.Marshal(model)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTCGAttributePlatformModel,
		Critical: false,
		Value:    value,
	}, nil
}

// CreatePlatformVersionExtension creates an X.509 extension for platform version.
func CreatePlatformVersionExtension(version string) (pkix.Extension, error) {
	value, err := asn1.Marshal(version)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTCGAttributePlatformVersion,
		Critical: false,
		Value:    value,
	}, nil
}

// CreateHardwareModuleNameExtension creates an X.509 extension for hardware module name.
func CreateHardwareModuleNameExtension(hwType asn1.ObjectIdentifier, serial []byte) (pkix.Extension, error) {
	hwName := TCGHardwareModuleName{
		HWType:   hwType,
		HWSerial: serial,
	}
	value, err := asn1.Marshal(hwName)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDHardwareModuleName,
		Critical: false,
		Value:    value,
	}, nil
}

// CreatePermanentIdentifierExtension creates an X.509 extension for permanent identifier.
func CreatePermanentIdentifierExtension(identifier string, assigner asn1.ObjectIdentifier) (pkix.Extension, error) {
	permID := TCGPermanentIdentifier{
		IdentifierValue: identifier,
		Assigner:        assigner,
	}
	value, err := asn1.Marshal(permID)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDPermanentIdentifier,
		Critical: false,
		Value:    value,
	}, nil
}

// CreateVerifiedTPMResidencyExtension creates an X.509 extension indicating TPM key residency.
func CreateVerifiedTPMResidencyExtension(verified bool) (pkix.Extension, error) {
	value, err := asn1.Marshal(verified)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTCGVerifiedTPMResidency,
		Critical: false,
		Value:    value,
	}, nil
}

// CreateVerifiedTPMFixedExtension creates an X.509 extension indicating non-migratable TPM key.
func CreateVerifiedTPMFixedExtension(fixed bool) (pkix.Extension, error) {
	value, err := asn1.Marshal(fixed)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTCGVerifiedTPMFixed,
		Critical: false,
		Value:    value,
	}, nil
}

// ParseTPMSpecificationExtension parses a TPM specification extension value.
func ParseTPMSpecificationExtension(value []byte) (TCGTPMSpecification, error) {
	var spec TCGTPMSpecification
	_, err := asn1.Unmarshal(value, &spec)
	if err != nil {
		return TCGTPMSpecification{}, ErrTCGExtensionParsing
	}
	return spec, nil
}

// ParseHardwareModuleNameExtension parses a hardware module name extension value.
func ParseHardwareModuleNameExtension(value []byte) (TCGHardwareModuleName, error) {
	var hwName TCGHardwareModuleName
	_, err := asn1.Unmarshal(value, &hwName)
	if err != nil {
		return TCGHardwareModuleName{}, ErrTCGExtensionParsing
	}
	return hwName, nil
}

// ParsePermanentIdentifierExtension parses a permanent identifier extension value.
func ParsePermanentIdentifierExtension(value []byte) (TCGPermanentIdentifier, error) {
	var permID TCGPermanentIdentifier
	_, err := asn1.Unmarshal(value, &permID)
	if err != nil {
		return TCGPermanentIdentifier{}, ErrTCGExtensionParsing
	}
	return permID, nil
}

// CreateTPKeyStoreExtension creates an X.509 extension indicating the key storage backend.
// Common values: "TPM2", "PKCS8", "PKCS11"
func CreateTPKeyStoreExtension(keystoreType string) (pkix.Extension, error) {
	value, err := asn1.Marshal(keystoreType)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTPKeyStore,
		Critical: false,
		Value:    value,
	}, nil
}

// CreateTPIssuerKeyStoreExtension creates an X.509 extension indicating the issuer's key storage backend.
// Common values: "TPM2", "PKCS8", "PKCS11"
func CreateTPIssuerKeyStoreExtension(keystoreType string) (pkix.Extension, error) {
	value, err := asn1.Marshal(keystoreType)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTPIssuerKeyStore,
		Critical: false,
		Value:    value,
	}, nil
}

// CreateTPFIPS140Extension creates an X.509 extension indicating FIPS 140 compliance.
func CreateTPFIPS140Extension(fipsCompliant bool) (pkix.Extension, error) {
	value, err := asn1.Marshal(fipsCompliant)
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTPFIPS140,
		Critical: false,
		Value:    value,
	}, nil
}

// CreateTenantIDExtension creates a certificate extension binding the certificate
// to a specific tenant ID for multi-tenant deployments.
func CreateTenantIDExtension(tenantID string) (pkix.Extension, error) {
	if tenantID == "" {
		return pkix.Extension{}, ErrTCGTenantIDEmpty
	}
	value, err := asn1.Marshal(TCGTenantID{ID: tenantID})
	if err != nil {
		return pkix.Extension{}, ErrTCGExtensionEncoding
	}
	return pkix.Extension{
		Id:       OIDTPTenantID,
		Critical: false,
		Value:    value,
	}, nil
}
