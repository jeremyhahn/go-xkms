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

package certstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Config provides configuration for creating a new CertStore instance.
type Config struct {
	// CertStorage provides underlying certificate storage.
	// Required.
	CertStorage CertificateStorageAdapter

	// VerifyOptions provides default verification options.
	// Optional - if not provided, defaults will be used.
	VerifyOptions *x509.VerifyOptions

	// AllowRevoked if true, allows operations on revoked certificates.
	// Default is false - operations on revoked certs will fail.
	AllowRevoked bool
}

// CertificateStorageAdapter is a local interface that matches storage.CertificateStorage.
// This allows the certstore package to work with any compatible storage implementation
// without creating a direct dependency on the storage package.
//
// This interface is satisfied by storage.CertificateStorage.
type CertificateStorageAdapter interface {
	SaveCert(ctx context.Context, id string, cert *x509.Certificate) error
	GetCert(ctx context.Context, id string) (*x509.Certificate, error)
	DeleteCert(ctx context.Context, id string) error
	SaveCertChain(ctx context.Context, id string, chain []*x509.Certificate) error
	GetCertChain(ctx context.Context, id string) ([]*x509.Certificate, error)
	ListCerts(ctx context.Context) ([]string, error)
	CertExists(ctx context.Context, id string) (bool, error)
	Close() error
}

// CRLEntry represents a certificate revocation list entry.
type CRLEntry struct {
	// SerialNumber is the serial number of the revoked certificate.
	SerialNumber string

	// RevocationTime is when the certificate was revoked.
	RevocationTime time.Time

	// Reason is the revocation reason code.
	Reason int
}

// CertificateInfo provides detailed information about a stored certificate.
type CertificateInfo struct {
	// Certificate is the X.509 certificate.
	Certificate *x509.Certificate

	// CN is the Common Name from the certificate subject.
	CN string

	// Issuer is the Common Name of the issuing CA.
	Issuer string

	// NotBefore is the certificate validity start time.
	NotBefore time.Time

	// NotAfter is the certificate validity end time.
	NotAfter time.Time

	// IsCA indicates if this is a CA certificate.
	IsCA bool

	// IsRevoked indicates if the certificate is revoked.
	IsRevoked bool

	// KeyUsage describes the key usage extensions.
	KeyUsage x509.KeyUsage

	// ExtKeyUsage describes the extended key usage extensions.
	ExtKeyUsage []x509.ExtKeyUsage
}

// ChainInfo provides information about a certificate chain.
type ChainInfo struct {
	// Certificates is the complete chain from leaf to root.
	Certificates []*x509.Certificate

	// LeafCN is the Common Name of the end-entity certificate.
	LeafCN string

	// RootCN is the Common Name of the root CA certificate.
	RootCN string

	// IsValid indicates if the chain is valid and trusted.
	IsValid bool

	// ValidationError contains any validation errors.
	ValidationError error
}

// =============================================================================
// Certificate Display Functions
// =============================================================================

// Well-known OID definitions for certificate extension display.
// Exported for use by dependent packages (e.g., go-trusted-ca).
var (
	// OIDTCGBase is the TCG Base OID: 2.23.133
	OIDTCGBase = asn1.ObjectIdentifier{2, 23, 133}

	// OIDTCGAttributeTPMManufacturer is tcg-at-tpmManufacturer (2.23.133.2.1)
	OIDTCGAttributeTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	// OIDTCGAttributeTPMModel is tcg-at-tpmModel (2.23.133.2.2)
	OIDTCGAttributeTPMModel = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	// OIDTCGAttributeTPMVersion is tcg-at-tpmVersion (2.23.133.2.3)
	OIDTCGAttributeTPMVersion = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	// OIDTCGAttributePlatformManufacturer is tcg-at-platformManufacturer (2.23.133.2.4)
	OIDTCGAttributePlatformManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 4}
	// OIDTCGAttributePlatformModel is tcg-at-platformModel (2.23.133.2.5)
	OIDTCGAttributePlatformModel = asn1.ObjectIdentifier{2, 23, 133, 2, 5}
	// OIDTCGAttributePlatformVersion is tcg-at-platformVersion (2.23.133.2.6)
	OIDTCGAttributePlatformVersion = asn1.ObjectIdentifier{2, 23, 133, 2, 6}
	// OIDTCGAttributeTPMIdLabel is tcg-at-tpmIdLabel (2.23.133.2.15)
	OIDTCGAttributeTPMIdLabel = asn1.ObjectIdentifier{2, 23, 133, 2, 15}
	// OIDTCGAttributeTPMSpecification is tcg-at-tpmSpecification (2.23.133.2.16)
	OIDTCGAttributeTPMSpecification = asn1.ObjectIdentifier{2, 23, 133, 2, 16}
	// OIDTCGPlatformSpecification is tcg-at-platformSpecification (2.23.133.2.17)
	OIDTCGPlatformSpecification = asn1.ObjectIdentifier{2, 23, 133, 2, 17}
	// OIDTCGCredentialType is tcg-at-credentialType (2.23.133.2.23)
	OIDTCGCredentialType = asn1.ObjectIdentifier{2, 23, 133, 2, 23}
	// OIDTCGCredentialSpecification is tcg-at-credentialSpecification (2.23.133.2.24)
	OIDTCGCredentialSpecification = asn1.ObjectIdentifier{2, 23, 133, 2, 24}

	// OIDTCGKpEKCertificate is tcg-kp-EKCertificate (2.23.133.8.1)
	OIDTCGKpEKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	// OIDTCGKpPlatformCertificate is tcg-kp-PlatformCertificate (2.23.133.8.2)
	OIDTCGKpPlatformCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 2}
	// OIDTCGKpAIKCertificate is tcg-kp-AIKCertificate (2.23.133.8.3)
	OIDTCGKpAIKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 3}

	// OIDTCGVerifiedTPMResidency is tcg-verified-tpmResidency (2.23.133.11.1.1)
	OIDTCGVerifiedTPMResidency = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 1}
	// OIDTCGVerifiedTPMFixed is tcg-verified-tpmFixed (2.23.133.11.1.2)
	OIDTCGVerifiedTPMFixed = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 2}

	// OIDHardwareModuleName is id-on-hardwareModuleName (1.3.6.1.5.5.7.8.4)
	OIDHardwareModuleName = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 4}
	// OIDPermanentIdentifier is id-on-permanentIdentifier (1.3.6.1.5.5.7.8.3)
	OIDPermanentIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}

	// OIDTPIssuerKeyStore is tp-issuerKeyStore (1.3.6.1.4.1.29377.101.1)
	OIDTPIssuerKeyStore = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 1}
	// OIDTPKeyStore is tp-keyStore (1.3.6.1.4.1.29377.101.2)
	OIDTPKeyStore = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 2}
	// OIDTPFIPS140 is tp-fips140 (1.3.6.1.4.1.29377.101.3)
	OIDTPFIPS140 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 3}
	// OIDQuantumAlgorithm is tp-quantumAlgorithm (1.3.6.1.4.1.29377.101.10)
	OIDQuantumAlgorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 10}
	// OIDQuantumSignature is tp-quantumSignature (1.3.6.1.4.1.29377.101.11)
	OIDQuantumSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 11}

	// OIDSubjectKeyIdentifier is subjectKeyIdentifier (2.5.29.14)
	OIDSubjectKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 14}
	// OIDKeyUsage is keyUsage (2.5.29.15)
	OIDKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}
	// OIDSubjectAltName is subjectAltName (2.5.29.17)
	OIDSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
	// OIDBasicConstraints is basicConstraints (2.5.29.19)
	OIDBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	// OIDAuthorityKeyIdentifier is authorityKeyIdentifier (2.5.29.35)
	OIDAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	// OIDExtKeyUsage is extKeyUsage (2.5.29.37)
	OIDExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// oidNames maps OID strings to human-readable names
var oidNames = map[string]string{
	// TCG Attribute Types
	"2.23.133.2.1":  "tcg-at-tpmManufacturer",
	"2.23.133.2.2":  "tcg-at-tpmModel",
	"2.23.133.2.3":  "tcg-at-tpmVersion",
	"2.23.133.2.4":  "tcg-at-platformManufacturer",
	"2.23.133.2.5":  "tcg-at-platformModel",
	"2.23.133.2.6":  "tcg-at-platformVersion",
	"2.23.133.2.15": "tcg-at-tpmIdLabel",
	"2.23.133.2.16": "tcg-at-tpmSpecification",
	"2.23.133.2.17": "tcg-at-platformSpecification",
	"2.23.133.2.23": "tcg-at-credentialType",
	"2.23.133.2.24": "tcg-at-credentialSpecification",

	// TCG Certificate Types
	"2.23.133.8.1": "tcg-kp-EKCertificate",
	"2.23.133.8.2": "tcg-kp-PlatformCertificate",
	"2.23.133.8.3": "tcg-kp-AIKCertificate",

	// TCG Verified TPM Attributes
	"2.23.133.11.1.1": "tcg-verified-tpmResidency",
	"2.23.133.11.1.2": "tcg-verified-tpmFixed",

	// PKIX Authority Information Access
	"1.3.6.1.5.5.7.1.1":  "authorityInfoAccess",
	"1.3.6.1.5.5.7.48.1": "id-ad-ocsp",
	"1.3.6.1.5.5.7.48.2": "id-ad-caIssuers",

	// PKIX OIDs
	"1.3.6.1.5.5.7.8.3": "id-on-permanentIdentifier",
	"1.3.6.1.5.5.7.8.4": "id-on-hardwareModuleName",

	// Trusted Platform OIDs
	"1.3.6.1.4.1.29377.101.1":  "tp-issuerKeyStore",
	"1.3.6.1.4.1.29377.101.2":  "tp-keyStore",
	"1.3.6.1.4.1.29377.101.3":  "tp-fips140",
	"1.3.6.1.4.1.29377.101.10": "tp-quantumAlgorithm",
	"1.3.6.1.4.1.29377.101.11": "tp-quantumSignature",

	// Standard X.509 Extensions
	"2.5.29.9":  "subjectDirectoryAttributes",
	"2.5.29.14": "subjectKeyIdentifier",
	"2.5.29.15": "keyUsage",
	"2.5.29.17": "subjectAltName",
	"2.5.29.19": "basicConstraints",
	"2.5.29.35": "authorityKeyIdentifier",
	"2.5.29.37": "extKeyUsage",
}

// OIDToName returns a human-readable name for known OIDs
func OIDToName(oid asn1.ObjectIdentifier) string {
	oidStr := oid.String()
	if name, ok := oidNames[oidStr]; ok {
		return name
	}

	// Check if it's a TCG OID
	if IsTCGOID(oid) {
		return fmt.Sprintf("tcg-unknown(%s)", oidStr)
	}

	// Check if it's a Trusted Platform OID
	if IsTrustedPlatformOID(oid) {
		return fmt.Sprintf("tp-unknown(%s)", oidStr)
	}

	return oidStr
}

// IsTCGOID checks if an OID belongs to the TCG arc (2.23.133)
func IsTCGOID(oid asn1.ObjectIdentifier) bool {
	return len(oid) >= 3 && oid[0] == 2 && oid[1] == 23 && oid[2] == 133
}

// IsTrustedPlatformOID checks if an OID belongs to the Trusted Platform arc
func IsTrustedPlatformOID(oid asn1.ObjectIdentifier) bool {
	return len(oid) >= 7 && oid[0] == 1 && oid[1] == 3 && oid[2] == 6 &&
		oid[3] == 1 && oid[4] == 4 && oid[5] == 1 && oid[6] == 29377
}

// KeyUsageToString returns a string representation of key usage flags.
func KeyUsageToString(usage x509.KeyUsage) string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}
	if len(usages) == 0 {
		return "None"
	}
	return strings.Join(usages, ", ")
}

// ExtKeyUsageToString returns a string representation of extended key usage.
func ExtKeyUsageToString(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return "Any"
	case x509.ExtKeyUsageServerAuth:
		return "ServerAuth"
	case x509.ExtKeyUsageClientAuth:
		return "ClientAuth"
	case x509.ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case x509.ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case x509.ExtKeyUsageIPSECEndSystem:
		return "IPSECEndSystem"
	case x509.ExtKeyUsageIPSECTunnel:
		return "IPSECTunnel"
	case x509.ExtKeyUsageIPSECUser:
		return "IPSECUser"
	case x509.ExtKeyUsageTimeStamping:
		return "TimeStamping"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	default:
		return fmt.Sprintf("Unknown(%d)", usage)
	}
}

// PublicKeyTypeString returns the type and size of a public key.
func PublicKeyTypeString(pub interface{}) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d bits", k.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", k.Curve.Params().Name)
	default:
		return fmt.Sprintf("Unknown(%T)", pub)
	}
}

// authorityKeyIdentifier matches the ASN.1 structure
type authorityKeyIdentifier struct {
	KeyIdentifier             []byte        `asn1:"optional,tag:0"`
	AuthorityCertIssuer       asn1.RawValue `asn1:"optional,tag:1"`
	AuthorityCertSerialNumber asn1.RawValue `asn1:"optional,tag:2"`
}

// oidAuthorityInfoAccess is the OID for Authority Information Access
var oidAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

// oidCAIssuers is the OID for CA Issuers access method
var oidCAIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}

// oidOCSP is the OID for OCSP access method
var oidOCSP = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}

// accessDescription represents a single AIA entry
type accessDescription struct {
	AccessMethod   asn1.ObjectIdentifier
	AccessLocation asn1.RawValue
}

// formatRDNSequence formats an RDN sequence with human-readable TCG OID names
func formatRDNSequence(rdnSeq pkix.RDNSequence) string {
	var parts []string
	for _, rdn := range rdnSeq {
		for _, atv := range rdn {
			oidName := OIDToName(atv.Type)
			// Try to format the value as a string
			switch v := atv.Value.(type) {
			case string:
				parts = append(parts, fmt.Sprintf("%s=%s", oidName, v))
			default:
				parts = append(parts, fmt.Sprintf("%s=%v", oidName, v))
			}
		}
	}
	return strings.Join(parts, ", ")
}

// ParseSubjectAltName parses the SAN extension and returns human-readable output.
func ParseSubjectAltName(value []byte) string {
	var generalNames []asn1.RawValue
	if _, err := asn1.Unmarshal(value, &generalNames); err != nil {
		return hex.EncodeToString(value)
	}

	var parts []string
	for _, gn := range generalNames {
		switch gn.Tag {
		case 1: // rfc822Name (email)
			parts = append(parts, fmt.Sprintf("email:%s", string(gn.Bytes)))
		case 2: // dNSName
			parts = append(parts, fmt.Sprintf("DNS:%s", string(gn.Bytes)))
		case 4: // directoryName
			var rdnSeq pkix.RDNSequence
			if _, err := asn1.Unmarshal(gn.Bytes, &rdnSeq); err == nil {
				parts = append(parts, fmt.Sprintf("DirName: %s", formatRDNSequence(rdnSeq)))
			} else {
				parts = append(parts, "DirName:<parse error>")
			}
		case 6: // uniformResourceIdentifier
			parts = append(parts, fmt.Sprintf("URI:%s", string(gn.Bytes)))
		case 7: // iPAddress
			if len(gn.Bytes) == 4 {
				parts = append(parts, fmt.Sprintf("IP:%d.%d.%d.%d",
					gn.Bytes[0], gn.Bytes[1], gn.Bytes[2], gn.Bytes[3]))
			} else if len(gn.Bytes) == 16 {
				parts = append(parts, fmt.Sprintf("IP:%x", gn.Bytes))
			}
		default:
			parts = append(parts, fmt.Sprintf("tag%d:%s", gn.Tag, hex.EncodeToString(gn.Bytes)))
		}
	}

	if len(parts) == 0 {
		return hex.EncodeToString(value)
	}
	return strings.Join(parts, "; ")
}

// ParseAuthorityInfoAccess parses the AIA extension.
func ParseAuthorityInfoAccess(value []byte) string {
	var accessDescriptions []accessDescription
	if _, err := asn1.Unmarshal(value, &accessDescriptions); err != nil {
		return hex.EncodeToString(value)
	}

	var parts []string
	for _, ad := range accessDescriptions {
		var methodName string
		if ad.AccessMethod.Equal(oidCAIssuers) {
			methodName = "CA Issuers"
		} else if ad.AccessMethod.Equal(oidOCSP) {
			methodName = "OCSP"
		} else {
			methodName = ad.AccessMethod.String()
		}

		// Parse the access location (usually a URI)
		if ad.AccessLocation.Tag == 6 { // uniformResourceIdentifier
			parts = append(parts, fmt.Sprintf("%s: %s", methodName, string(ad.AccessLocation.Bytes)))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s", methodName, hex.EncodeToString(ad.AccessLocation.Bytes)))
		}
	}

	if len(parts) == 0 {
		return hex.EncodeToString(value)
	}
	return strings.Join(parts, "; ")
}

// tpmSpecification represents TCG TPM Specification attribute (2.23.133.2.16)
type tpmSpecification struct {
	Family   string
	Level    int
	Revision int
}

// ParseSubjectDirectoryAttributes parses the subject directory attributes extension.
func ParseSubjectDirectoryAttributes(value []byte) string {
	// Subject Directory Attributes is a SEQUENCE OF Attribute
	// Each Attribute has an OID and a SET OF values
	var attributes []struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(value, &attributes); err != nil {
		return hex.EncodeToString(value)
	}

	var parts []string
	for _, attr := range attributes {
		attrName := OIDToName(attr.Type)

		// Special handling for TPM Specification (2.23.133.2.16)
		if attr.Type.Equal(OIDTCGAttributeTPMSpecification) {
			var spec tpmSpecification
			if _, err := asn1.Unmarshal(attr.Values.Bytes, &spec); err == nil {
				parts = append(parts, fmt.Sprintf("%s: Family=%s, Level=%d, Revision=%d",
					attrName, spec.Family, spec.Level, spec.Revision))
				continue
			}
		}

		// Try to parse as UTF8 string
		var strVal string
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &strVal); err == nil {
			parts = append(parts, fmt.Sprintf("%s=%s", attrName, strVal))
		} else {
			parts = append(parts, fmt.Sprintf("%s=%s", attrName, hex.EncodeToString(attr.Values.Bytes)))
		}
	}

	if len(parts) == 0 {
		return hex.EncodeToString(value)
	}
	return strings.Join(parts, "; ")
}

// TCGAttributes holds parsed TCG OID values from an X.509 certificate.
type TCGAttributes struct {
	// Manufacturer from subjectAltName DirName: tcg-at-tpmManufacturer (2.23.133.2.1)
	// Raw value, typically "id:XXXXXXXX" hex format.
	Manufacturer string
	// ManufacturerName is the resolved human-readable manufacturer name.
	// Derived from Manufacturer's hex vendor ID using the TCG vendor registry.
	ManufacturerName string
	// Model from subjectAltName DirName: tcg-at-tpmModel (2.23.133.2.2)
	Model string
	// Version from subjectAltName DirName: tcg-at-tpmVersion (2.23.133.2.3)
	Version string
	// SpecFamily from subjectDirectoryAttributes: tcg-at-tpmSpecification (2.23.133.2.16)
	SpecFamily string
	// SpecLevel from subjectDirectoryAttributes: tcg-at-tpmSpecification (2.23.133.2.16)
	SpecLevel int
	// SpecRevision from subjectDirectoryAttributes: tcg-at-tpmSpecification (2.23.133.2.16)
	SpecRevision int
}

// tcgVendors maps 4-byte TCG vendor IDs (as uint32) to human-readable names.
// These are the same values used in TPM_PT_MANUFACTURER.
var tcgVendors = map[uint32]string{
	0x414D4400: "AMD",
	0x41544D4C: "Atmel",
	0x4252434D: "Broadcom",
	0x49424D00: "IBM",
	0x48504500: "HPE",
	0x4D534654: "Microsoft",
	0x49465800: "Infineon",
	0x494E5443: "Intel",
	0x4C454E00: "Lenovo",
	0x4E534D20: "National Semiconductor",
	0x4E545A00: "Nationz",
	0x4E544300: "Nuvoton Technology",
	0x51434F4D: "Qualcomm",
	0x534D5343: "SMSC",
	0x53544D20: "ST Microelectronics",
	0x534D534E: "Samsung",
	0x53494E00: "Sinosun",
	0x54584E00: "Texas Instruments",
	0x57454300: "Winbond",
	0x524F4343: "Fuzhou Rockchip",
	0x474F4F47: "Google",
}

// resolveManufacturerID converts a TCG manufacturer ID string like "id:53544D20"
// to a human-readable vendor name. Returns empty string if the format is
// unrecognized or the vendor ID is not in the registry.
func resolveManufacturerID(raw string) string {
	if !strings.HasPrefix(raw, "id:") {
		return ""
	}
	hexStr := raw[3:]
	if len(hexStr) != 8 {
		return ""
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 4 {
		return ""
	}
	id := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return tcgVendors[id]
}

// ParseTCGAttributes extracts TCG attributes from an X.509 certificate's extensions.
// Parses subjectAltName (2.5.29.17) for manufacturer/model/version and
// subjectDirectoryAttributes (2.5.29.9) for TPM specification details.
// Returns a TCGAttributes with whatever fields could be parsed; missing fields
// remain at zero values.
func ParseTCGAttributes(cert *x509.Certificate) TCGAttributes {
	var attrs TCGAttributes
	if cert == nil {
		return attrs
	}

	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(OIDSubjectAltName):
			parseSANForTCG(ext.Value, &attrs)
		case ext.Id.Equal(OIDSubjectDirectoryAttributes):
			parseSDAttrForTCG(ext.Value, &attrs)
		}
	}

	// Resolve manufacturer hex ID to human-readable name.
	if attrs.Manufacturer != "" {
		attrs.ManufacturerName = resolveManufacturerID(attrs.Manufacturer)
	}

	return attrs
}

// parseSANForTCG extracts manufacturer/model/version from the SAN extension's
// directoryName entries.
func parseSANForTCG(value []byte, attrs *TCGAttributes) {
	var generalNames []asn1.RawValue
	if _, err := asn1.Unmarshal(value, &generalNames); err != nil {
		return
	}

	for _, gn := range generalNames {
		if gn.Tag != 4 { // directoryName
			continue
		}
		var rdnSeq pkix.RDNSequence
		if _, err := asn1.Unmarshal(gn.Bytes, &rdnSeq); err != nil {
			continue
		}
		for _, rdn := range rdnSeq {
			for _, atv := range rdn {
				str, ok := atv.Value.(string)
				if !ok {
					continue
				}
				switch {
				case atv.Type.Equal(OIDTCGAttributeTPMManufacturer):
					attrs.Manufacturer = str
				case atv.Type.Equal(OIDTCGAttributeTPMModel):
					attrs.Model = str
				case atv.Type.Equal(OIDTCGAttributeTPMVersion):
					attrs.Version = str
				}
			}
		}
	}
}

// parseSDAttrForTCG extracts TPM specification details from the
// subjectDirectoryAttributes extension.
func parseSDAttrForTCG(value []byte, attrs *TCGAttributes) {
	var attributes []struct {
		Type   asn1.ObjectIdentifier
		Values asn1.RawValue `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(value, &attributes); err != nil {
		return
	}

	for _, attr := range attributes {
		if !attr.Type.Equal(OIDTCGAttributeTPMSpecification) {
			continue
		}
		var spec tpmSpecification
		if _, err := asn1.Unmarshal(attr.Values.Bytes, &spec); err != nil {
			continue
		}
		attrs.SpecFamily = spec.Family
		attrs.SpecLevel = spec.Level
		attrs.SpecRevision = spec.Revision
	}
}

// OIDSubjectDirectoryAttributes is subjectDirectoryAttributes (2.5.29.9)
var OIDSubjectDirectoryAttributes = asn1.ObjectIdentifier{2, 5, 29, 9}

// ParseExtensionValue attempts to parse and display an extension value.
func ParseExtensionValue(ext pkix.Extension) string {
	oid := ext.Id

	// Try to parse known extension types
	switch {
	case oid.Equal(OIDSubjectKeyIdentifier):
		var ski []byte
		if _, err := asn1.Unmarshal(ext.Value, &ski); err == nil {
			return hex.EncodeToString(ski)
		}

	case oid.Equal(OIDAuthorityKeyIdentifier):
		var aki authorityKeyIdentifier
		if _, err := asn1.Unmarshal(ext.Value, &aki); err == nil {
			return fmt.Sprintf("KeyID: %s", hex.EncodeToString(aki.KeyIdentifier))
		}

	case oid.Equal(OIDSubjectAltName):
		return ParseSubjectAltName(ext.Value)

	case oid.Equal(oidAuthorityInfoAccess):
		return ParseAuthorityInfoAccess(ext.Value)

	case oid.Equal(OIDSubjectDirectoryAttributes):
		return ParseSubjectDirectoryAttributes(ext.Value)

	case IsTCGOID(oid), IsTrustedPlatformOID(oid):
		// Try to parse as UTF8 string first
		var strVal string
		if _, err := asn1.Unmarshal(ext.Value, &strVal); err == nil {
			return strVal
		}
		// Try to parse as boolean
		var boolVal bool
		if _, err := asn1.Unmarshal(ext.Value, &boolVal); err == nil {
			return fmt.Sprintf("%v", boolVal)
		}
		// Fall back to full hex (no truncation)
		return hex.EncodeToString(ext.Value)
	}

	// Default: show FULL hex representation (no truncation)
	return hex.EncodeToString(ext.Value)
}

// ToString returns a detailed string representation of a certificate
// including all extensions with TCG and Trusted Platform OID names.
func ToString(certificate *x509.Certificate) string {
	if certificate == nil {
		return "<nil certificate>"
	}

	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("                           CERTIFICATE DETAILS                                  \n")
	sb.WriteString("═══════════════════════════════════════════════════════════════════════════════\n")

	// Basic Information
	sb.WriteString("\n┌─ Subject ─────────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(&sb, "│  Common Name:        %s\n", certificate.Subject.CommonName)
	if len(certificate.Subject.Organization) > 0 {
		fmt.Fprintf(&sb, "│  Organization:       %s\n", strings.Join(certificate.Subject.Organization, ", "))
	}
	if len(certificate.Subject.OrganizationalUnit) > 0 {
		fmt.Fprintf(&sb, "│  Org Unit:           %s\n", strings.Join(certificate.Subject.OrganizationalUnit, ", "))
	}
	if len(certificate.Subject.Country) > 0 {
		fmt.Fprintf(&sb, "│  Country:            %s\n", strings.Join(certificate.Subject.Country, ", "))
	}
	if len(certificate.Subject.Province) > 0 {
		fmt.Fprintf(&sb, "│  State/Province:     %s\n", strings.Join(certificate.Subject.Province, ", "))
	}
	if len(certificate.Subject.Locality) > 0 {
		fmt.Fprintf(&sb, "│  Locality:           %s\n", strings.Join(certificate.Subject.Locality, ", "))
	}
	if certificate.Subject.SerialNumber != "" {
		fmt.Fprintf(&sb, "│  Serial Number:      %s\n", certificate.Subject.SerialNumber)
	}

	sb.WriteString("\n┌─ Issuer ──────────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(&sb, "│  Common Name:        %s\n", certificate.Issuer.CommonName)
	if len(certificate.Issuer.Organization) > 0 {
		fmt.Fprintf(&sb, "│  Organization:       %s\n", strings.Join(certificate.Issuer.Organization, ", "))
	}

	sb.WriteString("\n┌─ Validity ────────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(&sb, "│  Serial Number:      %s\n", certificate.SerialNumber.String())
	fmt.Fprintf(&sb, "│  SHA-1 Fingerprint:  %x\n", sha1.Sum(certificate.Raw))
	fmt.Fprintf(&sb, "│  Not Before:         %s\n", certificate.NotBefore.Format(time.RFC3339))
	fmt.Fprintf(&sb, "│  Not After:          %s\n", certificate.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(&sb, "│  Signature Algo:     %s\n", certificate.SignatureAlgorithm.String())

	sb.WriteString("\n┌─ Public Key ──────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(&sb, "│  Type:               %s\n", PublicKeyTypeString(certificate.PublicKey))
	if len(certificate.SubjectKeyId) > 0 {
		fmt.Fprintf(&sb, "│  Subject Key ID:     %s\n", hex.EncodeToString(certificate.SubjectKeyId))
	}

	sb.WriteString("\n┌─ Basic Constraints ──────────────────────────────────────────────────────────\n")
	fmt.Fprintf(&sb, "│  Is CA:              %v\n", certificate.IsCA)
	if certificate.IsCA {
		if certificate.MaxPathLenZero {
			sb.WriteString("│  Max Path Length:    0 (zero)\n")
		} else if certificate.MaxPathLen > 0 {
			fmt.Fprintf(&sb, "│  Max Path Length:    %d\n", certificate.MaxPathLen)
		} else {
			sb.WriteString("│  Max Path Length:    unlimited\n")
		}
	}

	sb.WriteString("\n┌─ Key Usage ───────────────────────────────────────────────────────────────────\n")
	fmt.Fprintf(&sb, "│  Key Usage:          %s\n", KeyUsageToString(certificate.KeyUsage))

	if len(certificate.ExtKeyUsage) > 0 {
		var ekuStrs []string
		for _, eku := range certificate.ExtKeyUsage {
			ekuStrs = append(ekuStrs, ExtKeyUsageToString(eku))
		}
		fmt.Fprintf(&sb, "│  Ext Key Usage:      %s\n", strings.Join(ekuStrs, ", "))
	}

	// Subject Alternative Names
	if len(certificate.DNSNames) > 0 || len(certificate.IPAddresses) > 0 ||
		len(certificate.URIs) > 0 || len(certificate.EmailAddresses) > 0 {
		sb.WriteString("\n┌─ Subject Alternative Names ───────────────────────────────────────────────────\n")
		for _, dns := range certificate.DNSNames {
			fmt.Fprintf(&sb, "│  DNS:                %s\n", dns)
		}
		for _, ip := range certificate.IPAddresses {
			fmt.Fprintf(&sb, "│  IP:                 %s\n", ip.String())
		}
		for _, uri := range certificate.URIs {
			fmt.Fprintf(&sb, "│  URI:                %s\n", uri.String())
		}
		for _, email := range certificate.EmailAddresses {
			fmt.Fprintf(&sb, "│  Email:              %s\n", email)
		}
	}

	// Extensions - group by type
	if len(certificate.Extensions) > 0 {
		// Separate extensions by category
		var tcgExts, tpExts, standardExts, otherExts []pkix.Extension

		for _, ext := range certificate.Extensions {
			if IsTCGOID(ext.Id) {
				tcgExts = append(tcgExts, ext)
			} else if IsTrustedPlatformOID(ext.Id) {
				tpExts = append(tpExts, ext)
			} else if len(ext.Id) >= 3 && ext.Id[0] == 2 && ext.Id[1] == 5 && ext.Id[2] == 29 {
				standardExts = append(standardExts, ext)
			} else {
				otherExts = append(otherExts, ext)
			}
		}

		// TCG Extensions
		if len(tcgExts) > 0 {
			sb.WriteString("\n┌─ TCG Extensions (Trusted Computing Group) ───────────────────────────────────\n")
			for _, ext := range tcgExts {
				critical := ""
				if ext.Critical {
					critical = " [CRITICAL]"
				}
				name := OIDToName(ext.Id)
				value := ParseExtensionValue(ext)
				fmt.Fprintf(&sb, "│  %-25s %s%s\n", name+":", value, critical)
			}
		}

		// Trusted Platform Extensions
		if len(tpExts) > 0 {
			sb.WriteString("\n┌─ Trusted Platform Extensions ────────────────────────────────────────────────\n")
			for _, ext := range tpExts {
				critical := ""
				if ext.Critical {
					critical = " [CRITICAL]"
				}
				name := OIDToName(ext.Id)
				value := ParseExtensionValue(ext)
				fmt.Fprintf(&sb, "│  %-25s %s%s\n", name+":", value, critical)
			}
		}

		// Standard X.509 Extensions
		if len(standardExts) > 0 {
			sb.WriteString("\n┌─ Standard X.509 Extensions ──────────────────────────────────────────────────\n")
			for _, ext := range standardExts {
				critical := ""
				if ext.Critical {
					critical = " [CRITICAL]"
				}
				name := OIDToName(ext.Id)
				value := ParseExtensionValue(ext)
				fmt.Fprintf(&sb, "│  %-25s %s%s\n", name+":", value, critical)
			}
		}

		// Other Extensions
		if len(otherExts) > 0 {
			sb.WriteString("\n┌─ Other Extensions ────────────────────────────────────────────────────────────\n")
			for _, ext := range otherExts {
				critical := ""
				if ext.Critical {
					critical = " [CRITICAL]"
				}
				name := OIDToName(ext.Id)
				value := ParseExtensionValue(ext)
				fmt.Fprintf(&sb, "│  %-25s %s%s\n", name+":", value, critical)
			}
		}
	}

	sb.WriteString("\n═══════════════════════════════════════════════════════════════════════════════\n")

	return sb.String()
}

// ChainToString returns a detailed string representation of a certificate chain
func ChainToString(chain []*x509.Certificate) string {
	if len(chain) == 0 {
		return "<empty certificate chain>"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Certificate chain contains %d certificate(s):\n", len(chain))

	for i, cert := range chain {
		fmt.Fprintf(&sb, "\n--- Certificate [%d/%d] ---\n", i+1, len(chain))
		sb.WriteString(ToString(cert))
	}

	return sb.String()
}
