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

package certstore

import (
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
	SaveCert(id string, cert *x509.Certificate) error
	GetCert(id string) (*x509.Certificate, error)
	DeleteCert(id string) error
	SaveCertChain(id string, chain []*x509.Certificate) error
	GetCertChain(id string) ([]*x509.Certificate, error)
	ListCerts() ([]string, error)
	CertExists(id string) (bool, error)
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

// Well-known OID definitions for certificate extension display
//
//nolint:unused // OIDs defined for future TPM/certificate features
var (
	// TCG Base OID: 2.23.133
	oidTCGBase = asn1.ObjectIdentifier{2, 23, 133}

	// TCG Attribute Types (2.23.133.2)
	oidTCGAttributeTPMManufacturer      = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	oidTCGAttributeTPMModel             = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	oidTCGAttributeTPMVersion           = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	oidTCGAttributePlatformManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 4}
	oidTCGAttributePlatformModel        = asn1.ObjectIdentifier{2, 23, 133, 2, 5}
	oidTCGAttributePlatformVersion      = asn1.ObjectIdentifier{2, 23, 133, 2, 6}
	oidTCGAttributeTPMIdLabel           = asn1.ObjectIdentifier{2, 23, 133, 2, 15}
	oidTCGAttributeTPMSpecification     = asn1.ObjectIdentifier{2, 23, 133, 2, 16}
	oidTCGPlatformSpecification         = asn1.ObjectIdentifier{2, 23, 133, 2, 17}
	oidTCGCredentialType                = asn1.ObjectIdentifier{2, 23, 133, 2, 23}
	oidTCGCredentialSpecification       = asn1.ObjectIdentifier{2, 23, 133, 2, 24}

	// TCG Certificate Types (2.23.133.8)
	oidTCGKpEKCertificate       = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	oidTCGKpPlatformCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 2}
	oidTCGKpAIKCertificate      = asn1.ObjectIdentifier{2, 23, 133, 8, 3}

	// TCG Verified TPM Attributes (2.23.133.11.1)
	oidTCGVerifiedTPMResidency = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 1}
	oidTCGVerifiedTPMFixed     = asn1.ObjectIdentifier{2, 23, 133, 11, 1, 2}

	// Hardware Module Name (for SAN extension)
	oidHardwareModuleName = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 4}

	// Permanent Identifier (for SAN extension)
	oidPermanentIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 3}

	// Trusted Platform OIDs (Private Enterprise Number: 29377)
	oidTPIssuerKeyStore = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 1}
	oidTPKeyStore       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 2}
	oidTPFIPS140        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 3}
	oidQuantumAlgorithm = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 10}
	oidQuantumSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 11}

	// Standard X.509 extension OIDs
	oidSubjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidKeyUsage               = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidSubjectAltName         = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidBasicConstraints       = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 37}
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

// keyUsageToString returns a string representation of key usage flags
func keyUsageToString(usage x509.KeyUsage) string {
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

// extKeyUsageToString returns a string representation of extended key usage
func extKeyUsageToString(usage x509.ExtKeyUsage) string {
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

// publicKeyTypeString returns the type and size of a public key
func publicKeyTypeString(pub interface{}) string {
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

// parseExtensionValue attempts to parse and display an extension value
func parseExtensionValue(ext pkix.Extension) string {
	oid := ext.Id

	// Try to parse known extension types
	switch {
	case oid.Equal(oidSubjectKeyIdentifier):
		var ski []byte
		if _, err := asn1.Unmarshal(ext.Value, &ski); err == nil {
			return hex.EncodeToString(ski)
		}

	case oid.Equal(oidAuthorityKeyIdentifier):
		var aki authorityKeyIdentifier
		if _, err := asn1.Unmarshal(ext.Value, &aki); err == nil {
			return fmt.Sprintf("KeyID: %s", hex.EncodeToString(aki.KeyIdentifier))
		}

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
		// Fall back to hex
		return hex.EncodeToString(ext.Value)
	}

	// Default: show truncated hex representation
	if len(ext.Value) > 32 {
		return hex.EncodeToString(ext.Value[:32]) + "..."
	}
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
	sb.WriteString(fmt.Sprintf("│  Common Name:        %s\n", certificate.Subject.CommonName))
	if len(certificate.Subject.Organization) > 0 {
		sb.WriteString(fmt.Sprintf("│  Organization:       %s\n", strings.Join(certificate.Subject.Organization, ", ")))
	}
	if len(certificate.Subject.OrganizationalUnit) > 0 {
		sb.WriteString(fmt.Sprintf("│  Org Unit:           %s\n", strings.Join(certificate.Subject.OrganizationalUnit, ", ")))
	}
	if len(certificate.Subject.Country) > 0 {
		sb.WriteString(fmt.Sprintf("│  Country:            %s\n", strings.Join(certificate.Subject.Country, ", ")))
	}
	if len(certificate.Subject.Province) > 0 {
		sb.WriteString(fmt.Sprintf("│  State/Province:     %s\n", strings.Join(certificate.Subject.Province, ", ")))
	}
	if len(certificate.Subject.Locality) > 0 {
		sb.WriteString(fmt.Sprintf("│  Locality:           %s\n", strings.Join(certificate.Subject.Locality, ", ")))
	}
	if certificate.Subject.SerialNumber != "" {
		sb.WriteString(fmt.Sprintf("│  Serial Number:      %s\n", certificate.Subject.SerialNumber))
	}

	sb.WriteString("\n┌─ Issuer ──────────────────────────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("│  Common Name:        %s\n", certificate.Issuer.CommonName))
	if len(certificate.Issuer.Organization) > 0 {
		sb.WriteString(fmt.Sprintf("│  Organization:       %s\n", strings.Join(certificate.Issuer.Organization, ", ")))
	}

	sb.WriteString("\n┌─ Validity ────────────────────────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("│  Serial Number:      %s\n", certificate.SerialNumber.String()))
	sb.WriteString(fmt.Sprintf("│  SHA-1 Fingerprint:  %x\n", sha1.Sum(certificate.Raw)))
	sb.WriteString(fmt.Sprintf("│  Not Before:         %s\n", certificate.NotBefore.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("│  Not After:          %s\n", certificate.NotAfter.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("│  Signature Algo:     %s\n", certificate.SignatureAlgorithm.String()))

	sb.WriteString("\n┌─ Public Key ──────────────────────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("│  Type:               %s\n", publicKeyTypeString(certificate.PublicKey)))
	if len(certificate.SubjectKeyId) > 0 {
		sb.WriteString(fmt.Sprintf("│  Subject Key ID:     %s\n", hex.EncodeToString(certificate.SubjectKeyId)))
	}

	sb.WriteString("\n┌─ Basic Constraints ──────────────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("│  Is CA:              %v\n", certificate.IsCA))
	if certificate.IsCA {
		if certificate.MaxPathLenZero {
			sb.WriteString("│  Max Path Length:    0 (zero)\n")
		} else if certificate.MaxPathLen > 0 {
			sb.WriteString(fmt.Sprintf("│  Max Path Length:    %d\n", certificate.MaxPathLen))
		} else {
			sb.WriteString("│  Max Path Length:    unlimited\n")
		}
	}

	sb.WriteString("\n┌─ Key Usage ───────────────────────────────────────────────────────────────────\n")
	sb.WriteString(fmt.Sprintf("│  Key Usage:          %s\n", keyUsageToString(certificate.KeyUsage)))

	if len(certificate.ExtKeyUsage) > 0 {
		var ekuStrs []string
		for _, eku := range certificate.ExtKeyUsage {
			ekuStrs = append(ekuStrs, extKeyUsageToString(eku))
		}
		sb.WriteString(fmt.Sprintf("│  Ext Key Usage:      %s\n", strings.Join(ekuStrs, ", ")))
	}

	// Subject Alternative Names
	if len(certificate.DNSNames) > 0 || len(certificate.IPAddresses) > 0 ||
		len(certificate.URIs) > 0 || len(certificate.EmailAddresses) > 0 {
		sb.WriteString("\n┌─ Subject Alternative Names ───────────────────────────────────────────────────\n")
		for _, dns := range certificate.DNSNames {
			sb.WriteString(fmt.Sprintf("│  DNS:                %s\n", dns))
		}
		for _, ip := range certificate.IPAddresses {
			sb.WriteString(fmt.Sprintf("│  IP:                 %s\n", ip.String()))
		}
		for _, uri := range certificate.URIs {
			sb.WriteString(fmt.Sprintf("│  URI:                %s\n", uri.String()))
		}
		for _, email := range certificate.EmailAddresses {
			sb.WriteString(fmt.Sprintf("│  Email:              %s\n", email))
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
				value := parseExtensionValue(ext)
				sb.WriteString(fmt.Sprintf("│  %-25s %s%s\n", name+":", value, critical))
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
				value := parseExtensionValue(ext)
				sb.WriteString(fmt.Sprintf("│  %-25s %s%s\n", name+":", value, critical))
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
				value := parseExtensionValue(ext)
				sb.WriteString(fmt.Sprintf("│  %-25s %s%s\n", name+":", value, critical))
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
				value := parseExtensionValue(ext)
				sb.WriteString(fmt.Sprintf("│  %-25s %s%s\n", name+":", value, critical))
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
	sb.WriteString(fmt.Sprintf("Certificate chain contains %d certificate(s):\n", len(chain)))

	for i, cert := range chain {
		sb.WriteString(fmt.Sprintf("\n--- Certificate [%d/%d] ---\n", i+1, len(chain)))
		sb.WriteString(ToString(cert))
	}

	return sb.String()
}
