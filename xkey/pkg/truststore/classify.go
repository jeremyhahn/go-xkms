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

package truststore

import (
	"crypto/x509"
	"encoding/asn1"
	"strings"
)

// oidAndroidKeyAttestation is the Android key attestation extension OID
// (1.3.6.1.4.1.11129.2.1.17), used to identify certificates containing
// Android hardware attestation data.
var oidAndroidKeyAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// oidTCGBase is the Trusted Computing Group (TCG) base OID (2.23.133),
// used as a prefix to identify TCG-related certificate extensions.
var oidTCGBase = asn1.ObjectIdentifier{2, 23, 133}

// manufacturerPurposes maps lowercase issuer organization name substrings to
// certificate purposes for auto-classification. This provides O(1) lookup
// for known TPM manufacturer organizations.
var manufacturerPurposes = map[string]CertPurpose{
	"intel":              PurposeTPMManufacturer,
	"amd":                PurposeTPMManufacturer,
	"infineon":           PurposeTPMManufacturer,
	"stmicroelectronics": PurposeTPMManufacturer,
	"nuvoton":            PurposeTPMManufacturer,
	"nationz":            PurposeTPMManufacturer,
	"atmel":              PurposeTPMManufacturer,
	"broadcom":           PurposeTPMManufacturer,
	"qualcomm":           PurposeTPMManufacturer,
}

// ClassifyCertificate determines the purpose of a certificate by examining its
// properties. Classification follows a priority order: Android hardware
// attestation, TPM manufacturer, IDevID issuer, user CA, and general.
// Uses map-based dispatch for O(1) manufacturer lookup.
func ClassifyCertificate(cert *x509.Certificate) CertPurpose {
	// Check for Android hardware attestation: extension OID match or
	// issuer heuristic (Google organization with Attestation in CN).
	if hasAndroidAttestationOID(cert) {
		return PurposeAndroidHardware
	}
	issuerOrg := strings.Join(cert.Issuer.Organization, " ")
	issuerCN := cert.Issuer.CommonName
	if strings.Contains(issuerOrg, "Google") && strings.Contains(issuerCN, "Attestation") {
		return PurposeAndroidHardware
	}

	// Check for TPM manufacturer: O(1) lookup against known manufacturer names,
	// plus TCG OID prefix detection in extensions.
	for _, org := range cert.Issuer.Organization {
		lowerOrg := strings.ToLower(org)
		for keyword, purpose := range manufacturerPurposes {
			if strings.Contains(lowerOrg, keyword) {
				return purpose
			}
		}
	}
	if hasOIDPrefix(cert, oidTCGBase) {
		return PurposeTPMManufacturer
	}

	// Check for IDevID issuer: heuristic based on extended key usage containing
	// server or client authentication combined with "IDevID" in the issuer CN.
	if strings.Contains(issuerCN, "IDevID") {
		for _, eku := range cert.ExtKeyUsage {
			if eku == x509.ExtKeyUsageServerAuth || eku == x509.ExtKeyUsageClientAuth {
				return PurposeIDevIDIssuer
			}
		}
	}

	// Check for user CA: self-signed CA certificate.
	if cert.IsCA && cert.Issuer.CommonName == cert.Subject.CommonName {
		subjectOrg := strings.Join(cert.Subject.Organization, " ")
		if subjectOrg == issuerOrg {
			return PurposeUserCA
		}
	}

	return PurposeGeneral
}

// hasOIDPrefix reports whether any certificate extension has an OID that starts
// with the given prefix. This is used for detecting TCG-related extensions.
func hasOIDPrefix(cert *x509.Certificate, prefix asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if len(ext.Id) >= len(prefix) {
			match := true
			for i, v := range prefix {
				if ext.Id[i] != v {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// hasAndroidAttestationOID reports whether the certificate contains an extension
// with the Android key attestation OID (1.3.6.1.4.1.11129.2.1.17).
func hasAndroidAttestationOID(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidAndroidKeyAttestation) {
			return true
		}
	}
	return false
}
