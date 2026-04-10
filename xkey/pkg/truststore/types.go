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

// CertPurpose categorizes certificates by their intended usage within the
// trust store, enabling purpose-scoped lookups and management.
type CertPurpose string

const (
	// PurposeGeneral is the default category for uncategorized certificates.
	PurposeGeneral CertPurpose = "general"

	// PurposeTPMManufacturer identifies TPM vendor root CA certificates used
	// to verify TPM endorsement key certificates and attestation chains.
	PurposeTPMManufacturer CertPurpose = "tpm-manufacturer"

	// PurposeAndroidHardware identifies Google/Android hardware attestation
	// root CA certificates used to verify Android key attestation chains.
	PurposeAndroidHardware CertPurpose = "android-hardware"

	// PurposeUserCA identifies user-created CA root certificates that have
	// been explicitly trusted by the operator.
	PurposeUserCA CertPurpose = "user-ca"

	// PurposeBootstrapCA identifies CA certificates obtained through the
	// bootstrap enrollment process.
	PurposeBootstrapCA CertPurpose = "bootstrap-ca"

	// PurposeIDevIDIssuer identifies CA certificates that issue IDevID
	// certificates for device identity verification.
	PurposeIDevIDIssuer CertPurpose = "idevid-issuer"
)

// validPurposes provides O(1) lookup for certificate purpose validation.
var validPurposes = map[CertPurpose]bool{
	PurposeGeneral:         true,
	PurposeTPMManufacturer: true,
	PurposeAndroidHardware: true,
	PurposeUserCA:          true,
	PurposeBootstrapCA:     true,
	PurposeIDevIDIssuer:    true,
}

// IsValidPurpose reports whether the given purpose is a recognized
// certificate category.
func IsValidPurpose(purpose CertPurpose) bool {
	return validPurposes[purpose]
}

// ParsePurpose converts a string to a CertPurpose, returning
// ErrInvalidPurpose if the string does not match a known purpose.
func ParsePurpose(s string) (CertPurpose, error) {
	purpose := CertPurpose(s)
	if !validPurposes[purpose] {
		return "", ErrInvalidPurpose
	}
	return purpose, nil
}
