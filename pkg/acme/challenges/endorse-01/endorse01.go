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

package endorse01

import (
	"crypto"
	"crypto/x509"
	"net"
)

// endorse-01 Challenge Implementation
//
// The endorse-01 challenge is a custom ACME extension for TPM Endorsement Key (EK)
// certificate issuance. This challenge type supports the enrollment of TPM-equipped
// devices that do NOT have manufacturer-issued EK certificates.
//
// Use Cases:
// - TPM simulators (swtpm) that don't have manufacturer EK certificates
// - Devices without manufacturer-issued EK certificates
// - OEM/Enterprise custom EK certificate enrollment
// - Enterprise TPM provisioning where custom EK certificates are required
//
// TPM Requirements:
// - TPM 2.0 compliant hardware or software TPM
// - Endorsement Key (EK) created in the TPM
// - EK public key exportable for certificate issuance
//
// Challenge Flow:
// 1. Client creates CSR with EK public key as permanent identifier
// 2. Client submits CSR to ACME server
// 3. Server validates request (optionally via EAB) and issues EK certificate
// 4. Client receives EK certificate for subsequent enroll-01 challenges
//
// Security Properties:
// - Can be combined with ACME External Account Binding (EAB) for authorized enrollment
// - EK certificate enables subsequent TPM-based attestation via enroll-01
// - Server policy determines which devices can receive EK certificates
//
// Note: This challenge does NOT perform credential activation because the TPM
// does not have an EK certificate yet - that's what this challenge issues!
// For TPMs with manufacturer EK certificates, use enroll-01 directly.

// CertificateAuthority defines the CA interface needed for endorse-01 operations
type CertificateAuthority interface {
	// CreateCSR generates a Certificate Signing Request
	CreateCSR(req CertificateRequest) ([]byte, error)

	// DefaultSignatureAlgorithm returns the CA's default signature algorithm
	DefaultSignatureAlgorithm() x509.SignatureAlgorithm
}

// CertificateRequest represents a certificate signing request
type CertificateRequest struct {
	PermanentID   string
	KeyAttributes interface{}
	Subject       Subject
}

// Subject represents certificate subject information
type Subject struct {
	CommonName string
}

// TrustedPlatformModule defines the TPM interface needed for endorse-01 setup
type TrustedPlatformModule interface {
	// EK returns the TPM Endorsement Key public key
	EK() crypto.PublicKey

	// EKAttributes returns the EK key attributes
	EKAttributes() (interface{}, error)
}

// Serializer defines the interface for key serialization
type Serializer interface {
	Serialize(key interface{}) ([]byte, error)
}

// KeyAttributesWithCN is an optional interface for KeyAttributes that provide a CN
type KeyAttributesWithCN interface {
	GetCN() string
}

// Verify performs endorse-01 challenge verification.
//
// The endorse-01 challenge verification simply returns nil because the
// actual validation happens at the CSR submission level through:
// - ACME External Account Binding (EAB) for authorized enrollment
// - Server-side policy validation of the EK public key
// - Optional integration with manufacturer databases
//
// This is different from enroll-01 which performs TPM2_MakeCredential/
// TPM2_ActivateCredential to prove TPM possession. The endorse-01 cannot
// do credential activation because the TPM doesn't have an EK certificate
// yet - that's what this challenge is meant to issue.
//
// Parameters:
//   - resolver: DNS resolver (not used in endorse-01)
//   - ca: Certificate Authority (not used in verification)
//   - domain: Domain/identifier (not used in endorse-01)
//   - port: HTTP port (not used in endorse-01)
//   - challengeToken: Challenge token (not used in endorse-01)
//   - expectedKeyAuth: Expected key authorization (not used in endorse-01)
//
// Returns:
//   - nil - verification is handled by EAB and server policy
//
// NOTE: ACME EAB support for endorse-01 is implemented in pkg/acme/server/handlers/endorse_eab.go.
// Administrators can pre-authorize specific devices or device batches for EK certificate issuance
// by creating EAB credentials with purpose="endorse-01".
func Verify(
	resolver *net.Resolver,
	ca CertificateAuthority,
	domain, port, challengeToken, expectedKeyAuth string) error {

	// The endorse-01 challenge verification relies on:
	// 1. ACME External Account Binding (EAB) if configured
	// 2. Server-side policy validation during CSR processing
	// 3. Optional integration with device inventory/provisioning systems
	//
	// No HTTP-based challenge verification is performed because:
	// - The TPM doesn't have an EK certificate for MakeCredential
	// - The purpose is to ISSUE an EK certificate, not verify one exists
	return nil
}

// Setup prepares an endorse-01 challenge by creating a CSR for the TPM Endorsement Key.
//
// The function performs the following steps:
// 1. Retrieves EK public key from TPM
// 2. Retrieves EK attributes (including common name)
// 3. Serializes EK public key to bytes
// 4. Creates CSR with EK public key as permanent identifier
//
// The serialized EK public key serves as a unique, permanent identifier for
// the device TPM. This ensures the certificate is bound to a specific TPM instance.
//
// Parameters:
//   - challengeToken: Challenge token (reserved for future use)
//   - certAuthority: Certificate Authority for CSR generation
//   - tpm: Trusted Platform Module for EK retrieval
//   - serializer: Key serializer for encoding EK public key
//
// Returns:
//   - CSR bytes for submission to ACME server
//   - error if EK retrieval, serialization, or CSR generation fails
//
// The CSR includes:
// - Subject CN from EK attributes
// - Serialized EK public key as permanent identifier
// - EK key attributes for validation
func Setup(
	challengeToken string,
	certAuthority CertificateAuthority,
	tpm TrustedPlatformModule,
	serializer Serializer) ([]byte, error) {

	ekPubKey := tpm.EK()
	ekAttrs, err := tpm.EKAttributes()
	if err != nil {
		return nil, err
	}

	ekPubKeyBytes, err := serializer.Serialize(ekPubKey)
	if err != nil {
		return nil, err
	}

	// Extract CN from attributes if available
	var cn string
	if attrs, ok := ekAttrs.(KeyAttributesWithCN); ok {
		cn = attrs.GetCN()
	}

	csr, err := certAuthority.CreateCSR(CertificateRequest{
		PermanentID:   string(ekPubKeyBytes),
		KeyAttributes: ekAttrs,
		Subject: Subject{
			CommonName: cn,
		},
	})
	if err != nil {
		return nil, err
	}

	return csr, nil
}
