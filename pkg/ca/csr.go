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

// Package ca provides CSR (Certificate Signing Request) generation operations
// for the XKMSCA certificate authority.
//
// # CSR Generation
//
// This file implements CSR creation functionality that supports:
//   - Automatic key generation based on KeyAttributes
//   - Manual key provision via crypto.Signer
//   - Subject Alternative Names (DNS, IP, Email, URI, Hardware Module)
//   - Automatic signature algorithm selection based on key type
//   - PEM-encoded output suitable for CA submission
//
// # Usage with CA Instance
//
// The CA.CreateCSR method generates a CSR using the CA's keystore for key management:
//
//	request := &ca.CertificateRequest{
//	    Subject: ca.Subject{
//	        CommonName:   "server.example.com",
//	        Organization: "Example Corp",
//	    },
//	    SANS: &ca.SubjectAlternativeNames{
//	        DNS: []string{"server.example.com", "www.example.com"},
//	        IPs: []string{"192.168.1.100"},
//	    },
//	    KeyAttributes: &types.KeyAttributes{
//	        CN:           "server.example.com",
//	        KeyAlgorithm: x509.ECDSA,
//	        StoreType:    types.StoreSoftware,
//	        KeyType:      types.KeyTypeTLS,
//	        ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
//	    },
//	}
//
//	csrPEM, err := ca.CreateCSR(request)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Standalone CSR Generation
//
// For creating CSRs with an externally provided signer (e.g., PIV keys, HSM keys):
//
//	signer, _ := pivCard.Signer(slot)
//	csrPEM, err := ca.CreateCSRWithKey(request, signer)
//
// # Hardware Module Names
//
// For TPM/HSM device identity certificates per RFC 4108:
//
//	request.SANS.HardwareModuleName = &ca.HardwareModuleInfo{
//	    HWType:         asn1.ObjectIdentifier{2, 23, 133, 1}, // TCG Platform
//	    HWSerialNumber: "ABCD1234567890",
//	}
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// OID for Subject Alternative Name extension (2.5.29.17)
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// OID for Hardware Module Name (RFC 4108)
var oidHardwareModuleName = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 8, 4}

// CreateCSR creates a new certificate signing request for the given request.
//
// The CSR is generated using a newly created or existing private key based on the
// KeyAttributes in the CertificateRequest. If KeyAttributes is nil, a default
// ECDSA P-256 key is generated. If Signer is provided in the request, that signer
// is used instead of generating or retrieving a key.
//
// The generated or existing private key is stored in the CA's keystore using the
// request's Subject.CommonName as the identifier.
//
// Returns the CSR in PEM-encoded format suitable for submission to a CA.
//
// Thread-safe: Yes
//
// Example:
//
//	request := &CertificateRequest{
//	    Subject: Subject{CommonName: "server.example.com"},
//	    SANS: &SubjectAlternativeNames{
//	        DNS: []string{"server.example.com"},
//	    },
//	}
//	csrPEM, err := ca.CreateCSR(request)
func (ca *CA) CreateCSR(request *CertificateRequest) ([]byte, error) {
	// Validate the request
	if err := validateCSRRequest(request); err != nil {
		return nil, err
	}

	// Get or create the signer
	var signer crypto.Signer
	var err error

	if request.Signer != nil {
		// Use provided signer
		signer = request.Signer
	} else {
		// Get or generate key from keystore
		signer, err = ca.getOrGenerateKey(request)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCSRGenerationFailed, err)
		}
	}

	// Build and sign the CSR
	return createAndSignCSR(request, signer)
}

// CreateCSRWithKey creates a certificate signing request using an externally provided signer.
//
// This standalone function does not require a CA instance and is useful for:
//   - PIV card CSR generation where keys are on a smart card
//   - HSM-backed keys accessed through PKCS#11
//   - TPM-backed keys that already exist
//   - Any scenario where the private key is managed externally
//
// The signer must implement crypto.Signer and its Public() method must return
// a valid public key (RSA, ECDSA, or Ed25519).
//
// Thread-safe: Yes (stateless function)
//
// Example:
//
//	// Generate CSR with a PIV card signer
//	pivSigner, _ := pivCard.Signer(piv.SlotAuthentication)
//	request := &CertificateRequest{
//	    Subject: Subject{CommonName: "user@example.com"},
//	    SANS: &SubjectAlternativeNames{
//	        Email: []string{"user@example.com"},
//	    },
//	}
//	csrPEM, err := CreateCSRWithKey(request, pivSigner)
func CreateCSRWithKey(request *CertificateRequest, signer crypto.Signer) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("%w: signer is nil", ErrCSRGenerationFailed)
	}

	if err := validateCSRRequest(request); err != nil {
		return nil, err
	}

	return createAndSignCSR(request, signer)
}

// getOrGenerateKey retrieves an existing key or generates a new one based on the request's KeyAttributes.
func (ca *CA) getOrGenerateKey(request *CertificateRequest) (crypto.Signer, error) {
	attrs := request.KeyAttributes
	if attrs == nil {
		// Create default key attributes using ECDSA P-256
		attrs = &types.KeyAttributes{
			CN:           request.Subject.CommonName,
			KeyAlgorithm: x509.ECDSA,
			StoreType:    types.StoreSoftware,
			KeyType:      types.KeyTypeTLS,
			ECCAttributes: &types.ECCAttributes{
				Curve: elliptic.P256(),
			},
			Hash: crypto.SHA256,
		}
		request.KeyAttributes = attrs
	}

	// Ensure CN is set
	if attrs.CN == "" {
		attrs.CN = request.Subject.CommonName
	}

	// Try to get existing key first
	signer, err := ca.keyStore.Signer(attrs)
	if err == nil {
		return signer, nil
	}

	// Key doesn't exist, generate a new one
	var privKey crypto.PrivateKey

	switch attrs.KeyAlgorithm {
	case x509.RSA:
		privKey, err = ca.keyStore.GenerateRSA(attrs)
	case x509.ECDSA:
		privKey, err = ca.keyStore.GenerateECDSA(attrs)
	case x509.Ed25519:
		privKey, err = ca.keyStore.GenerateEd25519(attrs)
	default:
		// Default to ECDSA P-256
		if attrs.ECCAttributes == nil {
			attrs.ECCAttributes = &types.ECCAttributes{Curve: elliptic.P256()}
		}
		attrs.KeyAlgorithm = x509.ECDSA
		privKey, err = ca.keyStore.GenerateECDSA(attrs)
	}

	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	// Return as signer
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("generated key does not implement crypto.Signer")
	}

	return signer, nil
}

// createAndSignCSR builds and signs the CSR using the provided signer.
func createAndSignCSR(request *CertificateRequest, signer crypto.Signer) ([]byte, error) {
	// Build the CSR template
	template, err := buildCSRTemplate(request)
	if err != nil {
		return nil, err
	}

	// Determine signature algorithm
	sigAlg, err := getSignatureAlgorithm(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCSRGenerationFailed, err)
	}
	template.SignatureAlgorithm = sigAlg

	// Create the CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCSRGenerationFailed, err)
	}

	// Encode to PEM
	return encodeCSRToPEM(csrDER), nil
}

// validateCSRRequest validates that the certificate request has required fields.
func validateCSRRequest(request *CertificateRequest) error {
	if request == nil {
		return fmt.Errorf("%w: request is nil", ErrInvalidCSR)
	}

	if request.Subject.CommonName == "" {
		return ErrSubjectCommonNameRequired
	}

	return nil
}

// buildCSRTemplate creates an x509.CertificateRequest template from the CertificateRequest.
func buildCSRTemplate(request *CertificateRequest) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		Subject: request.Subject.ToPkixName(),
	}

	// Add SANs if present
	if request.SANS != nil {
		if err := addSANsExtension(template, request.SANS); err != nil {
			return nil, err
		}
	}

	return template, nil
}

// addSANsExtension adds Subject Alternative Names to the CSR template.
//
// This function handles:
//   - DNS names (dNSName)
//   - IP addresses (iPAddress)
//   - Email addresses (rfc822Name)
//   - URIs (uniformResourceIdentifier)
//   - Hardware module names (RFC 4108) for TPM/HSM device certificates
//
// The SANs are added as an extension with OID 2.5.29.17.
func addSANsExtension(template *x509.CertificateRequest, sans *SubjectAlternativeNames) error {
	if sans == nil {
		return nil
	}

	// Add standard SANs directly to template
	template.DNSNames = sans.DNS
	template.EmailAddresses = sans.Email

	// Parse and add IPs
	for _, ipStr := range sans.IPs {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		}
	}

	// Parse and add URIs
	for _, uriStr := range sans.URIs {
		u, err := url.Parse(uriStr)
		if err == nil && u.Scheme != "" {
			template.URIs = append(template.URIs, u)
		}
	}

	// Handle hardware module name as custom extension if present
	if sans.HardwareModuleName != nil {
		ext, err := buildHardwareModuleNameExtension(sans.HardwareModuleName)
		if err != nil {
			return fmt.Errorf("failed to build hardware module name extension: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ext)
	}

	return nil
}

// hardwareModuleName is the ASN.1 structure for RFC 4108 hardware module identification.
// HardwareModuleName ::= SEQUENCE {
//
//	hwType OBJECT IDENTIFIER,
//	hwSerialNum OCTET STRING
//
// }
type hardwareModuleName struct {
	HWType         asn1.ObjectIdentifier
	HWSerialNumber []byte
}

// buildHardwareModuleNameExtension creates an X.509 extension for hardware module identification.
//
// This implements RFC 4108 which defines how TPM and HSM devices can be identified
// in certificates. The hardware module name includes:
//   - HWType: OID identifying the hardware type (e.g., 2.23.133.1 for TCG Platform)
//   - HWSerialNumber: Unique serial number of the hardware module
func buildHardwareModuleNameExtension(hwInfo *HardwareModuleInfo) (pkix.Extension, error) {
	// Build the HardwareModuleName ASN.1 structure
	hwName := hardwareModuleName{
		HWType:         hwInfo.HWType,
		HWSerialNumber: []byte(hwInfo.HWSerialNumber),
	}

	// Marshal to ASN.1
	hwNameBytes, err := asn1.Marshal(hwName)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal hardware module name: %w", err)
	}

	// Build the otherName structure for SAN
	// otherName [0] IMPLICIT SEQUENCE {
	//     type-id OBJECT IDENTIFIER,
	//     value [0] EXPLICIT ANY
	// }
	otherName := struct {
		TypeID asn1.ObjectIdentifier
		Value  asn1.RawValue
	}{
		TypeID: oidHardwareModuleName,
		Value: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      hwNameBytes,
		},
	}

	otherNameBytes, err := asn1.MarshalWithParams(otherName, "tag:0")
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal otherName: %w", err)
	}

	// Build GeneralNames sequence containing the otherName
	generalNames, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      otherNameBytes,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal GeneralNames: %w", err)
	}

	return pkix.Extension{
		Id:       oidSubjectAltName,
		Critical: false,
		Value:    generalNames,
	}, nil
}

// getSignatureAlgorithm determines the appropriate signature algorithm based on the public key type.
//
// Mapping:
//   - ECDSA P-256  -> ECDSAWithSHA256
//   - ECDSA P-384  -> ECDSAWithSHA384
//   - ECDSA P-521  -> ECDSAWithSHA512
//   - RSA 2048+    -> SHA256WithRSA
//   - Ed25519      -> PureEd25519
func getSignatureAlgorithm(pubKey crypto.PublicKey) (x509.SignatureAlgorithm, error) {
	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		return getECDSASignatureAlgorithm(key.Curve)

	case *rsa.PublicKey:
		// Use SHA-256 for RSA keys of any size (2048+)
		return x509.SHA256WithRSA, nil

	case ed25519.PublicKey:
		return x509.PureEd25519, nil

	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("%w: unsupported key type %T", ErrInvalidKeyAlgorithm, pubKey)
	}
}

// getECDSASignatureAlgorithm returns the appropriate signature algorithm for an ECDSA curve.
func getECDSASignatureAlgorithm(curve elliptic.Curve) (x509.SignatureAlgorithm, error) {
	if curve == nil {
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("%w: nil curve", ErrInvalidKeyAlgorithm)
	}

	switch curve.Params().BitSize {
	case 224, 256:
		return x509.ECDSAWithSHA256, nil
	case 384:
		return x509.ECDSAWithSHA384, nil
	case 521:
		return x509.ECDSAWithSHA512, nil
	default:
		// Default to SHA256 for unknown curves
		return x509.ECDSAWithSHA256, nil
	}
}

// encodeCSRToPEM encodes a DER-encoded CSR to PEM format.
//
// The returned PEM block has type "CERTIFICATE REQUEST" as specified in RFC 7468.
func encodeCSRToPEM(csrDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
}

// NOTE: ParseCSR and ValidateCSR are defined in signing.go with typed errors
// per CLAUDE.md convention "ALWAYS declare errors as types"
