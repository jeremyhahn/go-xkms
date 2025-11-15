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

package encoding

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// PEM block types
const (
	PEMTypeRSAPrivateKey       = "RSA PRIVATE KEY"
	PEMTypeECPrivateKey        = "EC PRIVATE KEY"
	PEMTypePrivateKey          = "PRIVATE KEY"
	PEMTypeEncryptedPrivateKey = "ENCRYPTED PRIVATE KEY"
	PEMTypePublicKey           = "PUBLIC KEY"
	PEMTypeCertificate         = "CERTIFICATE"
	PEMTypeCertificateRequest  = "CERTIFICATE REQUEST"
)

// EncodePrivateKeyPEM encodes a private key to PEM format.
// If a password is provided, the key will be encrypted using PKCS#8.
// If password is nil or empty, the key will be encoded without encryption.
//
// The keyAlgorithm parameter helps determine the PEM block type:
//   - x509.RSA: Uses "RSA PRIVATE KEY" (unencrypted) or "ENCRYPTED PRIVATE KEY" (encrypted)
//   - x509.ECDSA: Uses "EC PRIVATE KEY" (unencrypted) or "ENCRYPTED PRIVATE KEY" (encrypted)
//   - x509.Ed25519: Uses "PRIVATE KEY" (unencrypted) or "ENCRYPTED PRIVATE KEY" (encrypted)
//
// Example:
//
//	pemData, err := encoding.EncodePrivateKeyPEM(privateKey, x509.RSA, []byte("password"))
func EncodePrivateKeyPEM(privateKey crypto.PrivateKey, keyAlgorithm x509.PublicKeyAlgorithm, password []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}

	// Encode to PKCS#8 DER first
	der, err := EncodePKCS8(privateKey, password)
	if err != nil {
		return nil, err
	}

	// Determine PEM block type
	blockType := getPEMBlockType(keyAlgorithm, password)

	// Create PEM block
	block := &pem.Block{
		Type:  blockType,
		Bytes: der,
	}

	// Encode to PEM
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, fmt.Errorf("failed to encode PEM: %w", err)
	}

	return buf.Bytes(), nil
}

// DecodePrivateKeyPEM decodes PEM encoded data to a private key.
// If the PEM data is encrypted, a password must be provided.
//
// Returns the private key as crypto.PrivateKey (type assert to specific type if needed).
//
// Example:
//
//	key, err := encoding.DecodePrivateKeyPEM(pemData, []byte("password"))
//	rsaKey := key.(*rsa.PrivateKey)
func DecodePrivateKeyPEM(data []byte, password []byte) (crypto.PrivateKey, error) {
	if len(data) == 0 {
		return nil, ErrInvalidData
	}

	// Decode PEM block
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPEMEncoding
	}

	// Decode PKCS#8 DER
	return DecodePKCS8(block.Bytes, password)
}

// EncodePublicKeyPEM encodes a public key to PEM format.
//
// Example:
//
//	pemData, err := encoding.EncodePublicKeyPEM(publicKey)
func EncodePublicKeyPEM(publicKey crypto.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	// Encode to PKIX DER
	der, err := EncodePublicKeyPKIX(publicKey)
	if err != nil {
		return nil, err
	}

	// Create PEM block
	block := &pem.Block{
		Type:  PEMTypePublicKey,
		Bytes: der,
	}

	// Encode to PEM
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, fmt.Errorf("failed to encode PEM: %w", err)
	}

	return buf.Bytes(), nil
}

// DecodePublicKeyPEM decodes PEM encoded data to a public key.
//
// Returns the public key as crypto.PublicKey (type assert to specific type if needed).
//
// Example:
//
//	key, err := encoding.DecodePublicKeyPEM(pemData)
//	rsaPub := key.(*rsa.PublicKey)
func DecodePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	if len(data) == 0 {
		return nil, ErrInvalidData
	}

	// Decode PEM block
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPEMEncoding
	}

	// Decode PKIX DER
	return DecodePublicKeyPKIX(block.Bytes)
}

// EncodeCertificatePEM encodes an X.509 certificate to PEM format.
//
// Example:
//
//	pemData, err := encoding.EncodeCertificatePEM(cert)
func EncodeCertificatePEM(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, ErrInvalidCertificate
	}

	// Create PEM block from certificate's Raw bytes
	block := &pem.Block{
		Type:  PEMTypeCertificate,
		Bytes: cert.Raw,
	}

	// Encode to PEM
	var buf bytes.Buffer
	if err := pem.Encode(&buf, block); err != nil {
		return nil, fmt.Errorf("failed to encode certificate PEM: %w", err)
	}

	return buf.Bytes(), nil
}

// DecodeCertificatePEM decodes PEM encoded data to an X.509 certificate.
//
// Example:
//
//	cert, err := encoding.DecodeCertificatePEM(pemData)
func DecodeCertificatePEM(data []byte) (*x509.Certificate, error) {
	if len(data) == 0 {
		return nil, ErrInvalidData
	}

	// Decode PEM block
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrInvalidPEMEncoding
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// EncodeCertificateChainPEM encodes multiple X.509 certificates to PEM format.
// The certificates are concatenated in order (typically leaf to root).
//
// Example:
//
//	pemData, err := encoding.EncodeCertificateChainPEM(certChain)
func EncodeCertificateChainPEM(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, ErrInvalidCertificate
	}

	var buf bytes.Buffer

	for _, cert := range certs {
		if cert == nil {
			return nil, ErrInvalidCertificate
		}

		block := &pem.Block{
			Type:  PEMTypeCertificate,
			Bytes: cert.Raw,
		}

		if err := pem.Encode(&buf, block); err != nil {
			return nil, fmt.Errorf("failed to encode certificate chain PEM: %w", err)
		}
	}

	return buf.Bytes(), nil
}

// DecodeCertificateChainPEM decodes PEM encoded data containing multiple certificates.
// Returns all certificates found in the PEM data in order.
//
// Example:
//
//	certs, err := encoding.DecodeCertificateChainPEM(pemData)
func DecodeCertificateChainPEM(data []byte) ([]*x509.Certificate, error) {
	if len(data) == 0 {
		return nil, ErrInvalidData
	}

	var certs []*x509.Certificate
	remaining := data

	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate in chain: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, ErrInvalidPEMEncoding
	}

	return certs, nil
}

// getPEMBlockType determines the appropriate PEM block type based on key algorithm and encryption
func getPEMBlockType(keyAlgorithm x509.PublicKeyAlgorithm, password []byte) string {
	// If encrypted, always use ENCRYPTED PRIVATE KEY
	if len(password) > 0 {
		return PEMTypeEncryptedPrivateKey
	}

	// Unencrypted - use algorithm-specific types
	switch keyAlgorithm {
	case x509.RSA:
		return PEMTypeRSAPrivateKey
	case x509.ECDSA:
		return PEMTypeECPrivateKey
	case x509.Ed25519:
		return PEMTypePrivateKey
	default:
		return PEMTypePrivateKey
	}
}
