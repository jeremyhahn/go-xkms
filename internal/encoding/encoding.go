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

// Package encoding provides cryptographic key encoding and decoding utilities.
//
// This package supports PEM and DER encoding formats for public and private keys,
// with support for password-protected private keys using PKCS#8 format. It handles
// RSA, ECDSA, and Ed25519 key types from the standard library.
package encoding

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-keychain/internal/password"
	"github.com/youmark/pkcs8"
)

var (
	// ErrInvalidEncodingPEM is returned when PEM decoding fails.
	ErrInvalidEncodingPEM = errors.New("invalid PEM encoding")

	// ErrInvalidPassword is returned when the password is incorrect.
	ErrInvalidPassword = errors.New("invalid password")

	// ErrInvalidKeyType is returned when an unsupported key type is provided.
	ErrInvalidKeyType = errors.New("invalid key type")

	// ErrUnsupportedKeyAlgorithm is returned when an unsupported key algorithm is provided.
	ErrUnsupportedKeyAlgorithm = errors.New("unsupported key algorithm")
)

// KeyAlgorithm represents the type of key algorithm.
type KeyAlgorithm int

const (
	// RSA represents the RSA key algorithm.
	RSA KeyAlgorithm = iota
	// ECDSA represents the ECDSA key algorithm.
	ECDSA
	// Ed25519 represents the Ed25519 key algorithm.
	Ed25519
)

// String returns the string representation of the key algorithm.
func (k KeyAlgorithm) String() string {
	switch k {
	case RSA:
		return "RSA"
	case ECDSA:
		return "ECDSA"
	case Ed25519:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

// EncodePrivateKey encodes a private key to ASN.1 DER PKCS#8 format.
//
// If a password is provided, the key will be encrypted using PKCS#8.
// If password is nil, the key will be encoded without encryption.
func EncodePrivateKey(privateKey crypto.PrivateKey, pwd password.Password) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}

	var passwordBytes []byte
	var err error
	if pwd != nil {
		passwordBytes, err = pwd.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get password bytes: %w", err)
		}
		defer func() {
			// Zero the password bytes after use
			for i := range passwordBytes {
				passwordBytes[i] = 0
			}
		}()
	}

	pkcs8Data, err := pkcs8.MarshalPrivateKey(privateKey, passwordBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return pkcs8Data, nil
}

// EncodePrivateKeyPEM encodes a private key to PEM format.
//
// The PEM block type is determined by the key type and whether encryption is used:
// - Encrypted keys use "ENCRYPTED PRIVATE KEY"
// - Unencrypted RSA keys use "RSA PRIVATE KEY"
// - Unencrypted ECDSA/Ed25519 keys use "PRIVATE KEY"
func EncodePrivateKeyPEM(privateKey crypto.PrivateKey, pwd password.Password) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}

	// Determine key algorithm
	keyAlg, err := detectKeyAlgorithm(privateKey)
	if err != nil {
		return nil, err
	}

	// Encode to DER format
	der, err := EncodePrivateKey(privateKey, pwd)
	if err != nil {
		return nil, err
	}

	// Determine PEM block type
	var blockType string
	if pwd != nil {
		blockType = "ENCRYPTED PRIVATE KEY"
	} else {
		switch keyAlg {
		case RSA:
			blockType = "RSA PRIVATE KEY"
		case ECDSA, Ed25519:
			blockType = "PRIVATE KEY"
		default:
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedKeyAlgorithm, keyAlg)
		}
	}

	// Encode to PEM
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{
		Type:  blockType,
		Bytes: der,
	}); err != nil {
		return nil, fmt.Errorf("failed to encode PEM: %w", err)
	}

	return buf.Bytes(), nil
}

// DecodePrivateKeyPEM decodes a PEM encoded private key.
//
// The password parameter is required for encrypted keys and should be nil
// for unencrypted keys. Returns an error if the password is incorrect or
// if the PEM data is invalid.
func DecodePrivateKeyPEM(pemData []byte, pwd password.Password) (crypto.PrivateKey, error) {
	if len(pemData) == 0 {
		return nil, errors.New("PEM data cannot be empty")
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidEncodingPEM
	}

	var passwordBytes []byte
	if pwd != nil {
		var err error
		passwordBytes, err = pwd.Bytes()
		if err != nil {
			return nil, fmt.Errorf("failed to get password bytes: %w", err)
		}
		defer func() {
			// Zero the password bytes after use
			for i := range passwordBytes {
				passwordBytes[i] = 0
			}
		}()
	}

	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, passwordBytes)
	if err != nil {
		if strings.Contains(err.Error(), "pkcs8: incorrect password") {
			return nil, ErrInvalidPassword
		}
		// The PKCS8 package doesn't always return "incorrect password",
		// sometimes this ASN.1 error is given when it fails to parse the
		// private key because it's encrypted and the password is incorrect.
		if strings.Contains(err.Error(), "asn1: structure error: tags don't match") {
			return nil, ErrInvalidPassword
		}
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	privateKey, ok := key.(crypto.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	return privateKey, nil
}

// EncodePublicKey encodes a public key to ASN.1 DER PKIX format.
func EncodePublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("public key cannot be nil")
	}

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return der, nil
}

// EncodePublicKeyPEM encodes a public key to PEM format.
func EncodePublicKeyPEM(publicKey crypto.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("public key cannot be nil")
	}

	der, err := EncodePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}); err != nil {
		return nil, fmt.Errorf("failed to encode PEM: %w", err)
	}

	return buf.Bytes(), nil
}

// EncodeDERToPEM encodes ASN.1 DER formatted data to PEM format.
//
// This is a convenience function for converting DER encoded public keys to PEM.
func EncodeDERToPEM(der []byte) ([]byte, error) {
	if len(der) == 0 {
		return nil, errors.New("DER data cannot be empty")
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}); err != nil {
		return nil, fmt.Errorf("failed to encode PEM: %w", err)
	}

	return buf.Bytes(), nil
}

// DecodePublicKeyPEM decodes a PEM encoded public key.
func DecodePublicKeyPEM(pemData []byte) (crypto.PublicKey, error) {
	if len(pemData) == 0 {
		return nil, errors.New("PEM data cannot be empty")
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidEncodingPEM
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return publicKey.(crypto.PublicKey), nil
}

// detectKeyAlgorithm determines the key algorithm from a private key.
func detectKeyAlgorithm(key crypto.PrivateKey) (KeyAlgorithm, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return RSA, nil
	case *ecdsa.PrivateKey:
		return ECDSA, nil
	case ed25519.PrivateKey:
		return Ed25519, nil
	default:
		return 0, fmt.Errorf("%w: %T", ErrInvalidKeyType, key)
	}
}

// ExtractPublicKey extracts the public key from a private key.
func ExtractPublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		return key.Public(), nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrInvalidKeyType, key)
	}
}
