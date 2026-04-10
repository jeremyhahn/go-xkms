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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/encoding"
	"github.com/jeremyhahn/go-xkms/pkg/encoding/jwe"
	"github.com/jeremyhahn/go-xkms/pkg/encoding/jwt"
)

// PEM encoding/decoding functions re-exported from pkg/encoding.
// These allow SDK consumers to encode and decode PEM data without
// importing internal packages.
var (
	// EncodePublicKeyPEM encodes a public key to PEM format.
	EncodePublicKeyPEM = encoding.EncodePublicKeyPEM

	// DecodePublicKeyPEM decodes PEM encoded data to a public key.
	DecodePublicKeyPEM = encoding.DecodePublicKeyPEM

	// EncodePrivateKeyPEM encodes a private key to PEM format.
	// If a password is provided, the key will be encrypted using PKCS#8.
	EncodePrivateKeyPEM = encoding.EncodePrivateKeyPEM

	// DecodePrivateKeyPEM decodes PEM encoded data to a private key.
	// If the PEM data is encrypted, a password must be provided.
	DecodePrivateKeyPEM = encoding.DecodePrivateKeyPEM

	// EncodeCertificatePEM encodes an X.509 certificate to PEM format.
	EncodeCertificatePEM = encoding.EncodeCertificatePEM

	// DecodeCertificatePEM decodes PEM encoded data to an X.509 certificate.
	DecodeCertificatePEM = encoding.DecodeCertificatePEM

	// EncodeCertificateChainPEM encodes multiple X.509 certificates to PEM format.
	EncodeCertificateChainPEM = encoding.EncodeCertificateChainPEM

	// DecodeCertificateChainPEM decodes PEM encoded data containing multiple certificates.
	DecodeCertificateChainPEM = encoding.DecodeCertificateChainPEM
)

// JWE types re-exported from pkg/encoding/jwe.
// These allow SDK consumers to perform JWE encryption and decryption
// without importing internal packages.
type (
	// JWEEncrypter wraps go-jose encrypter with a simplified API for JWE encryption.
	JWEEncrypter = jwe.Encrypter

	// JWEDecrypter wraps go-jose for JWE decryption.
	JWEDecrypter = jwe.Decrypter
)

// JWE XKMS adapter types re-exported from pkg/encoding/jwe.
// These allow SDK consumers to perform JWE operations using XKMS-managed
// keys without importing internal packages.
type (
	// JWEXKMSEncrypter wraps a JWE encrypter that resolves recipient keys
	// via an XKMS key getter callback.
	JWEXKMSEncrypter = jwe.XKMSEncrypter

	// JWEXKMSDecrypter wraps a JWE decrypter that resolves decryption keys
	// via an XKMS decrypter getter callback.
	JWEXKMSDecrypter = jwe.XKMSDecrypter
)

// JWE constructor and utility functions re-exported from pkg/encoding/jwe.
var (
	// NewJWEEncrypter creates a new JWE encrypter with the specified algorithms.
	// Parameters: keyEncAlg, encAlg string, recipientKey interface{}.
	// An empty encAlg enables auto-detection of the optimal AEAD algorithm.
	NewJWEEncrypter = jwe.NewEncrypter

	// NewJWEDecrypter creates a new JWE decrypter.
	NewJWEDecrypter = jwe.NewDecrypter

	// NewJWEXKMSEncrypter creates a new JWE encrypter that resolves recipient
	// keys via an XKMS key getter callback.
	NewJWEXKMSEncrypter = jwe.NewXKMSEncrypter

	// NewJWEXKMSDecrypter creates a new JWE decrypter that resolves decryption
	// keys via an XKMS decrypter getter callback.
	NewJWEXKMSDecrypter = jwe.NewXKMSDecrypter

	// ExtractJWEKID extracts the Key ID (kid) from a JWE header without decrypting.
	ExtractJWEKID = jwe.ExtractKID
)

// JWT types re-exported from pkg/encoding/jwt.
// These allow SDK consumers to sign and verify JWTs without importing
// internal packages.
type (
	// JWTAlgorithm represents supported JWT signing algorithms.
	JWTAlgorithm = jwt.Algorithm

	// JWTSigner signs JWT tokens using cryptographic keys.
	JWTSigner = jwt.Signer

	// JWTVerifier verifies JWT tokens.
	JWTVerifier = jwt.Verifier

	// JWTVerifyOptions contains options for JWT verification.
	JWTVerifyOptions = jwt.VerifyOptions

	// JWTXKMSSigner signs JWT tokens using XKMS-managed keys via callback
	// functions for key and signer retrieval. This allows hardware-backed
	// keys (HSM, TPM, cloud KMS) to sign JWTs transparently.
	JWTXKMSSigner = jwt.XKMSSigner

	// JWTXKMSVerifier verifies JWT tokens using XKMS-managed keys via a
	// callback function for key retrieval.
	JWTXKMSVerifier = jwt.XKMSVerifier
)

// JWT algorithm constants re-exported from pkg/encoding/jwt.
const (
	JWTRS256 JWTAlgorithm = jwt.RS256 // RSASSA-PKCS1-v1_5 using SHA-256
	JWTRS384 JWTAlgorithm = jwt.RS384 // RSASSA-PKCS1-v1_5 using SHA-384
	JWTRS512 JWTAlgorithm = jwt.RS512 // RSASSA-PKCS1-v1_5 using SHA-512
	JWTES256 JWTAlgorithm = jwt.ES256 // ECDSA using P-256 and SHA-256
	JWTES384 JWTAlgorithm = jwt.ES384 // ECDSA using P-384 and SHA-384
	JWTES512 JWTAlgorithm = jwt.ES512 // ECDSA using P-521 and SHA-512
	JWTEdDSA JWTAlgorithm = jwt.EdDSA // EdDSA signature algorithms
	JWTPS256 JWTAlgorithm = jwt.PS256 // RSASSA-PSS using SHA-256
	JWTPS384 JWTAlgorithm = jwt.PS384 // RSASSA-PSS using SHA-384
	JWTPS512 JWTAlgorithm = jwt.PS512 // RSASSA-PSS using SHA-512
)

// JWT constructor and utility functions re-exported from pkg/encoding/jwt.
var (
	// NewJWTSigningMethodSigner creates a jwt.SigningMethod from key attributes.
	NewJWTSigningMethodSigner = jwt.NewSigningMethodSigner

	// NewJWTSigner creates a new JWT signer.
	NewJWTSigner = jwt.NewSigner

	// NewJWTVerifier creates a new JWT verifier.
	NewJWTVerifier = jwt.NewVerifier

	// NewJWTXKMSSigner creates a new JWT signer backed by XKMS-managed keys.
	// The getKey callback retrieves private keys and the getSigner callback
	// retrieves crypto.Signer instances by key ID.
	NewJWTXKMSSigner = jwt.NewXKMSSigner

	// NewJWTXKMSVerifier creates a new JWT verifier backed by XKMS-managed keys.
	// The getKey callback retrieves private keys by key ID for public key extraction.
	NewJWTXKMSVerifier = jwt.NewXKMSVerifier

	// ExtractJWTKID extracts the Key ID (kid) from a JWT token header
	// without verifying the signature.
	ExtractJWTKID = jwt.ExtractKID

	// ParseJWTAlgorithm converts an algorithm string to a JWTAlgorithm type.
	ParseJWTAlgorithm = jwt.ParseAlgorithm
)
