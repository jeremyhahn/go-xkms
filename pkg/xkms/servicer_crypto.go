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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// kdfFactory provides O(1) dispatch for KDF algorithm selection.
var kdfFactory = map[string]func() kdf.KDFAdapter{
	"hkdf":                      func() kdf.KDFAdapter { return kdf.NewHKDFAdapter() },
	"sp800-108-counter":         func() kdf.KDFAdapter { return kdf.NewSP800108CounterAdapter() },
	"sp800-108-feedback":        func() kdf.KDFAdapter { return kdf.NewSP800108FeedbackAdapter() },
	"sp800-108-double-pipeline": func() kdf.KDFAdapter { return kdf.NewSP800108DoublePipelineAdapter() },
}

// Sign signs data using the specified key.
// For Ed25519 keys, pure signing is used (no pre-hashing).
// For RSA and ECDSA keys, the data is hashed with the specified hash algorithm
// before signing. Implements the CryptoServicer interface.
func (s *XKMSService) Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil sign request"}
	}

	b, _, err := s.resolveBackendWithName(req.Backend)
	if err != nil {
		return nil, err
	}

	attrs, err := findKeyAttrs(b, req.KeyID)
	if err != nil {
		return nil, err
	}

	signer, err := b.Signer(attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrSigningFailed, Detail: "failed to get signer", Err: err}
	}

	// Ed25519 uses pure signing (no pre-hashing)
	if attrs.KeyAlgorithm == x509.Ed25519 {
		sig, signErr := signer.Sign(rand.Reader, req.Data, crypto.Hash(0))
		if signErr != nil {
			return nil, &ErrOperationWrap{Sentinel: ErrSigningFailed, Err: signErr}
		}
		return &transport.SignResponse{
			Signature: sig,
			Algorithm: algorithmString(attrs),
		}, nil
	}

	// For RSA and ECDSA, hash the data first
	h := parseHash(req.Hash)
	hasher := h.New()
	hasher.Write(req.Data)
	digest := hasher.Sum(nil)

	sig, err := signer.Sign(rand.Reader, digest, h)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrSigningFailed, Err: err}
	}

	return &transport.SignResponse{
		Signature: sig,
		Algorithm: algorithmString(attrs),
	}, nil
}

// Verify verifies a signature against data using the specified key.
// For Ed25519 keys, pure verification is used (no pre-hashing).
// For RSA keys, PKCS1v15 verification is used.
// For ECDSA keys, ASN1 verification is used.
// Implements the CryptoServicer interface.
func (s *XKMSService) Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil verify request"}
	}

	b, _, err := s.resolveBackendWithName(req.Backend)
	if err != nil {
		return nil, err
	}

	attrs, err := findKeyAttrs(b, req.KeyID)
	if err != nil {
		return nil, err
	}

	// Get the key and extract public key
	privKey, err := b.GetKey(attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrVerificationFailed, Detail: "failed to get key", Err: err}
	}

	keySigner, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, &ErrOperationWrap{Sentinel: ErrVerificationFailed, Detail: "key does not implement crypto.Signer"}
	}
	pubKey := keySigner.Public()

	// Ed25519 uses pure verification (no pre-hashing)
	if attrs.KeyAlgorithm == x509.Ed25519 {
		edPub, edOK := pubKey.(ed25519.PublicKey)
		if !edOK {
			return nil, &ErrOperationWrap{Sentinel: ErrVerificationFailed, Detail: "invalid Ed25519 public key type"}
		}
		valid := ed25519.Verify(edPub, req.Data, req.Signature)
		return &transport.VerifyResponse{Valid: valid}, nil
	}

	// Hash the data for RSA/ECDSA verification
	h := parseHash(req.Hash)
	hasher := h.New()
	hasher.Write(req.Data)
	digest := hasher.Sum(nil)

	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		verifyErr := rsa.VerifyPKCS1v15(pub, h, digest, req.Signature)
		if verifyErr != nil {
			return &transport.VerifyResponse{
				Valid:   false,
				Message: verifyErr.Error(),
			}, nil
		}
		return &transport.VerifyResponse{Valid: true}, nil

	case *ecdsa.PublicKey:
		valid := ecdsa.VerifyASN1(pub, digest, req.Signature)
		return &transport.VerifyResponse{Valid: valid}, nil

	default:
		return nil, &ErrOperationWrap{
			Sentinel: ErrVerificationFailed,
			Detail:   fmt.Sprintf("unsupported public key type %T", pubKey),
		}
	}
}

// Encrypt encrypts plaintext using a symmetric key.
// The backend must support the SymmetricKeyProvider interface.
// Implements the CryptoServicer interface.
func (s *XKMSService) Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil encrypt request"}
	}

	b, _, err := s.resolveBackendWithName(req.Backend)
	if err != nil {
		return nil, err
	}

	attrs, err := findKeyAttrs(b, req.KeyID)
	if err != nil {
		return nil, err
	}

	symBackend, ok := b.KeyProvider().(types.SymmetricKeyProvider)
	if !ok {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "backend does not support symmetric encryption"}
	}

	encrypter, err := symBackend.SymmetricEncrypter(attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "failed to get symmetric encrypter", Err: err}
	}

	encrypted, err := encrypter.Encrypt(req.Plaintext, &types.EncryptOptions{
		AdditionalData: req.AdditionalData,
	})
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Err: err}
	}

	return &transport.EncryptResponse{
		Ciphertext: encrypted.Ciphertext,
		Nonce:      encrypted.Nonce,
		Tag:        encrypted.Tag,
	}, nil
}

// Decrypt decrypts ciphertext using the specified key.
// For symmetric keys, uses the SymmetricKeyProvider interface.
// For asymmetric keys, uses the crypto.Decrypter interface.
// Implements the CryptoServicer interface.
func (s *XKMSService) Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil decrypt request"}
	}

	b, _, err := s.resolveBackendWithName(req.Backend)
	if err != nil {
		return nil, err
	}

	attrs, err := findKeyAttrs(b, req.KeyID)
	if err != nil {
		return nil, err
	}

	// Try symmetric decryption first
	if symBackend, ok := b.KeyProvider().(types.SymmetricKeyProvider); ok {
		encrypter, symErr := symBackend.SymmetricEncrypter(attrs)
		if symErr == nil {
			plaintext, decErr := encrypter.Decrypt(&types.EncryptedData{
				Ciphertext: req.Ciphertext,
				Nonce:      req.Nonce,
				Tag:        req.Tag,
			}, &types.DecryptOptions{
				AdditionalData: req.AdditionalData,
			})
			if decErr != nil {
				return nil, &ErrOperationWrap{Sentinel: ErrDecryptionFailed, Err: decErr}
			}
			return &transport.DecryptResponse{Plaintext: plaintext}, nil
		}
	}

	// Fall back to asymmetric decryption
	decrypter, err := b.Decrypter(attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrDecryptionFailed, Detail: "failed to get decrypter", Err: err}
	}

	plaintext, err := decrypter.Decrypt(rand.Reader, req.Ciphertext, nil)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrDecryptionFailed, Err: err}
	}

	return &transport.DecryptResponse{Plaintext: plaintext}, nil
}

// EncryptAsym encrypts plaintext using an RSA public key with OAEP padding.
// The key must be an RSA key. Implements the CryptoServicer interface.
func (s *XKMSService) EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil encrypt-asym request"}
	}

	b, _, err := s.resolveBackendWithName(req.Backend)
	if err != nil {
		return nil, err
	}

	attrs, err := findKeyAttrs(b, req.KeyID)
	if err != nil {
		return nil, err
	}

	// Get the key and extract the RSA public key
	privKey, err := b.GetKey(attrs)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "failed to get key", Err: err}
	}

	keySigner, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "key does not implement crypto.Signer"}
	}

	rsaPub, ok := keySigner.Public().(*rsa.PublicKey)
	if !ok {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "key is not RSA, asymmetric encryption requires RSA"}
	}

	// Use the specified hash or default to SHA-256 for OAEP
	h := parseHash(req.Hash)

	ciphertext, err := rsa.EncryptOAEP(h.New(), rand.Reader, rsaPub, req.Plaintext, nil)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrEncryptionFailed, Detail: "RSA OAEP encryption failed", Err: err}
	}

	return &transport.EncryptAsymResponse{
		Ciphertext: ciphertext,
	}, nil
}

// DeriveKey derives a key using the specified KDF algorithm.
// Supports HKDF, SP800-108-COUNTER, SP800-108-FEEDBACK, and SP800-108-DOUBLE-PIPELINE.
// Implements the CryptoServicer interface.
func (s *XKMSService) DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	if req == nil {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "nil derive-key request"}
	}

	algorithm := strings.ToLower(strings.TrimSpace(req.Algorithm))
	if algorithm == "" {
		algorithm = "hkdf"
	}

	factory, ok := kdfFactory[algorithm]
	if !ok {
		return nil, &ErrValidation{Sentinel: ErrOperationNotSupported, Detail: "unsupported KDF algorithm: " + req.Algorithm}
	}

	adapter := factory()

	h := parseHash(req.Hash)

	keyLength := int(req.KeyLength)
	if keyLength <= 0 {
		keyLength = 32
	}

	params := &kdf.KDFParams{
		Algorithm: adapter.Algorithm(),
		Salt:      req.Salt,
		Info:      req.Info,
		KeyLength: keyLength,
		Hash:      h,
		Label:     req.Label,
		Context:   req.Context,
	}

	// Determine input key material
	ikm := req.InputKeyMaterial
	if len(ikm) == 0 {
		return nil, &ErrValidation{Sentinel: ErrInvalidKeyAttributes, Detail: "input key material is required for KDF"}
	}

	derivedKey, err := adapter.DeriveKey(ikm, params)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Detail: "key derivation failed", Err: err}
	}

	return &transport.DeriveKeyResponse{
		DerivedKey: derivedKey,
		Algorithm:  req.Algorithm,
		KeyLength:  len(derivedKey),
	}, nil
}

// DeriveKeyECDH performs ECDH key agreement and derives a key.
// This operation is not yet supported and returns ErrOperationNotSupported.
// Implements the CryptoServicer interface.
func (s *XKMSService) DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return nil, ErrOperationNotSupported
}

// AttestKey returns a cryptographic attestation proving a key resides in hardware.
// This operation requires a hardware-backed backend (TPM2, PKCS#11) and is not
// yet supported at the service layer. Returns ErrOperationNotSupported.
// Implements the CryptoServicer interface.
func (s *XKMSService) AttestKey(ctx context.Context, req *transport.AttestKeyRequest) (*transport.AttestKeyResponse, error) {
	return nil, ErrOperationNotSupported
}
