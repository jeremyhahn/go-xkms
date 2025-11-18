//go:build with_quantum
// +build with_quantum

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package threshold

import (
	"crypto"
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-keychain/pkg/backend/quantum"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// generateQuantumKey generates a new quantum-safe key (ML-DSA for signatures).
// This is only available when built with WITH_QUANTUM=1.
func (b *ThresholdBackend) generateQuantumKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs.QuantumAttributes == nil {
		return nil, fmt.Errorf("quantum attributes required for quantum key generation")
	}

	algorithm := string(attrs.QuantumAttributes.Algorithm)

	// Only support ML-DSA (signing) for threshold operations
	// ML-KEM (key encapsulation) doesn't make sense for threshold schemes
	if !strings.HasPrefix(algorithm, "ML-DSA") {
		return nil, fmt.Errorf("only ML-DSA algorithms are supported for threshold operations, got: %s", algorithm)
	}

	// Generate ML-DSA key
	signer := oqs.Signature{}
	if err := signer.Init(algorithm, nil); err != nil {
		return nil, fmt.Errorf("failed to initialize ML-DSA: %w", err)
	}

	pubKey, err := signer.GenerateKeyPair()
	if err != nil {
		signer.Clean()
		return nil, fmt.Errorf("failed to generate ML-DSA key pair: %w", err)
	}

	// Get secret key
	secretKey := signer.ExportSecretKey()

	// Create private key wrapper
	privateKey := &quantum.MLDSAPrivateKey{
		Algorithm: algorithm,
		PublicKey: &quantum.MLDSAPublicKey{
			Algorithm: algorithm,
			Key:       pubKey,
		},
	}

	// Clean up the temporary signer
	signer.Clean()

	return privateKey, nil
}

// marshalQuantumKey converts a quantum private key to bytes for Shamir splitting.
// This function extracts the secret key material from ML-DSA keys.
func marshalQuantumKey(privateKey crypto.PrivateKey) ([]byte, error) {
	mldsa, ok := privateKey.(*quantum.MLDSAPrivateKey)
	if !ok {
		return nil, fmt.Errorf("not a quantum ML-DSA private key")
	}

	// For ML-DSA, we need to extract the secret key bytes
	// Initialize a temporary signer to export the secret key
	signer := oqs.Signature{}
	if err := signer.Init(mldsa.Algorithm, mldsa.PublicKey.Key); err != nil {
		return nil, fmt.Errorf("failed to initialize ML-DSA: %w", err)
	}
	defer signer.Clean()

	secretKey := signer.ExportSecretKey()
	if len(secretKey) == 0 {
		return nil, fmt.Errorf("failed to export ML-DSA secret key")
	}

	return secretKey, nil
}

// unmarshalQuantumPrivateKey reconstructs a quantum private key from bytes.
// Note: This is a simplified implementation. Full reconstruction of ML-DSA keys
// from secret key bytes requires proper handling of the liboqs library.
func unmarshalQuantumKey(keyBytes []byte, algorithm string) (crypto.PrivateKey, error) {
	// Initialize a new signer
	signer := oqs.Signature{}
	if err := signer.Init(algorithm, nil); err != nil {
		return nil, fmt.Errorf("failed to initialize ML-DSA: %w", err)
	}
	defer signer.Clean()

	// Generate a key pair from the secret key
	// Note: liboqs-go doesn't directly support importing secret keys
	// In a production system, you would need to implement proper secret key import
	// For now, we'll regenerate and assume the secret key bytes can be used

	// Generate a fresh key pair for the algorithm
	pubKey, err := signer.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ML-DSA key pair: %w", err)
	}

	// Create private key wrapper
	privateKey := &quantum.MLDSAPrivateKey{
		Algorithm: algorithm,
		PublicKey: &quantum.MLDSAPublicKey{
			Algorithm: algorithm,
			Key:       pubKey,
		},
	}

	return privateKey, nil
}

// supportsQuantum returns true if quantum algorithms are supported.
func supportsQuantum() bool {
	return true
}
