// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package threshold

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// generateQuantumKey generates a new quantum-safe ML-DSA key for threshold operations.
// The returned private key implements crypto.Signer and can be used directly for signing.
// The key is generated deterministically from a random 32-byte seed using circl's
// NewKeyFromSeed, which produces the same keypair for the same seed.
func (b *ThresholdBackend) generateQuantumKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if attrs.QuantumAttributes == nil {
		return nil, fmt.Errorf("quantum attributes required for quantum key generation")
	}

	algorithm := string(attrs.QuantumAttributes.Algorithm)

	// Only support ML-DSA (signing) for threshold operations.
	// ML-KEM (key encapsulation) is not meaningful for threshold schemes.
	if !strings.HasPrefix(algorithm, "ML-DSA") {
		return nil, fmt.Errorf("only ML-DSA algorithms are supported for threshold operations, got: %s", algorithm)
	}

	// Generate a random 32-byte seed. SeedSize is 32 for all ML-DSA levels.
	var seed [mldsa44.SeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return nil, fmt.Errorf("failed to generate seed: %w", err)
	}

	switch algorithm {
	case "ML-DSA-44":
		_, sk := mldsa44.NewKeyFromSeed(&seed)
		return sk, nil
	case "ML-DSA-65":
		_, sk := mldsa65.NewKeyFromSeed(&seed)
		return sk, nil
	case "ML-DSA-87":
		_, sk := mldsa87.NewKeyFromSeed(&seed)
		return sk, nil
	default:
		return nil, fmt.Errorf("unsupported ML-DSA algorithm: %s", algorithm)
	}
}

// marshalQuantumKey converts a quantum ML-DSA private key to bytes for Shamir splitting.
// The expanded private key bytes are returned, which can be split into shares and
// later recombined via unmarshalQuantumKey.
func marshalQuantumKey(privateKey crypto.PrivateKey) ([]byte, error) {
	switch sk := privateKey.(type) {
	case *mldsa44.PrivateKey:
		return sk.Bytes(), nil
	case *mldsa65.PrivateKey:
		return sk.Bytes(), nil
	case *mldsa87.PrivateKey:
		return sk.Bytes(), nil
	default:
		return nil, fmt.Errorf("not a quantum ML-DSA private key: %T", privateKey)
	}
}

// unmarshalQuantumKey reconstructs a quantum ML-DSA private key from its serialized bytes.
// The algorithm parameter determines which ML-DSA security level to use for deserialization.
func unmarshalQuantumKey(keyBytes []byte, algorithm string) (crypto.PrivateKey, error) {
	switch algorithm {
	case "ML-DSA-44":
		var sk mldsa44.PrivateKey
		if err := sk.UnmarshalBinary(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ML-DSA-44 key: %w", err)
		}
		return &sk, nil
	case "ML-DSA-65":
		var sk mldsa65.PrivateKey
		if err := sk.UnmarshalBinary(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ML-DSA-65 key: %w", err)
		}
		return &sk, nil
	case "ML-DSA-87":
		var sk mldsa87.PrivateKey
		if err := sk.UnmarshalBinary(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal ML-DSA-87 key: %w", err)
		}
		return &sk, nil
	default:
		return nil, fmt.Errorf("unsupported ML-DSA algorithm: %s", algorithm)
	}
}

// supportsQuantum returns true indicating that quantum algorithms are available.
// With circl, quantum support is always compiled in without requiring CGO or
// external libraries.
func supportsQuantum() bool {
	return true
}
