// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package threshold

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-keychain/pkg/threshold/shamir"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// ThresholdSigner implements crypto.Signer for threshold signing operations.
// It coordinates with other nodes to perform distributed signing.
//
// For now, this implementation collects M shares from storage and reconstructs
// the key locally. In a production distributed CA, this would use a multi-round
// signing protocol (e.g., threshold ECDSA) without reconstructing the full key.
type ThresholdSigner struct {
	backend *ThresholdBackend
	attrs   *types.KeyAttributes
	share   *shamir.Share
}

// Public returns the public key corresponding to the threshold key.
// This requires reconstructing the key from M shares.
func (s *ThresholdSigner) Public() crypto.PublicKey {
	// Reconstruct the full key to get public key
	privKey, err := s.reconstructKey()
	if err != nil {
		// Can't return error from Public(), return nil
		// This is a limitation of the crypto.Signer interface
		return nil
	}

	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	case ed25519.PrivateKey:
		return key.Public()
	default:
		return nil
	}
}

// Sign performs threshold signing on the digest.
// This collects M shares from storage, reconstructs the key, and signs.
//
// In a production distributed CA, this would:
// 1. Broadcast signing request to all N participants
// 2. Collect M signature shares
// 3. Combine signature shares into final signature
// 4. Never reconstruct the full private key
func (s *ThresholdSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Reconstruct the full key from shares
	privKey, err := s.reconstructKey()
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct key: %w", err)
	}

	// Sign using the reconstructed key
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		return key.Sign(rand, digest, opts)
	case *ecdsa.PrivateKey:
		return key.Sign(rand, digest, opts)
	case ed25519.PrivateKey:
		return key.Sign(rand, digest, opts)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", privKey)
	}
}

// reconstructKey collects M shares from storage and reconstructs the private key.
// This is used for local testing and development.
//
// TODO: Replace with distributed signing protocol for production use.
func (s *ThresholdSigner) reconstructKey() (crypto.PrivateKey, error) {
	threshold := s.attrs.ThresholdAttributes.Threshold

	// Collect M shares from storage
	shares := make([]*shamir.Share, 0, threshold)

	// Start with our own share
	shares = append(shares, s.share)

	// Load additional shares until we have M
	keyID := s.backend.getKeyID(s.attrs)
	for i := 1; i <= s.attrs.ThresholdAttributes.Total && len(shares) < threshold; i++ {
		if i == s.share.Index {
			continue // Skip our own share (already added)
		}

		shareKey := fmt.Sprintf("threshold/shares/%s/share-%d", keyID, i)
		data, err := s.backend.config.ShareStorage.Get(shareKey)
		if err != nil {
			continue // Share not available, try next one
		}

		var share shamir.Share
		if err := json.Unmarshal(data, &share); err != nil {
			continue // Corrupted share, try next one
		}

		if err := share.Validate(); err != nil {
			continue // Invalid share, try next one
		}

		shares = append(shares, &share)
	}

	// Check if we have enough shares
	if len(shares) < threshold {
		return nil, &InsufficientSharesError{
			Have:      len(shares),
			Threshold: threshold,
		}
	}

	// Combine shares to reconstruct key
	keyBytes, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shares: %w", err)
	}

	// Unmarshal the reconstructed key
	return s.unmarshalPrivateKey(keyBytes)
}

// unmarshalPrivateKey converts bytes back to a private key.
func (s *ThresholdSigner) unmarshalPrivateKey(keyBytes []byte) (crypto.PrivateKey, error) {
	// Try quantum key unmarshaling first if quantum attributes are set
	if s.attrs.QuantumAttributes != nil && supportsQuantum() {
		algorithm := string(s.attrs.QuantumAttributes.Algorithm)
		return unmarshalQuantumKey(keyBytes, algorithm)
	}

	switch s.attrs.KeyAlgorithm {
	case x509.RSA:
		return x509.ParsePKCS1PrivateKey(keyBytes)
	case x509.ECDSA:
		return x509.ParseECPrivateKey(keyBytes)
	case x509.Ed25519:
		if len(keyBytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid Ed25519 key size: got %d, want %d",
				len(keyBytes), ed25519.PrivateKeySize)
		}
		return ed25519.PrivateKey(keyBytes), nil
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", s.attrs.KeyAlgorithm)
	}
}
