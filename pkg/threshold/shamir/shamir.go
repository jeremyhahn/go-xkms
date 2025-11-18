// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

// Package shamir implements Shamir's Secret Sharing scheme for splitting secrets
// into N shares where any M shares can reconstruct the original secret.
//
// This package wraps the sssa-golang library with a clean API that integrates
// with the go-keychain architecture.
package shamir

import (
	"encoding/base64"
	"fmt"

	"github.com/SSSaaS/sssa-golang"
)

// Split divides a secret into N shares where any M shares can reconstruct it.
// The secret is encoded as a hexadecimal string internally by sssa-golang.
//
// Parameters:
//   - secret: The secret data to split
//   - threshold: Minimum number of shares needed to reconstruct (M)
//   - total: Total number of shares to create (N)
//
// Returns:
//   - shares: Array of N shares
//   - error: Any error that occurred during splitting
//
// Example:
//
//	secret := []byte("my secret key")
//	shares, err := shamir.Split(secret, 3, 5)
//	// Creates 5 shares, any 3 can reconstruct the secret
func Split(secret []byte, threshold, total int) ([]*Share, error) {
	// Validate parameters
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2, got %d", threshold)
	}
	if total < threshold {
		return nil, fmt.Errorf("total shares (%d) must be >= threshold (%d)", total, threshold)
	}
	if threshold > 255 {
		return nil, fmt.Errorf("threshold cannot exceed 255, got %d", threshold)
	}
	if total > 255 {
		return nil, fmt.Errorf("total shares cannot exceed 255, got %d", total)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	// Convert secret to hex string for sssa-golang
	secretHex := fmt.Sprintf("%x", secret)

	// Split using sssa-golang
	shareStrings, err := sssa.Create(threshold, total, secretHex)
	if err != nil {
		return nil, fmt.Errorf("failed to split secret: %w", err)
	}

	// Convert to Share objects
	shares := make([]*Share, len(shareStrings))
	for i, shareStr := range shareStrings {
		shares[i] = &Share{
			Index:     i + 1, // 1-indexed for human readability
			Threshold: threshold,
			Total:     total,
			Value:     base64.StdEncoding.EncodeToString([]byte(shareStr)),
			Metadata:  make(map[string]string),
		}
	}

	return shares, nil
}

// Combine reconstructs the original secret from M or more shares.
// Any subset of M shares from the original N shares can be used.
//
// Parameters:
//   - shares: Array of at least M shares
//
// Returns:
//   - secret: The reconstructed secret
//   - error: Any error that occurred during reconstruction
//
// Example:
//
//	// Reconstruct secret from any 3 of the 5 shares
//	secret, err := shamir.Combine([]*Share{shares[0], shares[2], shares[4]})
func Combine(shares []*Share) ([]byte, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}

	// Validate all shares
	threshold := shares[0].Threshold
	total := shares[0].Total

	for i, share := range shares {
		if err := share.Validate(); err != nil {
			return nil, fmt.Errorf("invalid share %d: %w", i, err)
		}
		if share.Threshold != threshold {
			return nil, fmt.Errorf("share %d has different threshold (%d) than share 0 (%d)",
				i, share.Threshold, threshold)
		}
		if share.Total != total {
			return nil, fmt.Errorf("share %d has different total (%d) than share 0 (%d)",
				i, share.Total, total)
		}
	}

	// Check minimum shares
	if len(shares) < threshold {
		return nil, fmt.Errorf("need at least %d shares, got %d", threshold, len(shares))
	}

	// Convert Share objects to strings for sssa-golang
	shareStrings := make([]string, len(shares))
	for i, share := range shares {
		decoded, err := base64.StdEncoding.DecodeString(share.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to decode share %d: %w", i, err)
		}
		shareStrings[i] = string(decoded)
	}

	// Combine using sssa-golang
	secretHex, err := sssa.Combine(shareStrings)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shares: %w", err)
	}

	// Convert hex string back to bytes
	secret := make([]byte, len(secretHex)/2)
	for i := 0; i < len(secretHex); i += 2 {
		var b byte
		_, err := fmt.Sscanf(secretHex[i:i+2], "%02x", &b)
		if err != nil {
			return nil, fmt.Errorf("failed to parse hex secret: %w", err)
		}
		secret[i/2] = b
	}

	return secret, nil
}

// VerifyShare checks if a share is valid and consistent with other shares.
// This is useful for detecting corrupted or tampered shares.
func VerifyShare(share *Share, otherShares []*Share) error {
	if err := share.Validate(); err != nil {
		return err
	}

	// Check consistency with other shares
	for i, other := range otherShares {
		if other.Threshold != share.Threshold {
			return fmt.Errorf("share threshold mismatch with share %d: %d != %d",
				i, other.Threshold, share.Threshold)
		}
		if other.Total != share.Total {
			return fmt.Errorf("share total mismatch with share %d: %d != %d",
				i, other.Total, share.Total)
		}
		if other.Index == share.Index {
			return fmt.Errorf("duplicate share index: %d", share.Index)
		}
	}

	return nil
}
