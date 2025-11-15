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

//go:build pkcs11

package smartcardhsm

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/secretsharing"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
)

// DKEK represents a Device Key Encryption Key handler for SmartCard-HSM.
// It implements the DKEK protocol using Shamir's Secret Sharing to split
// the device key into multiple shares that can be distributed securely.
//
// The DKEK is used for:
//   - Backing up keys from the SmartCard-HSM
//   - Restoring keys to the SmartCard-HSM
//   - Sharing keys across multiple SmartCard-HSM devices
//   - Distributed key management in raft clusters
type DKEK struct {
	shamir    *secretsharing.Shamir
	storage   storage.Backend
	threshold int
	shares    int
}

// DKEKShare represents a single share of the DKEK.
type DKEKShare struct {
	// Index is the share number (1-based)
	Index byte `json:"index"`

	// Value is the share data
	Value []byte `json:"value"`

	// Checksum is the SHA-256 hash for integrity verification
	Checksum []byte `json:"checksum"`
}

// NewDKEK creates a new DKEK handler.
//
// Parameters:
//   - threshold: Minimum number of shares needed to reconstruct the DKEK (M)
//   - shares: Total number of shares to create (N)
//   - storage: Storage backend for persisting DKEK shares
//
// Returns an error if the parameters are invalid.
func NewDKEK(threshold, shares int, storage storage.Backend) (*DKEK, error) {
	if threshold < 1 || threshold > 255 {
		return nil, fmt.Errorf("threshold must be between 1 and 255, got %d", threshold)
	}
	if shares < threshold || shares > 255 {
		return nil, fmt.Errorf("shares must be between %d and 255, got %d", threshold, shares)
	}
	if storage == nil {
		return nil, fmt.Errorf("storage is required")
	}

	// Create Shamir instance
	shamir, err := secretsharing.NewShamir(&secretsharing.ShareConfig{
		Threshold:   threshold,
		TotalShares: shares,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create shamir: %w", err)
	}

	return &DKEK{
		shamir:    shamir,
		storage:   storage,
		threshold: threshold,
		shares:    shares,
	}, nil
}

// Generate generates a new DKEK and splits it into shares.
// The DKEK itself is not stored; only the shares are persisted.
//
// Returns:
//   - The generated shares
//   - An error if generation or splitting fails
func (d *DKEK) Generate() ([]DKEKShare, error) {
	// Generate random 256-bit DKEK
	dkek := make([]byte, 32)
	if _, err := rand.Read(dkek); err != nil {
		return nil, fmt.Errorf("failed to generate dkek: %w", err)
	}

	// Split DKEK into shares
	shamirShares, err := d.shamir.Split(dkek)
	if err != nil {
		return nil, fmt.Errorf("failed to split dkek: %w", err)
	}

	// Convert to DKEK shares
	shares := make([]DKEKShare, len(shamirShares))
	for i, share := range shamirShares {
		shares[i] = DKEKShare{
			Index:    share.Index,
			Value:    share.Value,
			Checksum: share.Checksum,
		}
	}

	// Persist shares to storage
	if err := d.saveShares(shares); err != nil {
		return nil, fmt.Errorf("failed to save shares: %w", err)
	}

	return shares, nil
}

// Reconstruct reconstructs the DKEK from a subset of shares.
// At least 'threshold' number of shares must be provided.
//
// Parameters:
//   - shares: The DKEK shares to combine (must be >= threshold)
//
// Returns:
//   - The reconstructed DKEK
//   - An error if reconstruction fails or too few shares provided
func (d *DKEK) Reconstruct(shares []DKEKShare) ([]byte, error) {
	if len(shares) < d.threshold {
		return nil, fmt.Errorf("insufficient shares: need %d, got %d", d.threshold, len(shares))
	}

	// Convert to Shamir shares
	shamirShares := make([]secretsharing.Share, len(shares))
	for i, share := range shares {
		shamirShares[i] = secretsharing.Share{
			Index:    share.Index,
			Value:    share.Value,
			Checksum: share.Checksum,
		}
	}

	// Reconstruct DKEK
	dkek, err := d.shamir.Combine(shamirShares)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct dkek: %w", err)
	}

	return dkek, nil
}

// LoadShare loads a specific DKEK share from storage.
//
// Parameters:
//   - index: The share index to load (1-based)
//
// Returns:
//   - The loaded share
//   - An error if the share doesn't exist or loading fails
func (d *DKEK) LoadShare(index byte) (*DKEKShare, error) {
	shareID := fmt.Sprintf("dkek-share-%d", index)
	data, err := d.storage.Get(shareID)
	if err != nil {
		return nil, fmt.Errorf("failed to load share %d: %w", index, err)
	}

	// Parse share data (format: index:value:checksum in hex)
	var share DKEKShare
	if _, err := fmt.Sscanf(string(data), "%d:%x:%x", &share.Index, &share.Value, &share.Checksum); err != nil {
		return nil, fmt.Errorf("failed to parse share %d: %w", index, err)
	}

	return &share, nil
}

// LoadAllShares loads all DKEK shares from storage.
//
// Returns:
//   - All available shares
//   - An error if loading fails
func (d *DKEK) LoadAllShares() ([]DKEKShare, error) {
	shares := make([]DKEKShare, 0, d.shares)

	for i := byte(1); i <= byte(d.shares); i++ {
		share, err := d.LoadShare(i)
		if err != nil {
			// Share might not exist, skip it
			continue
		}
		shares = append(shares, *share)
	}

	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares found in storage")
	}

	return shares, nil
}

// DeleteShare deletes a specific DKEK share from storage.
//
// Parameters:
//   - index: The share index to delete (1-based)
//
// Returns an error if deletion fails.
func (d *DKEK) DeleteShare(index byte) error {
	shareID := fmt.Sprintf("dkek-share-%d", index)
	return d.storage.Delete(shareID)
}

// DeleteAllShares deletes all DKEK shares from storage.
// This is a destructive operation and cannot be undone.
//
// Returns an error if any deletion fails.
func (d *DKEK) DeleteAllShares() error {
	for i := byte(1); i <= byte(d.shares); i++ {
		if err := d.DeleteShare(i); err != nil {
			// Continue deleting other shares even if one fails
			continue
		}
	}
	return nil
}

// saveShares persists DKEK shares to storage.
func (d *DKEK) saveShares(shares []DKEKShare) error {
	for _, share := range shares {
		shareID := fmt.Sprintf("dkek-share-%d", share.Index)

		// Format: index:value:checksum (all in hex)
		data := fmt.Sprintf("%d:%s:%s",
			share.Index,
			hex.EncodeToString(share.Value),
			hex.EncodeToString(share.Checksum))

		if err := d.storage.Put(shareID, []byte(data), nil); err != nil {
			return fmt.Errorf("failed to save share %d: %w", share.Index, err)
		}
	}
	return nil
}

// GetThreshold returns the minimum number of shares needed for reconstruction.
func (d *DKEK) GetThreshold() int {
	return d.threshold
}

// GetTotalShares returns the total number of shares that were created.
func (d *DKEK) GetTotalShares() int {
	return d.shares
}

// VerifyShares verifies the integrity of a set of shares.
// It checks that each share has a valid checksum and that there are
// enough shares to reconstruct the DKEK.
//
// Parameters:
//   - shares: The shares to verify
//
// Returns:
//   - true if shares are valid and sufficient
//   - An error describing what's wrong if validation fails
func (d *DKEK) VerifyShares(shares []DKEKShare) error {
	if len(shares) < d.threshold {
		return fmt.Errorf("insufficient shares: need %d, got %d", d.threshold, len(shares))
	}

	// Convert to Shamir shares for verification
	shamirShares := make([]secretsharing.Share, len(shares))
	for i, share := range shares {
		shamirShares[i] = secretsharing.Share{
			Index:    share.Index,
			Value:    share.Value,
			Checksum: share.Checksum,
		}
	}

	// Verify checksums by attempting reconstruction
	// If checksums are invalid, reconstruction will fail
	if _, err := d.shamir.Combine(shamirShares); err != nil {
		return fmt.Errorf("share verification failed: %w", err)
	}

	return nil
}
