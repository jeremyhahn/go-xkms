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

//go:build smartcardhsm

package smartcardhsm

import (
	"crypto/rand"
	"fmt"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// DKEKStatus represents the current DKEK initialization status.
type DKEKStatus struct {
	// Initialized indicates if DKEK is fully initialized.
	Initialized bool `json:"initialized"`

	// TotalShares is the total number of shares (N).
	TotalShares int `json:"total_shares"`

	// Threshold is the minimum shares required (M).
	Threshold int `json:"threshold"`

	// SharesImported is the number of shares currently imported.
	SharesImported int `json:"shares_imported"`

	// SharesRemaining is the number of shares still needed.
	SharesRemaining int `json:"shares_remaining"`
}

// DKEKShare represents a single DKEK share for M-of-N reconstruction.
type DKEKShare struct {
	// Index is the share index (1-based).
	Index int `json:"index"`

	// Data is the 32-byte share data.
	Data []byte `json:"data"`
}

// GenerateDKEKShares generates N DKEK shares where M are required to reconstruct.
// This creates a new random 256-bit DKEK and splits it using Shamir's Secret Sharing.
// The shares should be distributed to key custodians for safekeeping.
//
// Parameters:
//   - n: Total number of shares to generate
//   - m: Minimum number of shares required to reconstruct (threshold)
//
// Returns a slice of DKEKShare structs containing the share data.
func GenerateDKEKShares(n, m int) ([]DKEKShare, error) {
	if n < 1 || n > 8 {
		return nil, fmt.Errorf("smartcardhsm: invalid share count %d (must be 1-8)", n)
	}
	if m < 1 || m > n {
		return nil, ErrDKEKThresholdInvalid
	}

	// Generate random 256-bit DKEK
	dkek := make([]byte, 32)
	if _, err := rand.Read(dkek); err != nil {
		return nil, fmt.Errorf("smartcardhsm: failed to generate DKEK: %w", err)
	}

	// Split using Shamir's Secret Sharing
	shares, err := qrdbsdk.ShamirSplit(dkek, n, m)
	if err != nil {
		return nil, fmt.Errorf("smartcardhsm: failed to split DKEK: %w", err)
	}

	result := make([]DKEKShare, len(shares))
	for i, share := range shares {
		result[i] = DKEKShare{
			Index: share.Index,
			Data:  share.Value,
		}
	}

	return result, nil
}

// ReconstructDKEK reconstructs the DKEK from the provided shares.
// At least 'threshold' shares must be provided.
func ReconstructDKEK(shares []DKEKShare, threshold int) ([]byte, error) {
	if len(shares) < threshold {
		return nil, fmt.Errorf("smartcardhsm: insufficient shares (%d < %d)", len(shares), threshold)
	}

	// Convert to shamir shares
	shamirShares := make([]qrdbsdk.ShamirShare, len(shares))
	for i, share := range shares {
		shamirShares[i] = qrdbsdk.ShamirShare{
			Index: share.Index,
			Value: share.Data,
		}
	}

	// Reconstruct
	dkek, err := qrdbsdk.ShamirCombine(shamirShares)
	if err != nil {
		return nil, fmt.Errorf("smartcardhsm: failed to reconstruct DKEK: %w", err)
	}

	return dkek, nil
}

// GetDKEKStatus queries the current DKEK status from the card.
func (b *Backend) GetDKEKStatus() (*DKEKStatus, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.card == nil {
		return nil, ErrNotInitialized
	}

	apdu := BuildReadDKEKStatusAPDU()
	resp, err := b.transmit(apdu)
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, NewAPDUError("GetDKEKStatus", resp.StatusWord())
	}

	// Parse response
	// Response format: status (1 byte) | shares_imported (1 byte) | shares_remaining (1 byte)
	if len(resp.Data) < 3 {
		return nil, fmt.Errorf("smartcardhsm: invalid DKEK status response")
	}

	status := &DKEKStatus{
		Initialized:     resp.Data[0] == DKEKStatusComplete,
		SharesImported:  int(resp.Data[1]),
		SharesRemaining: int(resp.Data[2]),
	}

	// Calculate total and threshold from imported + remaining
	status.TotalShares = status.SharesImported + status.SharesRemaining
	if status.Initialized {
		status.Threshold = status.SharesImported
	}

	return status, nil
}

// ImportDKEKShare imports a single DKEK share into the card.
// Must be called 'threshold' times with different shares to complete DKEK initialization.
// Returns the number of shares still needed.
func (b *Backend) ImportDKEKShare(share DKEKShare) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.card == nil {
		return 0, ErrNotInitialized
	}

	if len(share.Data) != 32 {
		return 0, ErrDKEKShareInvalid
	}

	apdu := BuildImportDKEKShareAPDU(share.Data)
	resp, err := b.transmit(apdu)
	if err != nil {
		return 0, err
	}

	if !resp.IsSuccess() {
		switch resp.StatusWord() {
		case SW_SECURITY_NOT_SAT:
			return 0, ErrAuthenticationFailed
		case SW_CONDITIONS_NOT_SAT:
			return 0, ErrDKEKAlreadyInitialized
		case SW_WRONG_DATA:
			return 0, ErrDKEKShareInvalid
		default:
			return 0, NewAPDUError("ImportDKEKShare", resp.StatusWord())
		}
	}

	// Response contains remaining shares count
	if len(resp.Data) > 0 {
		return int(resp.Data[0]), nil
	}

	return 0, nil
}

// WrapKey wraps a key with the DKEK for export/backup.
// The key must exist on the card at the specified key reference.
// Returns the wrapped key blob that can be imported to another card with the same DKEK.
func (b *Backend) WrapKey(keyRef byte) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.card == nil {
		return nil, ErrNotInitialized
	}

	// Check DKEK status first
	status, err := b.getDKEKStatusLocked()
	if err != nil {
		return nil, err
	}
	if !status.Initialized {
		return nil, ErrDKEKNotInitialized
	}

	apdu := BuildWrapKeyAPDU(keyRef)
	resp, err := b.transmit(apdu)
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		switch resp.StatusWord() {
		case SW_CONDITIONS_NOT_SAT:
			return nil, ErrDKEKNotInitialized
		case SW_WRONG_P1P2:
			return nil, ErrKeyNotFound
		default:
			return nil, NewAPDUError("WrapKey", resp.StatusWord())
		}
	}

	if len(resp.Data) == 0 {
		return nil, ErrKeyWrapFailed
	}

	return resp.Data, nil
}

// UnwrapKey imports a DKEK-wrapped key blob into the card.
// The key will be stored at the specified key reference.
// The card must have the same DKEK that was used to wrap the key.
func (b *Backend) UnwrapKey(keyRef byte, wrappedKey []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.card == nil {
		return ErrNotInitialized
	}

	// Check DKEK status first
	status, err := b.getDKEKStatusLocked()
	if err != nil {
		return err
	}
	if !status.Initialized {
		return ErrDKEKNotInitialized
	}

	if len(wrappedKey) == 0 {
		return ErrKeyUnwrapFailed
	}

	apdu := BuildUnwrapKeyAPDU(keyRef, wrappedKey)
	resp, err := b.transmit(apdu)
	if err != nil {
		return err
	}

	if !resp.IsSuccess() {
		switch resp.StatusWord() {
		case SW_SECURITY_NOT_SAT:
			return ErrAuthenticationFailed
		case SW_CONDITIONS_NOT_SAT:
			return ErrDKEKNotInitialized
		case SW_WRONG_DATA:
			return ErrKeyUnwrapFailed
		default:
			return NewAPDUError("UnwrapKey", resp.StatusWord())
		}
	}

	return nil
}

// getDKEKStatusLocked queries DKEK status without acquiring the lock.
// Caller must hold at least a read lock.
func (b *Backend) getDKEKStatusLocked() (*DKEKStatus, error) {
	apdu := BuildReadDKEKStatusAPDU()
	resp, err := b.transmit(apdu)
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, NewAPDUError("GetDKEKStatus", resp.StatusWord())
	}

	if len(resp.Data) < 3 {
		return nil, fmt.Errorf("smartcardhsm: invalid DKEK status response")
	}

	return &DKEKStatus{
		Initialized:     resp.Data[0] == DKEKStatusComplete,
		SharesImported:  int(resp.Data[1]),
		SharesRemaining: int(resp.Data[2]),
	}, nil
}
