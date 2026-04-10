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

package tpm2

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Ensure Backend implements types.Sealer interface at compile time.
var _ types.Sealer = (*Backend)(nil)

// CanSeal returns true if this backend supports sealing operations.
// The TPM2 backend supports sealing when it is initialized and the
// underlying TPM instance reports sealing capability.
func (b *Backend) CanSeal() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return false
	}

	return b.tpm.CanSeal()
}

// Seal encrypts/protects data using the TPM's native sealing mechanism.
// The data is sealed under the TPM's storage hierarchy and optionally
// bound to the current PCR state via platform policy.
//
// This method delegates to the underlying pkg/tpm2.TPM2.Seal implementation,
// which creates a sealed keyed-hash object in the TPM. The sealed data can
// only be recovered by the same TPM when the PCR values match (if platform
// policy is enabled).
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - data: The plaintext data to seal
//   - opts: Sealing options (may be nil for defaults)
//
// Returns SealedData containing the TPM public/private areas, or error.
func (b *Backend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	sealed, err := b.tpm.Seal(ctx, data, opts)
	if err != nil {
		return nil, err
	}

	// Ensure the backend type reflects this backend wrapper
	sealed.Backend = types.BackendTypeTPM2

	return sealed, nil
}

// Unseal decrypts/recovers data using the TPM's unsealing mechanism.
// For TPM backends, this requires the same PCR state as when the data
// was sealed (if platform policy was active during sealing).
//
// This method delegates to the underlying pkg/tpm2.TPM2.Unseal implementation.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - sealed: The sealed data from a previous Seal operation
//   - opts: Unsealing options (may be nil for defaults)
//
// Returns the original plaintext data, or error if unsealing fails.
func (b *Backend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, ErrNilSealedData
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	return b.tpm.Unseal(ctx, sealed, opts)
}
