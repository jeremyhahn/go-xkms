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

package keychain

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// ========================================================================
// Sealing Operations (delegated to backend)
// ========================================================================

// Seal encrypts/protects data using the backend's native sealing mechanism.
// The sealed data can only be unsealed by the same backend type.
//
// Different backends provide different security guarantees:
//   - TPM2: PCR-bound hardware sealing (strongest)
//   - PKCS#11: HSM-backed AES-GCM encryption
//   - AWS/Azure/GCP KMS: Cloud-managed envelope encryption
//   - PKCS#8: Software-based HKDF + AES-GCM (weakest, but portable)
func (ks *compositeKeyStore) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	// Check if backend implements Sealer interface
	sealer, ok := ks.backend.(types.Sealer)
	if !ok {
		return nil, fmt.Errorf("%w: backend %s does not implement Sealer interface",
			ErrSealingNotSupported, ks.backend.Type())
	}

	// Verify backend can seal
	if !sealer.CanSeal() {
		return nil, fmt.Errorf("%w: backend %s cannot seal (not initialized or not supported)",
			ErrSealingNotSupported, ks.backend.Type())
	}

	// Delegate to backend
	sealed, err := sealer.Seal(ctx, data, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to seal data: %w", err)
	}

	return sealed, nil
}

// Unseal decrypts/recovers data that was previously sealed.
// The sealed data must have been created by the same backend type.
//
// For TPM backends, this requires the same PCR state as when the data was sealed.
// For cloud backends, the same key must be accessible.
func (ks *compositeKeyStore) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, ErrInvalidSealedData
	}

	// Check if backend implements Sealer interface
	sealer, ok := ks.backend.(types.Sealer)
	if !ok {
		return nil, fmt.Errorf("%w: backend %s does not implement Sealer interface",
			ErrSealingNotSupported, ks.backend.Type())
	}

	// Verify backend can seal (and therefore unseal)
	if !sealer.CanSeal() {
		return nil, fmt.Errorf("%w: backend %s cannot unseal (not initialized or not supported)",
			ErrSealingNotSupported, ks.backend.Type())
	}

	// Verify the sealed data was created by this backend type
	if sealed.Backend != ks.backend.Type() {
		return nil, fmt.Errorf("%w: sealed data was created by %s, but current backend is %s",
			ErrBackendMismatch, sealed.Backend, ks.backend.Type())
	}

	// Delegate to backend
	plaintext, err := sealer.Unseal(ctx, sealed, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal data: %w", err)
	}

	return plaintext, nil
}

// CanSeal returns true if the backend supports sealing operations.
func (ks *compositeKeyStore) CanSeal() bool {
	sealer, ok := ks.backend.(types.Sealer)
	if !ok {
		return false
	}
	return sealer.CanSeal()
}
