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

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ========================================================================
// Sealing Operations (delegated to key provider)
// ========================================================================

// Seal encrypts/protects data using the key provider's native sealing mechanism.
// The sealed data can only be unsealed by the same key provider type.
//
// Different key providers provide different security guarantees:
//   - TPM2: PCR-bound hardware sealing (strongest)
//   - PKCS#11: HSM-backed AES-GCM encryption
//   - AWS/Azure/GCP KMS: Cloud-managed envelope encryption
//   - PKCS#8: Software-based HKDF + AES-GCM (weakest, but portable)
func (c *compositeBackend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (*types.SealedData, error) {
	// Check if key provider implements Sealer interface
	sealer, ok := c.backend.(types.Sealer)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrSealingNotSupported,
			Backend:  string(c.backend.Type()),
			Detail:   "does not implement Sealer interface",
		}
	}

	// Verify key provider can seal
	if !sealer.CanSeal() {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrSealingNotSupported,
			Backend:  string(c.backend.Type()),
			Detail:   "cannot seal (not initialized or not supported)",
		}
	}

	// Delegate to key provider
	sealed, err := sealer.Seal(ctx, data, opts)
	if err != nil {
		return nil, &ErrSealOperation{Operation: "seal", Err: err}
	}

	return sealed, nil
}

// Unseal decrypts/recovers data that was previously sealed.
// The sealed data must have been created by the same key provider type.
//
// For TPM key providers, this requires the same PCR state as when the data was sealed.
// For cloud key providers, the same key must be accessible.
func (c *compositeBackend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) ([]byte, error) {
	if sealed == nil {
		return nil, ErrInvalidSealedData
	}

	// Check if key provider implements Sealer interface
	sealer, ok := c.backend.(types.Sealer)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrSealingNotSupported,
			Backend:  string(c.backend.Type()),
			Detail:   "does not implement Sealer interface",
		}
	}

	// Verify key provider can seal (and therefore unseal)
	if !sealer.CanSeal() {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrSealingNotSupported,
			Backend:  string(c.backend.Type()),
			Detail:   "cannot unseal (not initialized or not supported)",
		}
	}

	// Verify the sealed data was created by this key provider type
	if sealed.Backend != c.backend.Type() {
		return nil, &ErrSealBackendMismatch{
			SealedBy: sealed.Backend,
			Current:  c.backend.Type(),
		}
	}

	// Delegate to key provider
	plaintext, err := sealer.Unseal(ctx, sealed, opts)
	if err != nil {
		return nil, &ErrSealOperation{Operation: "unseal", Err: err}
	}

	return plaintext, nil
}

// CanSeal returns true if the key provider supports sealing operations.
func (c *compositeBackend) CanSeal() bool {
	sealer, ok := c.backend.(types.Sealer)
	if !ok {
		return false
	}
	return sealer.CanSeal()
}
