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
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
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
func (b *Backend) Seal(ctx context.Context, data []byte, opts *types.SealOptions) (_ *types.SealedData, err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	// Without KeyAttributes the TPM seals under its own defaults: the
	// system scope's Platform SRK and key store.
	if opts == nil || opts.KeyAttributes == nil {
		return b.sealed(b.tpm.Seal(ctx, data, opts))
	}

	scope, err := b.scope(ctx, opts.KeyAttributes.TenantID)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, scope.close()) }()

	scoped := *opts
	scoped.KeyAttributes = scope.bind(opts.KeyAttributes)
	if scope.scoped {
		scoped.Backend = scope.keys
	}
	sealed, err := b.sealed(scope.tpm.Seal(ctx, data, &scoped))
	if err != nil {
		return nil, err
	}
	if err := b.recordSealed(ctx, scope, scoped.KeyAttributes, sealed); err != nil {
		return nil, err
	}
	return sealed, nil
}

// sealed stamps a sealing result as this backend's.
func (b *Backend) sealed(sealed *types.SealedData, err error) (*types.SealedData, error) {
	if err != nil {
		return nil, err
	}
	// Ensure the backend type reflects this backend wrapper
	sealed.Backend = types.BackendTypeTPM2
	return sealed, nil
}

// recordSealed records the assignment of a sealed object bound to a named
// policy, so the policy's objects include it and the policy cannot be deleted
// while it exists. An object under the built-in platform policy is not
// recorded: the platform policy is never deleted.
func (b *Backend) recordSealed(ctx context.Context, scope *keyScope, attrs *types.KeyAttributes, sealed *types.SealedData) error {
	if !scope.scoped || attrs.TPMPolicy == "" || attrs.TPMPolicy == types.TPMPolicyPlatform {
		return nil
	}
	authPolicy, err := publicAuthPolicy(sealed.TPMPublic)
	if err != nil {
		return &AssignmentError{Tenant: scope.tenant, Object: tpmpolicy.ObjectID(tpmpolicy.ObjectSealed, attrs.CN), Err: err}
	}
	return b.assign(ctx, scope, tpmpolicy.ObjectSealed, attrs, authPolicy)
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
//
// Sealed-data authentication is classified by pkg/tpm2's TPM2.Unseal, whose
// errors this method returns unchanged: forged, tampered, truncated,
// foreign, malformed or AAD-mismatched sealed data matches
// types.ErrSealedDataAuthentication; a closed backend, a cancelled context,
// a tenant scope that cannot be opened, and TPM authorization failures (PCR
// policy, UserAuth) do not.
func (b *Backend) Unseal(ctx context.Context, sealed *types.SealedData, opts *types.UnsealOptions) (_ []byte, err error) {
	if sealed == nil {
		return nil, ErrNilSealedData
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if opts == nil || opts.KeyAttributes == nil {
		return b.tpm.Unseal(ctx, sealed, opts)
	}

	scope, err := b.scope(ctx, opts.KeyAttributes.TenantID)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, scope.close()) }()

	scoped := *opts
	scoped.KeyAttributes = scope.bind(opts.KeyAttributes)
	if scope.scoped {
		scoped.Backend = scope.keys
	}
	return scope.tpm.Unseal(ctx, sealed, &scoped)
}
