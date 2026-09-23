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

package phone

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// Compile-time check that Backend satisfies ImportExportBackend.
var _ backend.ImportExportBackend = (*Backend)(nil)

// ExportPublicKey exports the public key for the given key attributes.
// The phone backend only supports exporting public keys; private keys
// cannot leave the phone's secure hardware.
func (b *Backend) ExportPublicKey(ctx context.Context, attrs *types.KeyAttributes, format string) ([]byte, error) {
	if b.closed.Load() {
		return nil, ErrBackendClosed
	}

	params := &pairing.LocalGetPublicKeyParams{
		KeyID:  attrs.CN,
		Format: format,
	}

	ctx, cancel := context.WithTimeout(ctx, b.config.RequestTimeout)
	defer cancel()

	resp, err := b.sendLocalRequest(ctx, pairing.MethodLocalGetPublicKey, params)
	if err != nil {
		return nil, err
	}

	result, err := pairing.DecodeResult[pairing.LocalGetPublicKeyResult](resp)
	if err != nil {
		return nil, ErrInvalidResponse
	}

	return result.PublicKey, nil
}

// GetImportParameters returns ErrImportNotSupported since the phone's hardware
// keystore does not support importing private key material.
func (b *Backend) GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	return nil, ErrImportNotSupported
}

// WrapKey returns ErrExportNotSupported since the phone's hardware keystore
// does not support exporting private key material.
func (b *Backend) WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return nil, ErrExportNotSupported
}

// UnwrapKey returns ErrImportNotSupported since the phone's hardware keystore
// does not support importing private key material.
func (b *Backend) UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	return nil, ErrImportNotSupported
}

// ImportKey returns ErrImportNotSupported since the phone's hardware keystore
// does not support importing private key material.
func (b *Backend) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	return ErrImportNotSupported
}

// ExportKey returns ErrExportNotSupported since the phone's hardware keystore
// does not support exporting private key material.
func (b *Backend) ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	return nil, ErrExportNotSupported
}

// ExportKeyTo returns ErrExportNotSupported for the same reason ExportKey
// does: the phone's hardware keystore never releases private key material,
// so there is nothing for this method to wrap under a destination's
// parameters either.
func (b *Backend) ExportKeyTo(ctx context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return nil, ErrExportNotSupported
}

// ExportKeyMaterial returns ErrExportNotSupported since the phone's hardware
// keystore does not support exporting raw key material.
func (b *Backend) ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	return nil, ErrExportNotSupported
}
