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

	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// symmetricDeriver is the TPM 2.0 side of types.SymmetricKeyDeriver: the one
// method this backend needs from its TrustedPlatformModule to derive from a
// sealed symmetric key.
//
// It is declared here, at the point of use, rather than added to
// pkgtpm2.TrustedPlatformModule. That interface is implemented by test doubles
// across three Go modules; widening it to carry a capability only the real
// *TPM2 can provide would force every one of them to grow a method that cannot
// do anything, which is the stub this project forbids. A double that does not
// implement it yields ErrKeyDerivationNotSupported, which is the truth about
// that double.
type symmetricDeriver interface {
	DeriveFromSymmetricKeyIn(attrs *types.KeyAttributes, keys store.KeyBackend, params *kdf.KDFParams) ([]byte, error)
}

// DeriveFromSymmetricKey runs the key derivation function selected by params
// over the TPM-sealed symmetric key named by attrs, implementing
// types.SymmetricKeyDeriver. It is what answers PKCS#11 C_DeriveKey
// (v3.2 §5.18.5) for this backend.
//
// The work happens inside pkg/tpm2, one call frame from TPM2_Unseal, and the
// unsealed material is zeroized there before the call returns. Only derived
// bytes come back; the sealed key's own material never leaves the daemon that
// owns the TPM, and never reaches the PKCS#11 module in the calling
// application's address space.
func (b *Backend) DeriveFromSymmetricKey(ctx context.Context, attrs *types.KeyAttributes, params *kdf.KDFParams) (_ []byte, err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}
	if params == nil {
		return nil, &errs.Detail{Err: types.ErrUnsupportedKDFAlgorithm, Detail: "nil KDF parameters"}
	}

	scope, err := b.scope(ctx, attrs.TenantID)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, scope.close()) }()

	deriver, ok := scope.tpm.(symmetricDeriver)
	if !ok {
		return nil, &errs.Detail{
			Err:    types.ErrKeyDerivationNotSupported,
			Detail: "this TrustedPlatformModule cannot unseal symmetric key material for derivation",
		}
	}

	attrs.StoreType = types.StoreTPM2

	return deriver.DeriveFromSymmetricKeyIn(scope.bind(attrs), scope.keys, params)
}

// Compile-time proof that this backend offers derivation from a stored key.
var _ types.SymmetricKeyDeriver = (*Backend)(nil)
