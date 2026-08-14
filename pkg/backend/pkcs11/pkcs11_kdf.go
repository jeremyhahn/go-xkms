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

//go:build pkcs11

package pkcs11

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// DeriveFromSymmetricKey runs the key derivation function selected by params
// over the token key named by attrs, implementing types.SymmetricKeyDeriver.
// It is what answers PKCS#11 C_DeriveKey (v3.2 §5.18.5) for this backend.
//
// The token is the authority on whether it will release the key at all. This
// method asks it through the same path C_GetAttributeValue(CKA_VALUE) takes:
// a key whose CKA_EXTRACTABLE is CK_FALSE, or whose CKA_SENSITIVE is CK_TRUE,
// is refused by the token and reported here as
// types.ErrKeyDerivationNotSupported. That is a genuine capability boundary,
// not a missing implementation — the material is inside the HSM by the
// application's own choice of attributes, and no correct derivation exists
// that does not touch it.
//
// The token's own CKM_HKDF_DERIVE / CKM_SP800_108_*_KDF mechanisms are not used
// because the Go binding this backend drives (github.com/miekg/pkcs11) has no
// marshaller for CK_HKDF_PARAMS or CK_SP800_108_KDF_PARAMS: both are
// pointer-bearing C structures that cannot be assembled from Go without new
// cgo. Deriving here, over material the token agreed to release, is the
// complete implementation available at this layer; it is still a derivation
// over the real key, and the material is zeroized before the call returns.
func (b *Backend) DeriveFromSymmetricKey(ctx context.Context, attrs *types.KeyAttributes, params *kdf.KDFParams) ([]byte, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: "key attributes cannot be nil"}
	}
	if params == nil {
		return nil, &errs.Detail{Err: types.ErrUnsupportedKDFAlgorithm, Detail: "nil KDF parameters"}
	}

	keyMaterial, err := b.ExportKeyMaterial(ctx, attrs)
	if err != nil {
		// ErrKeyNotExportable is the token declining to release the key, which
		// is a statement about this key's protection rather than about the
		// request. Reporting it as a derivation the backend cannot perform is
		// what lets a caller tell it apart from a malformed request or a key
		// that is simply not there.
		if errors.Is(err, backend.ErrKeyNotExportable) {
			return nil, &errs.Detail{
				Err:    types.ErrKeyDerivationNotSupported,
				Detail: "the token will not release this key's material, and offers no reachable KDF over it",
			}
		}
		return nil, err
	}
	// secure.Wipe is the project's compiler-optimization-resistant wipe; key
	// material the token released and this process left in the heap is
	// material an attacker can still find.
	defer secure.Wipe(keyMaterial)

	return types.DeriveFromKeyMaterial(keyMaterial, params)
}

// Compile-time proof that this backend offers derivation from a stored key.
var _ types.SymmetricKeyDeriver = (*Backend)(nil)
