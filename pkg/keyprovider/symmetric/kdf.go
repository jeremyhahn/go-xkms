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

package symmetric

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// DeriveFromSymmetricKey runs the key derivation function selected by params
// over the stored symmetric key named by attrs, implementing
// types.SymmetricKeyDeriver.
//
// It is what answers PKCS#11 C_DeriveKey (v3.2 §5.18.5) for this backend. The
// key material is read out of storage, decoded, fed to the KDF and zeroized
// before the call returns; nothing but the derived bytes leaves the function,
// and the base key's own bytes are never returned to any caller.
//
// CKA_EXTRACTABLE (attrs.Exportable) is deliberately NOT required. Deriving is
// not exporting: §5.18.5 constrains the sensitivity and extractability of the
// DERIVED key from the base key's, and places no extractability requirement on
// the base key itself. Requiring it here would refuse the very keys — sensitive,
// non-extractable — that derivation exists to serve.
func (b *Backend) DeriveFromSymmetricKey(ctx context.Context, attrs *types.KeyAttributes, params *kdf.KDFParams) ([]byte, error) {
	if attrs == nil {
		return nil, backend.ErrInvalidAttributes
	}
	if params == nil {
		return nil, &errs.Detail{Err: types.ErrUnsupportedKDFAlgorithm, Detail: "nil KDF parameters"}
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrStorageClosed
	}

	if err := attrs.Validate(); err != nil {
		return nil, &errs.Detail{Err: backend.ErrInvalidAttributes, Detail: fmt.Sprintf("%v", err)}
	}
	if !attrs.IsSymmetric() {
		return nil, &errs.Detail{Err: backend.ErrInvalidAlgorithm, Detail: attrs.KeyAlgorithm.String()}
	}

	keyData, err := storage.GetKey(ctx, b.storage, attrs.ID())
	if err != nil {
		if err == storage.ErrNotFound {
			return nil, backend.ErrKeyNotFound
		}
		return nil, &errs.Wrapped{Msg: "failed to retrieve key", Err: err}
	}

	rawKey, err := b.decodeSymmetricKey(keyData, attrs.Password)
	if err != nil {
		return nil, err
	}
	// secure.Wipe is the project's compiler-optimization-resistant wipe; a
	// plain assignment loop may be eliminated for memory the compiler can
	// prove is never read again, and a key left in the heap after the
	// derivation is a key an attacker can still find.
	defer secure.Wipe(rawKey)

	return types.DeriveFromKeyMaterial(rawKey, params)
}

// Compile-time proof that this backend offers derivation from a stored key.
var _ types.SymmetricKeyDeriver = (*Backend)(nil)
