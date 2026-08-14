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

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// deriveBaseKeyMaterial resolves the base key a DeriveKey request names and
// returns params.KeyLength bytes derived from it.
//
// A request names its base key exactly one of two ways:
//
//	input_key_material   raw bytes the caller already holds
//	backend + key_id     the identity of a key the backend holds
//
// Supplying both is refused. They are two different base keys, and choosing
// one silently would derive from material the caller did not select while
// returning a response indistinguishable from the one they wanted. PKCS#11's
// C_DeriveKey has a single hBaseKey for the same reason.
//
// The identity form is what makes hardware-backed derivation possible. The
// PKCS#11 module runs inside the calling application and knows a base key only
// by handle, label and backend key identifier — all non-secret. It therefore
// sends the identity, and the derivation runs in the backend that holds the
// key. Backends unable to reach their own symmetric key material do not
// implement types.SymmetricKeyDeriver, and the assertion below turns that into
// ErrOperationNotSupported naming the backend, rather than a key derived from
// something that is not the key.
func (s *XKMSService) deriveBaseKeyMaterial(ctx context.Context, req *transport.DeriveKeyRequest, params *kdf.KDFParams) ([]byte, error) {
	hasMaterial := len(req.InputKeyMaterial) > 0
	hasIdentity := req.KeyID != ""

	switch {
	case hasMaterial && hasIdentity:
		return nil, &ErrValidation{
			Sentinel: ErrInvalidKeyAttributes,
			Detail:   "input_key_material and key_id name two different base keys; supply exactly one",
		}

	case hasMaterial:
		derived, err := types.DeriveFromKeyMaterial(req.InputKeyMaterial, params)
		if err != nil {
			return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Detail: "key derivation failed", Err: err}
		}
		return derived, nil

	case hasIdentity:
		return s.deriveFromStoredKey(ctx, req, params)

	default:
		return nil, &ErrValidation{
			Sentinel: ErrInvalidKeyAttributes,
			Detail:   "either input_key_material or key_id is required",
		}
	}
}

// deriveFromStoredKey runs the KDF inside the backend that holds the base key.
//
// Nothing here ever reads the base key: the backend is handed the key's
// attributes and the KDF parameters and returns only derived bytes. That is
// the whole point of the split — see types.SymmetricKeyDeriver.
func (s *XKMSService) deriveFromStoredKey(ctx context.Context, req *transport.DeriveKeyRequest, params *kdf.KDFParams) ([]byte, error) {
	backendName := req.Backend
	if backendName == "" {
		backendName = s.defaultBackendName()
	}
	if backendName == "" {
		return nil, requiredField("backend")
	}

	b, err := s.resolveTenantBackend(backendName, req.TenantID)
	if err != nil {
		return nil, roleLookupError("backend", backendName, err)
	}

	deriver, ok := b.KeyProvider().(types.SymmetricKeyDeriver)
	if !ok {
		return nil, &ErrBackendUnsupported{
			Sentinel: ErrOperationNotSupported,
			Backend:  backendName,
			Detail:   "cannot derive from a stored symmetric key",
		}
	}

	attrs, err := findKeyAttrs(ctx, b, req.KeyID)
	if err != nil {
		return nil, roleLookupError("key", req.KeyID, err)
	}

	derived, err := deriver.DeriveFromSymmetricKey(ctx, attrs, params)
	if err != nil {
		return nil, &ErrOperationWrap{Sentinel: ErrOperationFailed, Detail: "key derivation failed", Err: err}
	}

	return derived, nil
}
