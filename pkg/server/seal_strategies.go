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

package server

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// sealKeyCN mirrors seal.SealKeyCN, the canonical common name of the
// symmetric wrapping key that the barrier root key is sealed under by a
// hardware/cloud backend. Kept as a local alias so existing callers in this
// package need no changes; the value itself, and the key-attribute and
// provisioning logic below, are owned by pkg/seal -- the ONE composition
// path xkmsd and xkey both build cloud-KMS seal strategies through
// (go-xkms#757).
const sealKeyCN = seal.SealKeyCN

// sealKeyAttributesFor builds the types.KeyAttributes that identify the
// symmetric wrapping key used to seal and unseal the barrier root key for the
// given store. It delegates to seal.SealKeyAttributes; see that function's
// doc for the field semantics.
func sealKeyAttributesFor(store types.StoreType) *types.KeyAttributes {
	return seal.SealKeyAttributes(store)
}

// ensureSealKey guarantees the symmetric wrapping key identified by keyAttrs is
// resolvable by the backend so the sealer's SymmetricEncrypter can find it. It
// delegates the provisioning recipe (PKCS#11 login, AWS KMS metadata seeding,
// then the idempotent GetSymmetricKey/GenerateSymmetricKey check-and-skip) to
// seal.EnsureSealKey, translating a backend-unavailable failure into this
// package's own ErrBackendNotAvailable so existing callers observe the same
// error type as before the logic moved to pkg/seal (go-xkms#757).
func (s *Server) ensureSealKey(
	id seal.StrategyID,
	provider types.KeyProvider,
	keyAttrs *types.KeyAttributes,
) error {
	err := seal.EnsureSealKey(context.Background(), id, provider, keyAttrs)
	if err == nil {
		return nil
	}
	var notAvail *seal.ErrSealBackendUnavailable
	if errors.As(err, &notAvail) {
		return &ErrBackendNotAvailable{Backend: notAvail.Strategy, Purpose: notAvail.Purpose}
	}
	return err
}
