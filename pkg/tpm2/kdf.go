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
	"github.com/jeremyhahn/go-xkms/pkg/crypto/kdf"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// DeriveFromSymmetricKey runs the key derivation function selected by params
// over the TPM-sealed symmetric key named by attrs, returning
// params.KeyLength bytes of derived keying material.
//
// It is the TPM 2.0 answer to PKCS#11 C_DeriveKey (v3.2 §5.18.5). TPM 2.0
// defines no HKDF or SP 800-108 command — TPM2_Unseal is the only way to reach
// a sealed keyed-hash object's secret — so the derivation runs here, one call
// frame away from the unseal, and the unsealed material is zeroized before the
// function returns. That keeps the base key inside the daemon that owns the
// TPM; it never crosses the transport to the PKCS#11 module in the calling
// application's address space, which is where deriving from a key identifier
// rather than from key material became possible in the first place.
//
// The caller receives only derived bytes. The base key's own material is never
// returned, and tpm2SymmetricKey.Raw continues to refuse it.
func (tpm *TPM2) DeriveFromSymmetricKey(attrs *types.KeyAttributes, params *kdf.KDFParams) ([]byte, error) {
	return tpm.DeriveFromSymmetricKeyIn(attrs, tpm.backend, params)
}

// DeriveFromSymmetricKeyIn is DeriveFromSymmetricKey over a key whose blobs
// are in keys.
func (tpm *TPM2) DeriveFromSymmetricKeyIn(attrs *types.KeyAttributes, keys store.KeyBackend, params *kdf.KDFParams) ([]byte, error) {
	if attrs == nil {
		return nil, ErrInvalidKeyAttributes
	}
	if params == nil {
		return nil, types.ErrUnsupportedKDFAlgorithm
	}

	if err := validateSymmetricKeyAttributes(attrs); err != nil {
		return nil, err
	}

	// GetSymmetricKey proves the sealed object exists and carries the
	// attributes claimed for it before any TPM_Unseal is attempted; the
	// encrypter below performs no such check of its own.
	if _, err := tpm.GetSymmetricKeyIn(attrs, keys); err != nil {
		return nil, err
	}

	encrypter := &tpm2AESEncrypter{tpm: tpm, attrs: attrs, keys: keys}
	keyMaterial, err := encrypter.loadKeyMaterial()
	if err != nil {
		return nil, err
	}
	// secure.Wipe is the project's compiler-optimization-resistant wipe;
	// unsealed TPM key material left in the heap is material an attacker can
	// still find.
	defer secure.Wipe(keyMaterial)

	return types.DeriveFromKeyMaterial(keyMaterial, params)
}
