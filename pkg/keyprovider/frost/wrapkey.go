// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build frost

package frost

import (
	"crypto/x509"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// SecretSealKeyCN is the fixed common name of the wrapping key a FROST
// secret backend that seals via a reusable key (PKCS#11, cloud KMS,
// software, PKCS#8) provisions to seal/unseal every participant's secret
// share. It is distinct from seal.SealKeyCN, the barrier's own wrapping key
// (go-xkms#757), so a backend configured as both the barrier's hardware
// strategy and FROST's secret_backend never shares a single key across the
// two roles.
//
// TPM2 does not use this CN: it seals directly under the Platform SRK
// (go-xkms#997) and needs a wrapping-object identity unique per FROST key,
// not one shared name -- see secretSealKeyAttributesFor.
const SecretSealKeyCN = "xkms-frost-wrap"

// SymmetricSecretSealKeyAttributes returns the KeyAttributes identifying the
// AES-256-GCM wrapping key that a backend implementing
// types.SymmetricKeyProvider (PKCS#11, AWS KMS, GCP KMS, Azure Key Vault,
// HashiCorp Vault) uses to seal and unseal every FROST secret share it
// holds. Provision the key with seal.EnsureSealKey before use.
func SymmetricSecretSealKeyAttributes(store types.StoreType) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 SecretSealKeyCN,
		StoreType:          store,
		KeyType:            types.KeyTypeEncryption,
		KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
}

// AsymmetricSecretSealKeyAttributes returns the KeyAttributes identifying
// the Ed25519 private key that the software and PKCS#8 backends' Sealer
// implementation derives an AES-256-GCM wrapping key from via HKDF (see
// pkg/keyprovider/pkcs8/sealer.go). Unlike the hardware/cloud backends,
// these backends have no dedicated symmetric-key seal primitive: Seal loads
// an existing private key through GetKey, so the "wrapping key" here is a
// private key generated once (via seal.EnsurePrivateSealKey) and reused for
// every FROST secret share.
func AsymmetricSecretSealKeyAttributes(store types.StoreType) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           SecretSealKeyCN,
		StoreType:    store,
		KeyType:      types.KeyTypeEncryption,
		KeyAlgorithm: x509.Ed25519,
	}
}

// TPM2SecretSealKeyAttributes returns the wrapping-key template for a TPM2
// secret backend: no CN, just the Platform SRK as Parent. TPM2 needs no
// provisioning step -- Seal creates a new sealed object per call -- but each
// FROST key still needs a distinct sealed-object identity, so
// KeyStore.secretSealKeyAttributesFor fills in CN per key from this
// template rather than reusing SecretSealKeyCN across every key (which
// would make each new FROST key's Seal silently overwrite the TPM backend's
// stored copy of a previous key's sealed object).
//
// The sealed object carries no password, so it is bound to the Platform
// SRK's own policy: a TPM2 seal must name a policy or a password.
func TPM2SecretSealKeyAttributes(psrkAttrs *types.KeyAttributes) *types.KeyAttributes {
	attrs := &types.KeyAttributes{Parent: psrkAttrs}
	if psrkAttrs != nil {
		attrs.TPMPolicy = psrkAttrs.TPMPolicy
	}
	return attrs
}
