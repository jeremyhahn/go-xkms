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

package seal

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// SealKeyCN is the canonical common name of the symmetric wrapping key that
// the barrier root key is sealed under by a hardware/cloud backend. The
// PKCS#11 and cloud KMS backends resolve their HSM/KMS-resident wrapping key
// by this CN, so a fixed, deterministic value keeps seal/unseal idempotent
// across restarts: the same key is resolved (or created on first init) on
// every boot.
const SealKeyCN = "xkms-barrier-seal"

// SealKeyAttributes builds the types.KeyAttributes that identify the
// symmetric wrapping key used to seal and unseal the barrier root key for
// the given store. SymmetricAlgorithm being non-empty is what makes the
// backend treat the request as a symmetric seal (the asymmetric path is
// rejected); KeyTypeEncryption marks the key's purpose.
func SealKeyAttributes(store types.StoreType) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 SealKeyCN,
		StoreType:          store,
		KeyType:            types.KeyTypeEncryption,
		KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
}

// SealLoginProvider is implemented by backends (PKCS#11) that require an
// explicit token login before symmetric-key operations succeed.
type SealLoginProvider interface {
	Login() error
}

// SealMetadataSaver is implemented by cloud-KMS backends (AWS KMS) whose
// in-process metadata store must be seeded with the operator's
// pre-provisioned key identifier before GetSymmetricKey can resolve it.
type SealMetadataSaver interface {
	Save(attrs *types.KeyAttributes, data []byte, extension types.FSExtension, overwrite bool) error
}

// ErrSealBackendUnavailable indicates a hardware/cloud backend does not
// implement the interface (types.Sealer / types.SymmetricKeyProvider) a
// seal strategy requires.
type ErrSealBackendUnavailable struct {
	Strategy string
	Purpose  string
}

// Error returns the error message.
func (e *ErrSealBackendUnavailable) Error() string {
	if e.Purpose != "" {
		return fmt.Sprintf("backend %q not available for %s", e.Strategy, e.Purpose)
	}
	return fmt.Sprintf("backend %q not available", e.Strategy)
}

// ErrNotCloudSealStrategy indicates BuildCloudKMSStrategy was called with a
// strategy ID that is not one of the cloud KMS strategies it composes
// (StrategyAWSKMS, StrategyGCPKMS, StrategyAzureKV, StrategyVault).
type ErrNotCloudSealStrategy struct {
	Strategy string
}

// Error returns the error message.
func (e *ErrNotCloudSealStrategy) Error() string {
	return fmt.Sprintf("seal: %q is not a cloud KMS strategy", e.Strategy)
}

// IsCloudSealStrategy reports whether id is one of the cloud KMS strategies
// BuildCloudKMSStrategy composes (StrategyAWSKMS, StrategyGCPKMS,
// StrategyAzureKV, StrategyVault).
func IsCloudSealStrategy(id StrategyID) bool {
	switch id {
	case StrategyAWSKMS, StrategyGCPKMS, StrategyAzureKV, StrategyVault:
		return true
	default:
		return false
	}
}

// EnsureSealKey guarantees the symmetric wrapping key identified by keyAttrs
// is resolvable by provider so the sealer's SymmetricEncrypter can find it.
//
// It mirrors the provisioning recipe shared by every hardware/cloud seal
// strategy:
//
//   - PKCS#11 opens no session until Login(); this seeds it first.
//   - AWS KMS resolves its operator-provisioned CMK through an in-process
//     metadata store keyed on CN, which starts empty each boot; this seeds it
//     (upsert) so GetSymmetricKey can read the key id.
//   - Every backend then check-and-skips: GetSymmetricKey reuses an existing
//     key, and only a genuine not-found triggers GenerateSymmetricKey (first
//     init).
//
// The operation is idempotent: an existing key is detected and reused
// unchanged, so previously-sealed data unseals after a restart.
func EnsureSealKey(
	ctx context.Context,
	id StrategyID,
	provider types.KeyProvider,
	keyAttrs *types.KeyAttributes,
) error {
	symProvider, ok := provider.(types.SymmetricKeyProvider)
	if !ok {
		return &ErrSealBackendUnavailable{Strategy: string(id), Purpose: "symmetric sealing key"}
	}

	if loginProvider, ok := provider.(SealLoginProvider); ok {
		if err := loginProvider.Login(); err != nil {
			return err
		}
	}

	// AWS KMS keeps its key identifier in an in-process metadata store that
	// must be seeded before GetSymmetricKey can resolve the
	// operator-managed CMK.
	if id == StrategyAWSKMS {
		if saver, ok := provider.(SealMetadataSaver); ok {
			metadata, err := json.Marshal(map[string]string{"key_id": keyAttrs.CN})
			if err != nil {
				return err
			}
			if err := saver.Save(keyAttrs, metadata, types.FSExtPrivateBlob, true); err != nil {
				return err
			}
		}
	}

	if _, err := symProvider.GetSymmetricKey(ctx, keyAttrs); err == nil {
		return nil
	} else if !errors.Is(err, backend.ErrKeyNotFound) &&
		!errors.Is(err, backend.ErrKeyAlreadyExists) {
		return err
	}

	if _, err := symProvider.GenerateSymmetricKey(ctx, keyAttrs); err != nil &&
		!errors.Is(err, backend.ErrKeyAlreadyExists) {
		return err
	}
	return nil
}

// BuildCloudKMSStrategy is the ONE composition path xkmsd and xkey both call
// to turn an already-constructed, already-configured cloud KMS backend
// (types.KeyProvider) into a seal.CloudKMSStrategy: it provisions the named
// symmetric wrapping key (creating it on first init, reusing it thereafter
// via EnsureSealKey) and wraps the backend's types.Sealer. id must be one of
// StrategyAWSKMS, StrategyGCPKMS, StrategyAzureKV, or StrategyVault; store is
// the matching types.StoreType (types.StoreAWSKMS, etc.).
//
// Sharing this path keeps seal-key provisioning identical between xkmsd
// (pkg/server/seal_strategies.go) and xkey (which has no backend/provider
// registry of its own and constructs the backend directly from its own
// config), so a barrier initialized by one unseals under the other.
func BuildCloudKMSStrategy(
	ctx context.Context,
	id StrategyID,
	store types.StoreType,
	provider types.KeyProvider,
) (SealingStrategy, error) {
	if !IsCloudSealStrategy(id) {
		return nil, &ErrNotCloudSealStrategy{Strategy: string(id)}
	}

	sealer, ok := provider.(types.Sealer)
	if !ok {
		return nil, &ErrSealBackendUnavailable{Strategy: string(id), Purpose: "sealing"}
	}

	keyAttrs := SealKeyAttributes(store)
	if err := EnsureSealKey(ctx, id, provider, keyAttrs); err != nil {
		return nil, err
	}

	return NewCloudKMSStrategy(id, sealer, keyAttrs, nil), nil
}
