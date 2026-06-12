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
	"crypto/x509"
	"encoding/json"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// sealKeyCN is the canonical common name of the symmetric wrapping key that the
// barrier root key is sealed under by a hardware/cloud backend. The PKCS#11 and
// cloud KMS backends resolve their HSM/KMS-resident wrapping key by this CN, so
// a fixed, deterministic value keeps seal/unseal idempotent across restarts:
// the same key is resolved (or created on first init) on every boot.
const sealKeyCN = "xkms-barrier-seal"

// sealKeyAttributesFor builds the types.KeyAttributes that identify the
// symmetric wrapping key used to seal and unseal the barrier root key for the
// given store. SymmetricAlgorithm being non-empty is what makes the backend
// treat the request as a symmetric seal (the asymmetric path is rejected);
// KeyTypeEncryption marks the key's purpose.
func sealKeyAttributesFor(store types.StoreType) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 sealKeyCN,
		StoreType:          store,
		KeyType:            types.KeyTypeEncryption,
		KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
}

// sealStoreType maps a barrier strategy ID to the backend store type whose
// wrapping key seals the root key. It returns ("", false) for strategies that
// are not hardware/cloud-backed (software/none/shamir/passphrase).
func sealStoreType(id seal.StrategyID) (types.StoreType, bool) {
	switch id {
	case seal.StrategyTPM2:
		return types.StoreTPM2, true
	case seal.StrategyPKCS11:
		return types.StorePKCS11, true
	case seal.StrategyAWSKMS:
		return types.StoreAWSKMS, true
	case seal.StrategyGCPKMS:
		return types.StoreGCPKMS, true
	case seal.StrategyAzureKV:
		return types.StoreAzureKV, true
	case seal.StrategyVault:
		return types.StoreVault, true
	default:
		return "", false
	}
}

// sealLoginProvider is implemented by backends (PKCS#11) that require an
// explicit token login before symmetric-key operations succeed.
type sealLoginProvider interface {
	Login() error
}

// sealMetadataSaver is implemented by cloud-KMS backends (AWS KMS) whose
// in-process metadata store must be seeded with the operator's pre-provisioned
// key identifier before GetSymmetricKey can resolve it.
type sealMetadataSaver interface {
	Save(attrs *types.KeyAttributes, data []byte, extension types.FSExtension, overwrite bool) error
}

// buildHardwareSealStrategies builds the ordered set of sealing strategies the
// barrier composes from. It reuses the backends already initialized by
// initializeBackends (held in s.keyProviders) rather than constructing a second
// hardware handle: each hardware/cloud backend in go-xkms implements both
// types.Sealer and types.SymmetricKeyProvider, so the matching strategy is
// wrapped directly around the live backend.
//
// For every hardware/cloud strategy ID listed in the barrier preference order
// whose backend is configured and compiled in, the matching seal.SealingStrategy
// is appended. Strategies whose backend is absent are skipped: the barrier
// preference order tolerates unavailable strategies and falls back to the next
// available one. seal.NewSoftwareStrategy() is always appended last as the
// baseline fallback, so behavior is identical to the previous software-only
// wiring when no hardware backend is configured.
func (s *Server) buildHardwareSealStrategies() ([]seal.SealingStrategy, error) {
	var strategies []seal.SealingStrategy
	seen := make(map[seal.StrategyID]struct{})

	for _, raw := range s.config.Barrier.PreferenceOrder {
		id := seal.StrategyID(raw)
		if _, dup := seen[id]; dup {
			continue
		}

		store, hardware := sealStoreType(id)
		if !hardware {
			// software / none / shamir / passphrase: handled by the software
			// fallback (or by qrdb's barrier), not a hardware sealer.
			continue
		}

		provider, ok := s.keyProviders[raw]
		if !ok {
			// The strategy was requested but its backend is not configured or
			// not compiled in; let the barrier fall back to a later strategy.
			s.logger.Warn("Seal strategy requested but backend not configured; skipping",
				"strategy", raw)
			continue
		}

		strategy, err := s.buildHardwareSealStrategy(id, store, provider)
		if err != nil {
			return nil, err
		}

		strategies = append(strategies, strategy)
		seen[id] = struct{}{}
		s.logger.Info("Hardware seal strategy enabled", "strategy", raw)
	}

	// Software is always the baseline fallback.
	strategies = append(strategies, seal.NewSoftwareStrategy())

	return strategies, nil
}

// buildHardwareSealStrategy wraps a single already-initialized backend in its
// matching seal.SealingStrategy. The provider must implement types.Sealer (and,
// for the symmetric-wrapping strategies, types.SymmetricKeyProvider); every
// go-xkms hardware/cloud backend does.
func (s *Server) buildHardwareSealStrategy(
	id seal.StrategyID,
	store types.StoreType,
	provider types.KeyProvider,
) (seal.SealingStrategy, error) {
	sealer, ok := provider.(types.Sealer)
	if !ok {
		return nil, &ErrSealStrategyBuild{
			Strategy: string(id),
			Err:      &ErrBackendNotAvailable{Backend: string(id), Purpose: "sealing"},
		}
	}

	// TPM 2.0 seals the root key under the SRK hierarchy; it needs no named
	// wrapping key, so no key attributes or provisioning step is required.
	if id == seal.StrategyTPM2 {
		return seal.NewTPM2Strategy(sealer, nil), nil
	}

	// PKCS#11 and the cloud KMS backends seal under a named symmetric wrapping
	// key. Ensure that key is resolvable (creating it on first init) before
	// wrapping the sealer.
	keyAttrs := sealKeyAttributesFor(store)
	if err := s.ensureSealKey(id, provider, keyAttrs); err != nil {
		return nil, &ErrSealStrategyBuild{Strategy: string(id), Err: err}
	}

	if id == seal.StrategyPKCS11 {
		return seal.NewPKCS11Strategy(sealer, keyAttrs, nil), nil
	}
	return seal.NewCloudKMSStrategy(id, sealer, keyAttrs, nil), nil
}

// ensureSealKey guarantees the symmetric wrapping key identified by keyAttrs is
// resolvable by the backend so the sealer's SymmetricEncrypter can find it.
//
// It mirrors the provisioning recipe used elsewhere in the stack:
//
//   - PKCS#11 opens no session until Login(); the factory logs in first.
//   - AWS KMS resolves its operator-provisioned CMK through an in-process
//     metadata store keyed on CN, which starts empty each boot; the factory
//     seeds it (upsert) so GetSymmetricKey can read the key id.
//   - All backends then check-and-skip: GetSymmetricKey reuses an existing key,
//     and only a genuine not-found triggers GenerateSymmetricKey (first init).
//
// The operation is idempotent: an existing key is detected and reused unchanged,
// so previously-sealed data unseals after a restart.
func (s *Server) ensureSealKey(
	id seal.StrategyID,
	provider types.KeyProvider,
	keyAttrs *types.KeyAttributes,
) error {
	symProvider, ok := provider.(types.SymmetricKeyProvider)
	if !ok {
		return &ErrBackendNotAvailable{Backend: string(id), Purpose: "symmetric sealing key"}
	}

	if loginProvider, ok := provider.(sealLoginProvider); ok {
		if err := loginProvider.Login(); err != nil {
			return err
		}
	}

	// AWS KMS keeps its key identifier in an in-process metadata store that must
	// be seeded before GetSymmetricKey can resolve the operator-managed CMK.
	if id == seal.StrategyAWSKMS {
		if saver, ok := provider.(sealMetadataSaver); ok {
			metadata, err := json.Marshal(map[string]string{"key_id": keyAttrs.CN})
			if err != nil {
				return err
			}
			if err := saver.Save(keyAttrs, metadata, types.FSExtPrivateBlob, true); err != nil {
				return err
			}
		}
	}

	// Seal-key provisioning runs at server startup, outside any request, so it
	// is bounded by a background context rather than a request-scoped one.
	ctx := context.Background()

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
