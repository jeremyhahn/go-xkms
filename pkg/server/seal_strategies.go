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

	// PKCS#11 seals under a named symmetric wrapping key it provisions
	// itself; unlike the cloud KMS strategies below, PKCS#11 is not shared
	// with xkey (go-xkms#757 only wires the cloud KMS strategies through).
	if id == seal.StrategyPKCS11 {
		keyAttrs := sealKeyAttributesFor(store)
		if err := s.ensureSealKey(id, provider, keyAttrs); err != nil {
			return nil, &ErrSealStrategyBuild{Strategy: string(id), Err: err}
		}
		return seal.NewPKCS11Strategy(sealer, keyAttrs, nil), nil
	}

	// AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault: seal.BuildCloudKMSStrategy
	// is the ONE cloud-KMS strategy composition path xkmsd and xkey both call
	// (go-xkms#757), so seal-key provisioning (idempotent create-or-reuse)
	// never diverges between the two entry points.
	strategy, err := seal.BuildCloudKMSStrategy(context.Background(), id, store, provider)
	if err != nil {
		return nil, &ErrSealStrategyBuild{Strategy: string(id), Err: err}
	}
	return strategy, nil
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
