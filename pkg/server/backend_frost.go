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

package server

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// initFrostBackend initializes the FROST threshold-signing backend (RFC
// 9591) if enabled in configuration. It runs last in initializeBackends,
// after every other backend: backends.frost.secret_backend names one of
// them, and the named backend must already be registered in s.keyProviders,
// and implement types.SealingKeyProvider, for the FrostBackend to seal each
// participant's secret share through it. Every FROST entity -- key metadata,
// group public key, verification shares, the sealed secret share, and used
// nonce claims -- lives in the datastore's frost.DatabaseName database.
//
// FROST signing sessions (nonces, in-flight commitments) are held only in
// the returned *frost.FrostBackend's in-memory session map — never
// persisted — so a restart always starts a fresh signing round; only used
// nonce claims persist, so nonce-reuse detection stays effective across
// restarts.
func (s *Server) initFrostBackend() error {
	cfg := s.config.Backends.Frost
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	provider, ok := s.keyProviders[cfg.SecretBackend]
	if !ok {
		return &ErrFrostSecretBackendUnavailable{Backend: cfg.SecretBackend}
	}
	secretBackend, ok := provider.(types.SealingKeyProvider)
	if !ok {
		return &ErrFrostSecretBackendUnavailable{Backend: cfg.SecretBackend}
	}

	sealKeyAttrs, err := s.ensureFrostSecretSealKey(cfg.SecretBackend, provider)
	if err != nil {
		return &ErrBackendCreate{Backend: "FROST", Err: err}
	}

	daos, err := s.daoFactory(frost.DatabaseName)
	if err != nil {
		return err
	}

	frostBackend, err := frost.NewBackend(&frost.Config{
		DAOs:                    daos,
		SecretBackend:           secretBackend,
		SecretSealKeyAttributes: sealKeyAttrs,
		Algorithm:               types.FrostAlgorithm(cfg.Algorithm),
		DefaultThreshold:        cfg.DefaultThreshold,
		DefaultTotal:            cfg.DefaultTotal,
		EnableNonceTracking:     true,
	})
	if err != nil {
		return &ErrBackendCreate{Backend: "FROST", Err: err}
	}

	s.keyProviders["frost"] = frostBackend
	s.logger.Info("FROST backend initialized",
		"backend", "frost",
		"secret_backend", cfg.SecretBackend,
		"algorithm", cfg.Algorithm,
		"default_threshold", cfg.DefaultThreshold,
		"default_total", cfg.DefaultTotal)
	return nil
}

// ensureFrostSecretSealKey provisions (idempotently) the wrapping key that
// the named backend's Sealer implementation needs to seal/unseal a FROST
// secret share, and returns the KeyAttributes identifying it for
// frost.Config.SecretSealKeyAttributes.
//
// TPM2 needs no provisioning step: it seals directly under the Platform SRK
// (go-xkms#997), so only a Parent-only template is returned, and
// pkg/keyprovider/frost fills in a per-FROST-key CN itself. Every other
// whitelisted backend (pkg/config/frost.go's frostSecretBackendNames) is
// provisioned a key dedicated to FROST (frost.SecretSealKeyCN), distinct
// from the barrier's own wrapping key (seal.SealKeyCN, go-xkms#757), so a
// backend serving both roles never shares a single key between them:
// PKCS#11 and the cloud KMS backends get a symmetric AES-256-GCM key via
// seal.EnsureSealKey; software and PKCS#8 -- which seal by deriving a key
// from an existing private key, not a dedicated symmetric primitive -- get
// an Ed25519 private key via seal.EnsurePrivateSealKey.
func (s *Server) ensureFrostSecretSealKey(name string, provider types.KeyProvider) (*types.KeyAttributes, error) {
	ctx := context.Background()

	switch name {
	case "tpm2":
		tpmBackend, ok := provider.(interface{ SRKAttributes() *types.KeyAttributes })
		if !ok {
			return nil, &ErrFrostSecretBackendUnavailable{Backend: name}
		}
		return frost.TPM2SecretSealKeyAttributes(tpmBackend.SRKAttributes()), nil

	case "pkcs11":
		attrs := frost.SymmetricSecretSealKeyAttributes(types.StorePKCS11)
		return attrs, seal.EnsureSealKey(ctx, seal.StrategyPKCS11, provider, attrs)

	case "awskms":
		attrs := frost.SymmetricSecretSealKeyAttributes(types.StoreAWSKMS)
		return attrs, seal.EnsureSealKey(ctx, seal.StrategyAWSKMS, provider, attrs)

	case "gcpkms":
		attrs := frost.SymmetricSecretSealKeyAttributes(types.StoreGCPKMS)
		return attrs, seal.EnsureSealKey(ctx, seal.StrategyGCPKMS, provider, attrs)

	case "azurekv":
		attrs := frost.SymmetricSecretSealKeyAttributes(types.StoreAzureKV)
		return attrs, seal.EnsureSealKey(ctx, seal.StrategyAzureKV, provider, attrs)

	case "vault":
		attrs := frost.SymmetricSecretSealKeyAttributes(types.StoreVault)
		return attrs, seal.EnsureSealKey(ctx, seal.StrategyVault, provider, attrs)

	case "software":
		attrs := frost.AsymmetricSecretSealKeyAttributes(types.StoreSoftware)
		return attrs, seal.EnsurePrivateSealKey(ctx, provider, attrs)

	case "pkcs8":
		attrs := frost.AsymmetricSecretSealKeyAttributes(types.StoreSoftware)
		return attrs, seal.EnsurePrivateSealKey(ctx, provider, attrs)

	default:
		// config.FrostConfig.Validate already refuses any name outside
		// pkg/config/frost.go's whitelist, so reaching this means the
		// whitelist and this switch have drifted -- a defect in this code,
		// not an operator config mistake.
		return nil, &ErrFrostSecretBackendUnavailable{Backend: name}
	}
}
