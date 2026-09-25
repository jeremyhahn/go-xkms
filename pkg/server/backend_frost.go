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
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// initFrostBackend initializes the FROST threshold-signing backend (RFC
// 9591) if enabled in configuration. It runs last in initializeBackends,
// after every other backend: backends.frost.secret_backend names one of
// them, and the named types.KeyProvider must already be registered in
// s.keyProviders for the FrostBackend to hold each participant's secret
// share through it. Public group components (group public key, verification
// shares, metadata) are stored separately, under
// backends.frost.public_path, since they carry no secret material.
//
// FROST signing sessions (nonces, in-flight commitments) are held only in
// the returned *frost.FrostBackend's in-memory session map — never
// persisted — so a restart always starts a fresh signing round; only used
// nonce markers (under the storage prefix noncesPrefix) persist, through the
// same public storage, to keep nonce-reuse detection effective across
// restarts.
func (s *Server) initFrostBackend() error {
	cfg := s.config.Backends.Frost
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	secretBackend, ok := s.keyProviders[cfg.SecretBackend]
	if !ok {
		return &ErrFrostSecretBackendUnavailable{Backend: cfg.SecretBackend}
	}

	publicStorage, err := s.createStorageAt(cfg.PublicPath)
	if err != nil {
		return &ErrStorageCreate{Resource: "FROST public storage", Err: err}
	}

	frostBackend, err := frost.NewBackend(&frost.Config{
		PublicStorage: publicStorage,
		SecretBackend: secretBackend,
		// NonceStorage is left nil so the backend tracks used nonce markers
		// in publicStorage (frost.Config.GetNonceStorage's fallback) — the
		// same durable, server-managed storage as the public group
		// components, so nonce-reuse detection survives a restart.
		Algorithm:           types.FrostAlgorithm(cfg.Algorithm),
		DefaultThreshold:    cfg.DefaultThreshold,
		DefaultTotal:        cfg.DefaultTotal,
		EnableNonceTracking: true,
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
