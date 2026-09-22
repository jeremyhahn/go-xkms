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

package pinstrategy

import (
	"errors"
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Config drives Resolve. It embeds xkmssdk.PINSelectConfig (the SDK's
// re-export of pkg/pinselect.Config) so the TPM, PKCS#11 and software
// provider adapters are supplied exactly as a caller would supply them to
// xkmssdk.SelectPINBackend directly. xkey depends only on sdk/go and its
// subpackages, never on go-xkms/pkg/* (Architecture Gates), so this
// package reaches pinselect/pintpm2 exclusively through the SDK.
type Config struct {
	xkmssdk.PINSelectConfig

	// PINDir is the directory holding PIN state (<dataDir>/pin by
	// default); <PINDir>/strategy records the governing PIN strategy,
	// beside the qrdb software store's own <PINDir>/{so-pin,user-pin}.
	PINDir string
}

// Resolve returns the PINBackend for PINDir's persisted governing
// strategy, and the strategy ID that governs. It is the ONE selection
// point the xKey GUI, the headless daemon and `xkey pin` all call, so a
// PIN set through any one of them authenticates through the others.
//
//   - No strategy persisted yet (fresh install, or PIN state that
//     predates this package): Resolve auto-selects via pinselect's
//     hardware-first preference and PERSISTS the result, so every entry
//     point converges on the same backend from then on.
//   - A strategy IS persisted: Resolve builds exactly that backend. It
//     never substitutes a different one on failure — an unavailable
//     governing provider is *ProviderUnavailableError, not a silent
//     fallback to software (go-xkms#307).
func Resolve(cfg Config) (qrdbsdk.PINBackend, qrdbsdk.PINStrategyID, error) {
	persisted, err := Load(cfg.PINDir)
	switch {
	case errors.Is(err, ErrStrategyNotPersisted):
		return selectAndPersist(cfg)
	case err != nil:
		return nil, "", err
	}

	return buildGoverning(cfg.PINSelectConfig, persisted)
}

// selectAndPersist runs pinselect's hardware-first preference to choose a
// backend for a PIN directory with no recorded strategy, then persists
// the choice so it governs from now on.
func selectAndPersist(cfg Config) (qrdbsdk.PINBackend, qrdbsdk.PINStrategyID, error) {
	backend, err := xkmssdk.SelectPINBackend(cfg.PINSelectConfig)
	if err != nil {
		return nil, "", err
	}

	strategy := backend.Strategy()
	if err := Save(cfg.PINDir, strategy); err != nil {
		return nil, "", err
	}

	return backend, strategy, nil
}

// buildGoverning constructs exactly the backend named by strategy,
// returning *ProviderUnavailableError when the required provider cannot
// answer right now. Unlike xkmssdk.SelectPINBackend, it never falls
// through to a different strategy: the persisted value already made the
// choice.
func buildGoverning(cfg xkmssdk.PINSelectConfig, strategy qrdbsdk.PINStrategyID) (qrdbsdk.PINBackend, qrdbsdk.PINStrategyID, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	switch strategy {
	case qrdbsdk.PINStrategyTPM2:
		if cfg.TPM == nil {
			return nil, "", &ProviderUnavailableError{Strategy: strategy}
		}
		pa, ok := cfg.TPM.PlatformAuth()
		if !ok {
			return nil, "", &ProviderUnavailableError{Strategy: strategy}
		}
		logger.Info("PIN backend: governing strategy", slog.String("strategy", string(strategy)))
		return xkmssdk.NewPINTPMBackend(pa), strategy, nil

	case qrdbsdk.PINStrategyPKCS11:
		if cfg.PKCS11 == nil {
			return nil, "", &ProviderUnavailableError{Strategy: strategy}
		}
		backend, ok := cfg.PKCS11.Backend()
		if !ok {
			return nil, "", &ProviderUnavailableError{Strategy: strategy}
		}
		logger.Info("PIN backend: governing strategy", slog.String("strategy", string(strategy)))
		return backend, strategy, nil

	case qrdbsdk.PINStrategySoftware:
		if cfg.Software == nil {
			return nil, "", xkmssdk.ErrPINSelectNoSoftwareProvider
		}
		store, err := cfg.Software.Storage()
		if err != nil {
			return nil, "", &xkmssdk.PINSelectSoftwareStorageError{Cause: err}
		}
		backend, err := qrdbsdk.NewSoftwareBackend(store, cfg.Software.HashConfig())
		if err != nil {
			return nil, "", &xkmssdk.PINSelectSoftwareStorageError{Cause: err}
		}
		logger.Info("PIN backend: governing strategy", slog.String("strategy", string(strategy)))
		return backend, strategy, nil

	default:
		return nil, "", &UnknownStrategyError{Strategy: strategy}
	}
}
