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

package pinselect

import (
	"errors"
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/pintpm2"
)

// StrategyAuto selects the PIN backend by pinselect's hardware-first
// preference (DefaultPreference). It is what an empty strategy means too.
const StrategyAuto qrdbsdk.PINStrategyID = "auto"

// ResolveConfig drives Resolve. It embeds Config so the TPM, PKCS#11 and
// software provider adapters are supplied exactly as a caller would supply
// them to Select directly.
type ResolveConfig struct {
	Config

	// PINDir is the directory holding PIN state (<dataDir>/pin by
	// default); <PINDir>/strategy records the governing PIN strategy,
	// beside the qrdb software store's own <PINDir>/{so-pin,user-pin}.
	PINDir string

	// Strategy is the operator-configured PIN strategy: StrategyAuto (or
	// empty) for the hardware-first choice, or one of the qrdb
	// PINStrategy IDs to demand that backend exactly. xkmsd passes its
	// pin.strategy setting; xKey passes StrategyAuto.
	Strategy qrdbsdk.PINStrategyID
}

// Resolve returns the PINBackend for PINDir's governing strategy, and the
// strategy ID that governs. It is the ONE selection point xkmsd, the xKey
// GUI, the headless daemon and `xkey pin` all call, so a PIN set through
// any one of them authenticates through the others.
//
//   - No strategy persisted yet (fresh install, or PIN state that
//     predates the record): an automatic strategy selects via pinselect's
//     hardware-first preference, an explicit one builds exactly that
//     backend, and the result is PERSISTED so every entry point converges
//     on the same backend from then on.
//   - A strategy IS persisted: Resolve builds exactly that backend. It
//     never substitutes a different one on failure — an unavailable
//     governing provider is *ProviderUnavailableError, not a silent
//     fallback to software (go-xkms#307). An explicit strategy that
//     differs from the record is *StrategyMismatchError: switching would
//     orphan every PIN set under the recorded backend.
func Resolve(cfg ResolveConfig) (qrdbsdk.PINBackend, qrdbsdk.PINStrategyID, error) {
	configured := cfg.Strategy
	if configured == "" {
		configured = StrategyAuto
	}

	persisted, err := LoadStrategy(cfg.PINDir)
	switch {
	case errors.Is(err, ErrStrategyNotPersisted):
		if configured == StrategyAuto {
			return selectAndPersist(cfg)
		}
		return buildAndPersist(cfg, configured)
	case err != nil:
		return nil, "", err
	}

	if configured != StrategyAuto && configured != persisted {
		return nil, "", &StrategyMismatchError{Configured: configured, Persisted: persisted}
	}
	return buildGoverning(cfg.Config, persisted)
}

// buildAndPersist builds exactly the configured strategy's backend for a
// PIN directory with no recorded strategy, and records it only once the
// backend exists, so a refused build leaves nothing a later start trusts.
func buildAndPersist(cfg ResolveConfig, strategy qrdbsdk.PINStrategyID) (qrdbsdk.PINBackend, qrdbsdk.PINStrategyID, error) {
	backend, governing, err := buildGoverning(cfg.Config, strategy)
	if err != nil {
		return nil, "", err
	}
	if err := SaveStrategy(cfg.PINDir, governing); err != nil {
		return nil, "", err
	}
	return backend, governing, nil
}

// selectAndPersist runs pinselect's hardware-first preference to choose a
// backend for a PIN directory with no recorded strategy, then persists
// the choice so it governs from now on.
func selectAndPersist(cfg ResolveConfig) (qrdbsdk.PINBackend, qrdbsdk.PINStrategyID, error) {
	backend, err := Select(cfg.Config)
	if err != nil {
		return nil, "", err
	}

	strategy := backend.Strategy()
	if err := SaveStrategy(cfg.PINDir, strategy); err != nil {
		return nil, "", err
	}

	return backend, strategy, nil
}

// buildGoverning constructs exactly the backend named by strategy,
// returning *ProviderUnavailableError when the required provider cannot
// answer right now. Unlike Select, it never falls
// through to a different strategy: the persisted value already made the
// choice.
func buildGoverning(cfg Config, strategy qrdbsdk.PINStrategyID) (qrdbsdk.PINBackend, qrdbsdk.PINStrategyID, error) {
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
		return pintpm2.NewTPM2Backend(pa), strategy, nil

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
			return nil, "", ErrNoSoftwareProvider
		}
		store, err := cfg.Software.Storage()
		if err != nil {
			return nil, "", &SoftwareStorageError{Cause: err}
		}
		backend, err := qrdbsdk.NewSoftwareBackend(store, cfg.Software.HashConfig())
		if err != nil {
			return nil, "", &SoftwareStorageError{Cause: err}
		}
		logger.Info("PIN backend: governing strategy", slog.String("strategy", string(strategy)))
		return backend, strategy, nil

	default:
		return nil, "", &UnknownStrategyError{Strategy: strategy}
	}
}
