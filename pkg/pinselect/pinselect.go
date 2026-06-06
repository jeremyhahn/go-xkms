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

// Package pinselect is the single, shared decision point for choosing a
// qrdb PINBackend across every go-xkms consumer (the xKey GUI and the
// quicbaasd daemon). It removes the duplicated "try TPM, else software"
// selection logic that previously lived inline in each caller.
//
// The security model is encoded here, not in the callers:
//
//   - TPM2 and PKCS#11 backends VERIFY PINS IN HARDWARE and inherit the
//     device's dictionary-attack lockout. They never persist a PIN hash.
//   - The software backend is the always-available fallback. It is the ONLY
//     backend that persists a (salted, Argon2id/PBKDF2) hash, because it has
//     no hardware to delegate to. Prefer hardware in production.
//
// Callers supply small environment adapters (how to reach the TPM, how to
// reach a token, where software PIN state persists); pinselect owns the
// preference order and availability rules. This keeps the decision DRY and
// uniform while letting each environment plug in its own provisioning model.
package pinselect

import (
	"log/slog"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/pintpm2"
)

// TPMProvider yields a TPM PlatformAuthProvider when a provisioned TPM whose
// PlatformSRK auth is usable IN THE CURRENT ENVIRONMENT is available. The
// "usable" judgement is the caller's: the xKey GUI confirms it via the
// enrollment wizard; the quicbaasd daemon ties it to an active, provisioned
// TPM2 seal strategy. Returning (nil, false) makes Select fall through to the
// next strategy in the preference order.
type TPMProvider interface {
	PlatformAuth() (pintpm2.PlatformAuthProvider, bool)
}

// PKCS11Provider yields a ready PKCS#11-backed PINBackend when a token is
// present. It returns a fully-constructed backend (rather than a lower-level
// auth provider) so pinselect carries no dependency on a concrete PKCS#11 PIN
// implementation: the backend is built only when a deployment needs it.
// Returning (nil, false) makes Select fall through.
type PKCS11Provider interface {
	Backend() (qrdbsdk.PINBackend, bool)
}

// SoftwareProvider supplies the persistent storage and hash parameters for the
// always-available software fallback. It is required: Select must always be
// able to produce a usable backend.
type SoftwareProvider interface {
	Storage() (qrdbsdk.PINStorage, error)
	HashConfig() qrdbsdk.PINHashConfig
}

// DefaultPreference is the canonical hardware-first order: TPM2, then PKCS#11,
// then software. Hardware backends are preferred because they verify in-device
// with native lockout and never persist a hash.
var DefaultPreference = []qrdbsdk.PINStrategyID{
	qrdbsdk.PINStrategyTPM2,
	qrdbsdk.PINStrategyPKCS11,
	qrdbsdk.PINStrategySoftware,
}

// Config drives Select. TPM and PKCS11 are optional (nil means "this
// environment has no such device"); Software is required.
type Config struct {
	// TPM, when non-nil and reporting an available provisioned TPM, yields the
	// TPM2 PIN backend.
	TPM TPMProvider

	// PKCS11, when non-nil and reporting a present token, yields the PKCS#11
	// PIN backend.
	PKCS11 PKCS11Provider

	// Software is the mandatory fallback provider.
	Software SoftwareProvider

	// Preference overrides DefaultPreference when set. Unknown strategy IDs
	// are skipped. Software should always appear (last) so Select can resolve.
	Preference []qrdbsdk.PINStrategyID

	// Logger receives the single "PIN backend: <strategy>" decision line. Nil
	// defaults to slog.Default().
	Logger *slog.Logger
}

// Select returns the highest-preference available PINBackend. With the default
// preference order the software fallback is always reachable, so Select returns
// a usable backend unless the software provider's storage cannot be opened.
func Select(cfg Config) (qrdbsdk.PINBackend, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Software == nil {
		return nil, ErrNoSoftwareProvider
	}

	order := cfg.Preference
	if len(order) == 0 {
		order = DefaultPreference
	}

	for _, id := range order {
		switch id {
		case qrdbsdk.PINStrategyTPM2:
			if cfg.TPM == nil {
				continue
			}
			pa, ok := cfg.TPM.PlatformAuth()
			if !ok {
				continue
			}
			logger.Info("PIN backend selected", slog.String("strategy", string(qrdbsdk.PINStrategyTPM2)))
			return pintpm2.NewTPM2Backend(pa), nil

		case qrdbsdk.PINStrategyPKCS11:
			if cfg.PKCS11 == nil {
				continue
			}
			backend, ok := cfg.PKCS11.Backend()
			if !ok {
				continue
			}
			logger.Info("PIN backend selected", slog.String("strategy", string(qrdbsdk.PINStrategyPKCS11)))
			return backend, nil

		case qrdbsdk.PINStrategySoftware:
			store, err := cfg.Software.Storage()
			if err != nil {
				return nil, &SoftwareStorageError{Cause: err}
			}
			backend, err := qrdbsdk.NewSoftwareBackend(store, cfg.Software.HashConfig())
			if err != nil {
				return nil, &SoftwareStorageError{Cause: err}
			}
			logger.Info("PIN backend selected", slog.String("strategy", string(qrdbsdk.PINStrategySoftware)))
			return backend, nil
		}
	}

	// No software entry in a custom preference order and no hardware available.
	return nil, ErrNoBackendAvailable
}
