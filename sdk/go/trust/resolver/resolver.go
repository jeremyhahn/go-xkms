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

// Package resolver is the SDK re-export of the canonical trust resolver
// (pkg/trust/resolver: generic scope-keyed strategy-chain trust
// resolution with DANE / Noise / SPKI / TOFU / embedded / ca-file /
// provider-ca strategies). Client binaries import this package instead
// of pkg/trust/resolver.
package resolver

import (
	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	pkgconfig "github.com/jeremyhahn/go-xkms/pkg/config"
	pkgresolver "github.com/jeremyhahn/go-xkms/pkg/trust/resolver"
)

// Re-exported types.
type (
	// Config is the top-level trust: configuration.
	Config = pkgresolver.Config

	// ScopeConfig configures a single trust scope.
	ScopeConfig = pkgresolver.ScopeConfig

	// DANEConfig configures the DANE/TLSA resolver.
	DANEConfig = pkgresolver.DANEConfig

	// NoiseConfig configures the Noise_NK client.
	NoiseConfig = pkgresolver.NoiseConfig

	// SPKIConfig configures the SPKI pin.
	SPKIConfig = pkgresolver.SPKIConfig

	// TOFUScopeConfig holds per-scope TOFU knobs.
	TOFUScopeConfig = pkgresolver.TOFUScopeConfig

	// Resolver resolves trust material for a (scope, endpoint) pair.
	Resolver = pkgresolver.Resolver

	// PinStore supplies per-endpoint SPKI pins.
	PinStore = pkgresolver.PinStore

	// CABundleProvider supplies a CA bundle PEM for the provider-ca strategy.
	CABundleProvider = pkgresolver.CABundleProvider

	// Option configures optional resolver collaborators.
	Option = pkgresolver.Option

	// Attempt records the outcome of a single strategy attempt.
	Attempt = pkgresolver.Attempt

	// Strategy identifies a single trust-establishment method.
	Strategy = pkgresolver.Strategy

	// TOFUPinStore is the truststrap PinStore used by the tofu strategy.
	// Use TrustBootstrapNewStoragePinStore to construct a storage-backed instance.
	TOFUPinStore = truststrap.PinStore

	// TOFUPin is the truststrap Pin record used by the tofu strategy.
	TOFUPin = truststrap.Pin
)

// Re-exported strategy constants.
const (
	StrategyDANE       = pkgresolver.StrategyDANE
	StrategyNoise      = pkgresolver.StrategyNoise
	StrategySPKI       = pkgresolver.StrategySPKI
	StrategyEmbedded   = pkgresolver.StrategyEmbedded
	StrategyCAFile     = pkgresolver.StrategyCAFile
	StrategyProviderCA = pkgresolver.StrategyProviderCA
	StrategyTOFU       = pkgresolver.StrategyTOFU
)

// Re-exported typed errors.
type (
	ErrNilConfig             = pkgresolver.ErrNilConfig
	ErrScopeNotConfigured    = pkgresolver.ErrScopeNotConfigured
	ErrInvalidConfig         = pkgresolver.ErrInvalidConfig
	ErrFetchFailed           = pkgresolver.ErrFetchFailed
	ErrCABundleEmpty         = pkgresolver.ErrCABundleEmpty
	ErrCABundleParse         = pkgresolver.ErrCABundleParse
	ErrWriteFailed           = pkgresolver.ErrWriteFailed
	ErrProviderCAUnavailable = pkgresolver.ErrProviderCAUnavailable
	ErrPinNotFound           = pkgresolver.ErrPinNotFound
	ErrCAFileRead            = pkgresolver.ErrCAFileRead
	ErrEndpointInvalid       = pkgresolver.ErrEndpointInvalid
	ErrTOFUPinStoreRequired  = pkgresolver.ErrTOFUPinStoreRequired
	ErrNoStrategySucceeded   = pkgresolver.ErrNoStrategySucceeded
)

// Re-exported constructor and options.
var (
	// New validates the configuration and constructs a Resolver.
	New = pkgresolver.New

	// DefaultConfig returns a Config pre-configured with the standard
	// fetch chain (dane, noise, spki) and a 5-second per-method timeout.
	DefaultConfig = pkgresolver.DefaultConfig

	// WithLogger sets the slog logger used for strategy diagnostics.
	WithLogger = pkgresolver.WithLogger

	// WithPinStore injects a per-endpoint SPKI pin source.
	WithPinStore = pkgresolver.WithPinStore

	// WithCABundleProvider injects the CA bundle source for the
	// provider-ca strategy.
	WithCABundleProvider = pkgresolver.WithCABundleProvider

	// WithTOFUPinStore injects the TOFU pin persistence store required
	// by the tofu strategy.
	WithTOFUPinStore = pkgresolver.WithTOFUPinStore

	// WithTOFUConfirmFunc injects an optional confirmation hook called
	// before a newly captured TOFU pin is persisted.
	WithTOFUConfirmFunc = pkgresolver.WithTOFUConfirmFunc

	// InstallToSystemTrust writes the PEM-encoded CA bundle to the given
	// certificate path, creating parent directories as needed.
	InstallToSystemTrust = pkgresolver.InstallToSystemTrust
)

// LoadTrustConfig loads the xkmsd/xkmsctl config file at path and returns
// its trust: section. Client binaries use this instead of importing
// pkg/config directly to reach the trust-resolver Config embedded in the
// daemon config file.
func LoadTrustConfig(path string) (*Config, error) {
	cfg, err := pkgconfig.Load(path)
	if err != nil {
		return nil, err
	}
	return cfg.Trust, nil
}
