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

package xkms

import (
	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	trustbootstrap "github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	trustfetcher "github.com/jeremyhahn/go-xkms/pkg/trust/fetcher"
	pkgresolver "github.com/jeremyhahn/go-xkms/pkg/trust/resolver"
)

// Trust-bootstrap surface re-exported so first-contact clients (the xkey
// GUI/CLI) dispatch CA-bundle fetch+verify through the canonical
// pkg/trust/bootstrap library via the SDK. Identifiers carry TrustBootstrap*/
// TrustFetcher* prefixes because the bare Config/Fetch/Options names collide
// across the two packages and the flat SDK namespace.

// --- Mode dispatch (pkg/trust/bootstrap) ---

// TrustBootstrapMode selects the trust-bootstrap verification mode.
type TrustBootstrapMode = trustbootstrap.Mode

const (
	// TrustBootstrapModeDANE verifies the CA bundle via DANE TLSA records.
	TrustBootstrapModeDANE = trustbootstrap.ModeDANE
	// TrustBootstrapModeNoise verifies via a Noise-pinned channel.
	TrustBootstrapModeNoise = trustbootstrap.ModeNoise
	// TrustBootstrapModeSPKI verifies via an SPKI pin.
	TrustBootstrapModeSPKI = trustbootstrap.ModeSPKI
	// TrustBootstrapModeDirect verifies via the system trust store.
	TrustBootstrapModeDirect = trustbootstrap.ModeDirect
	// TrustBootstrapModeTOFU uses trust-on-first-use SPKI pinning.
	// Requires TrustBootstrapTOFUConfig.PinStore.
	TrustBootstrapModeTOFU = trustbootstrap.ModeTOFU
)

// TrustBootstrapConfig configures a trust-bootstrap dispatch.
type TrustBootstrapConfig = trustbootstrap.Config

// TrustBootstrapDANEConfig configures DANE-mode bootstrap.
type TrustBootstrapDANEConfig = trustbootstrap.DANEConfig

// TrustBootstrapNoiseConfig configures Noise-mode bootstrap.
type TrustBootstrapNoiseConfig = trustbootstrap.NoiseConfig

// TrustBootstrapSPKIConfig configures SPKI-mode bootstrap.
type TrustBootstrapSPKIConfig = trustbootstrap.SPKIConfig

// TrustBootstrapDirectConfig configures Direct-mode bootstrap.
type TrustBootstrapDirectConfig = trustbootstrap.DirectConfig

// TrustBootstrapTOFUConfig configures TOFU-mode bootstrap.
// PinStore is required; use TrustBootstrapNewStoragePinStore to wrap
// any storage.Backend.
type TrustBootstrapTOFUConfig = trustbootstrap.TOFUConfig

// TrustBootstrapPin is the TOFU pin record type re-exported from go-truststrap.
type TrustBootstrapPin = truststrap.Pin

// TrustBootstrapPinStore is the TOFU pin persistence interface re-exported
// from go-truststrap. Implement it or use TrustBootstrapNewStoragePinStore
// to get a qrdb-backed implementation.
type TrustBootstrapPinStore = truststrap.PinStore

// TrustBootstrapStoragePinStore implements TrustBootstrapPinStore over a
// storage.Backend. Backed by any xkms storage engine (memory, file,
// PebbleDB, or a Raft-replicated qrdb cluster).
type TrustBootstrapStoragePinStore = trustbootstrap.StoragePinStore

// TrustBootstrapNewStoragePinStore creates a TrustBootstrapStoragePinStore
// backed by the given storage.Backend. Returns an error when backend is nil.
var TrustBootstrapNewStoragePinStore = trustbootstrap.NewStoragePinStore

// TrustBootstrapFetch fetches and verifies a CA bundle per the configured mode.
var TrustBootstrapFetch = trustbootstrap.Fetch

// --- CA-bundle fetcher (pkg/trust/fetcher) ---

// TrustFetcherOptions configures a raw CA-bundle fetch.
type TrustFetcherOptions = trustfetcher.Options

// TrustFetcherDefaultBundlePath is the default CA-bundle endpoint path.
const TrustFetcherDefaultBundlePath = trustfetcher.DefaultBundlePath

// TrustFetcherDefaultTimeout is the default CA-bundle fetch timeout.
const TrustFetcherDefaultTimeout = trustfetcher.DefaultTimeout

// TrustFetcherFetch fetches a CA bundle from a URL with the given options.
var TrustFetcherFetch = trustfetcher.Fetch

// TrustFetcherSPKIHash computes the SPKI SHA-256 pin for a certificate.
var TrustFetcherSPKIHash = trustfetcher.SPKIHash

// --- Trust resolver (pkg/trust/resolver) ---

// TrustResolverConfig is the top-level trust: configuration for the
// generic scope-keyed strategy-chain resolver.
type TrustResolverConfig = pkgresolver.Config

// TrustResolverScopeConfig configures a single trust scope.
type TrustResolverScopeConfig = pkgresolver.ScopeConfig

// TrustResolverDANEConfig configures the DANE/TLSA resolver.
type TrustResolverDANEConfig = pkgresolver.DANEConfig

// TrustResolverNoiseConfig configures the Noise_NK client.
type TrustResolverNoiseConfig = pkgresolver.NoiseConfig

// TrustResolverSPKIConfig configures the SPKI pin.
type TrustResolverSPKIConfig = pkgresolver.SPKIConfig

// TrustResolverTOFUScopeConfig holds per-scope TOFU knobs.
type TrustResolverTOFUScopeConfig = pkgresolver.TOFUScopeConfig

// TrustResolver resolves trust material for a (scope, endpoint) pair by
// walking the scope's ordered strategy chain.
type TrustResolver = pkgresolver.Resolver

// TrustResolverPinStore supplies per-endpoint SPKI pins.
type TrustResolverPinStore = pkgresolver.PinStore

// TrustResolverCABundleProvider supplies a CA bundle PEM for the
// provider-ca strategy.
type TrustResolverCABundleProvider = pkgresolver.CABundleProvider

// TrustResolverOption configures optional resolver collaborators.
type TrustResolverOption = pkgresolver.Option

// TrustResolverAttempt records the outcome of a single strategy attempt.
type TrustResolverAttempt = pkgresolver.Attempt

// TrustResolverStrategy identifies a single trust-establishment method.
type TrustResolverStrategy = pkgresolver.Strategy

// TrustResolver strategy constants.
const (
	TrustResolverStrategyDANE       = pkgresolver.StrategyDANE
	TrustResolverStrategyNoise      = pkgresolver.StrategyNoise
	TrustResolverStrategySPKI       = pkgresolver.StrategySPKI
	TrustResolverStrategyEmbedded   = pkgresolver.StrategyEmbedded
	TrustResolverStrategyCAFile     = pkgresolver.StrategyCAFile
	TrustResolverStrategyProviderCA = pkgresolver.StrategyProviderCA
	TrustResolverStrategyTOFU       = pkgresolver.StrategyTOFU
)

// TrustResolverNew validates the configuration and constructs a TrustResolver.
var TrustResolverNew = pkgresolver.New

// TrustResolverDefaultConfig returns a TrustResolverConfig pre-configured
// with the standard fetch chain (dane, noise, spki) and a 5-second
// per-method timeout.
var TrustResolverDefaultConfig = pkgresolver.DefaultConfig

// TrustResolverWithLogger sets the slog logger used for strategy diagnostics.
var TrustResolverWithLogger = pkgresolver.WithLogger

// TrustResolverWithPinStore injects a per-endpoint SPKI pin source.
var TrustResolverWithPinStore = pkgresolver.WithPinStore

// TrustResolverWithCABundleProvider injects the CA bundle source for the
// provider-ca strategy.
var TrustResolverWithCABundleProvider = pkgresolver.WithCABundleProvider

// TrustResolverWithTOFUPinStore injects the TOFU pin persistence store
// required by the tofu strategy.
var TrustResolverWithTOFUPinStore = pkgresolver.WithTOFUPinStore

// TrustResolverWithTOFUConfirmFunc injects an optional confirmation hook
// called before a newly captured TOFU pin is persisted.
var TrustResolverWithTOFUConfirmFunc = pkgresolver.WithTOFUConfirmFunc

// TrustResolverInstallToSystemTrust writes the PEM-encoded CA bundle to
// the given certificate path, creating parent directories as needed.
var TrustResolverInstallToSystemTrust = pkgresolver.InstallToSystemTrust
