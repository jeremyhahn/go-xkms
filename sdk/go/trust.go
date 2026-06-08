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
	trustbootstrap "github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
	trustfetcher "github.com/jeremyhahn/go-xkms/pkg/trust/fetcher"
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
