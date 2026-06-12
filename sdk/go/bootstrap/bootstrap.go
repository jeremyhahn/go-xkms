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

// Package bootstrap is the SDK re-export of the canonical trust-bootstrap
// dispatch (pkg/trust/bootstrap: DANE / Noise / SPKI / Direct / Auto / TOFU).
// Client binaries import this package instead of pkg/trust/bootstrap.
package bootstrap

import (
	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	pkgbootstrap "github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// Re-exported types.
type (
	Config       = pkgbootstrap.Config
	Mode         = pkgbootstrap.Mode
	CABundle     = pkgbootstrap.CABundle
	DANEConfig   = pkgbootstrap.DANEConfig
	NoiseConfig  = pkgbootstrap.NoiseConfig
	SPKIConfig   = pkgbootstrap.SPKIConfig
	DirectConfig = pkgbootstrap.DirectConfig
	// TOFUConfig configures the trust-on-first-use bootstrap mode.
	TOFUConfig = pkgbootstrap.TOFUConfig

	// StoragePinStore implements truststrap.PinStore over a storage.Backend.
	// Use NewStoragePinStore to construct one.
	StoragePinStore = pkgbootstrap.StoragePinStore

	// Pin is the truststrap TOFU pin record re-exported for SDK callers.
	Pin = truststrap.Pin

	// PinStore is the truststrap PinStore interface re-exported for SDK callers.
	PinStore = truststrap.PinStore

	// MemoryPinStore is the truststrap in-memory PinStore re-exported for SDK
	// callers that need run-scoped TOFU pins with no on-disk persistence
	// (e.g. greenfield bootstrap before any storage backend exists).
	MemoryPinStore = truststrap.MemoryPinStore
)

// Re-exported mode constants.
const (
	ModeAuto   = pkgbootstrap.ModeAuto
	ModeDANE   = pkgbootstrap.ModeDANE
	ModeNoise  = pkgbootstrap.ModeNoise
	ModeSPKI   = pkgbootstrap.ModeSPKI
	ModeDirect = pkgbootstrap.ModeDirect
	// ModeTOFU selects trust-on-first-use bootstrap. Requires TOFUConfig.PinStore.
	ModeTOFU = pkgbootstrap.ModeTOFU
)

// Re-exported dispatch entry point.
var Fetch = pkgbootstrap.Fetch

// DefaultNoisePort is the well-known port the Noise bootstrap channel
// listens on; used by DeriveNoiseAddr when callers don't supply one.
const DefaultNoisePort = pkgbootstrap.DefaultNoisePort

// Re-exported typed errors.
var (
	// ErrInvalidMode is returned for an unrecognized bootstrap mode.
	ErrInvalidMode = pkgbootstrap.ErrInvalidMode
	// ErrModeNotConfigured is returned when the requested mode lacks its config.
	ErrModeNotConfigured = pkgbootstrap.ErrModeNotConfigured
	// ErrServerURLRequired is returned when no server URL is provided.
	ErrServerURLRequired = pkgbootstrap.ErrServerURLRequired
	// ErrFetch is the sentinel matched by errors.Is for any fetch failure.
	ErrFetch = pkgbootstrap.ErrFetch
)

// FetchError carries the attempted mode alongside the underlying cause.
type FetchError = pkgbootstrap.FetchError

// DeriveNoiseAddr extracts the host portion of a server URL and appends the
// default Noise bootstrap port.
var DeriveNoiseAddr = pkgbootstrap.DeriveNoiseAddr

// ErrHostnameRequired is returned by NewDANETLSConfig when no hostname is
// available for the TLSA lookup.
var ErrHostnameRequired = pkgbootstrap.ErrHostnameRequired

// Re-exported trust-verified tls.Config constructors (custom-verifier
// pattern; WebPKI verification is replaced by DANE/TLSA or SPKI-pin
// validation of the presented chain).
var (
	// NewDANETLSConfig builds a client *tls.Config whose sole certificate
	// verification is DANE/TLSA validation per RFC 7671.
	NewDANETLSConfig = pkgbootstrap.NewDANETLSConfig

	// NewSPKIPinTLSConfig builds a client *tls.Config whose sole certificate
	// verification is a SHA-256 SubjectPublicKeyInfo pin match.
	NewSPKIPinTLSConfig = pkgbootstrap.NewSPKIPinTLSConfig
)

// NewStoragePinStore creates a StoragePinStore backed by the given storage.Backend.
// Returns NilBackendError when backend is nil.
var NewStoragePinStore = pkgbootstrap.NewStoragePinStore

// NewMemoryPinStore creates an empty run-scoped in-memory MemoryPinStore.
var NewMemoryPinStore = truststrap.NewMemoryPinStore

// Server-side Noise_NK bootstrap surface (see pkg/trust/bootstrap). Consumers
// hosting a Noise bootstrap listener use these instead of go-truststrap.
type (
	// BundleProvider provides CA certificate bundles for trust bootstrapping.
	BundleProvider = pkgbootstrap.BundleProvider

	// NoiseStaticKey is a Curve25519 static key pair for the Noise_NK handshake.
	NoiseStaticKey = pkgbootstrap.NoiseStaticKey

	// NoiseServer serves CA bundles over Noise_NK encrypted TCP connections.
	NoiseServer = pkgbootstrap.NoiseServer

	// NoiseServerConfig configures the Noise_NK bootstrap server.
	NoiseServerConfig = pkgbootstrap.NoiseServerConfig

	// NoiseBundleProvider is the bundle source consumed by the Noise server.
	NoiseBundleProvider = pkgbootstrap.NoiseBundleProvider
)

// Re-exported Noise server constructors and key helpers.
var (
	// NewNoiseServer constructs a Noise_NK bootstrap server.
	NewNoiseServer = pkgbootstrap.NewNoiseServer

	// GenerateNoiseStaticKey generates a Curve25519 static key pair.
	GenerateNoiseStaticKey = pkgbootstrap.GenerateNoiseStaticKey

	// EncodeNoiseStaticKey encodes a Noise static key as a hex string.
	EncodeNoiseStaticKey = pkgbootstrap.EncodeNoiseStaticKey

	// DecodeNoiseStaticKey decodes a hex-encoded Noise static key.
	DecodeNoiseStaticKey = pkgbootstrap.DecodeNoiseStaticKey
)
