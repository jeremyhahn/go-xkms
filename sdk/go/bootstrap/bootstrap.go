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

	// NewTOFUTLSConfig builds a client *tls.Config whose sole certificate
	// verification is trust-on-first-use SPKI pinning against a PinStore,
	// keyed by endpoint: the first connection captures and persists the
	// leaf's pin, every later one must present it.
	NewTOFUTLSConfig = pkgbootstrap.NewTOFUTLSConfig
)

// ErrTOFUPinStoreRequired is returned by NewTOFUTLSConfig when no pin store
// is supplied.
var ErrTOFUPinStoreRequired = pkgbootstrap.ErrTOFUPinStoreRequired

// Typed errors of the TOFU TLS verifier.
type (
	// TOFUEndpointError reports an endpoint that is not a "host:port".
	TOFUEndpointError = pkgbootstrap.TOFUEndpointError
	// TOFUPinStoreError reports a pin store failure other than "no pin".
	TOFUPinStoreError = pkgbootstrap.TOFUPinStoreError
	// TOFUPinMismatchError reports a presented chain that does not carry
	// the pin recorded for the endpoint.
	TOFUPinMismatchError = pkgbootstrap.TOFUPinMismatchError
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

// NoiseHexKeySize is the buffer length EncodeNoiseStaticKey requires. It is
// re-exported because the encode direction writes into a caller-supplied
// buffer, so a consumer cannot size that buffer without it.
const NoiseHexKeySize = pkgbootstrap.NoiseHexKeySize

// Re-exported Noise server constructors and key helpers.
var (
	// NewNoiseServer constructs a Noise_NK bootstrap server.
	NewNoiseServer = pkgbootstrap.NewNoiseServer

	// GenerateNoiseStaticKey generates a Curve25519 static key pair.
	GenerateNoiseStaticKey = pkgbootstrap.GenerateNoiseStaticKey

	// EncodeNoiseStaticKey hex-encodes a Noise static private key into the
	// caller's buffer, which must be at least NoiseHexKeySize bytes and
	// should itself be protected memory: the encoded form is as sensitive as
	// the key. It does not return a string, because a Go string is immutable
	// and therefore cannot be wiped.
	EncodeNoiseStaticKey = pkgbootstrap.EncodeNoiseStaticKey

	// DecodeNoiseStaticKey decodes a hex-encoded Noise static key straight
	// into protected memory. The caller's encoded bytes remain theirs to wipe.
	DecodeNoiseStaticKey = pkgbootstrap.DecodeNoiseStaticKey

	// NoiseServerStaticKey adapts a protected NoiseStaticKey to the key pair
	// NoiseServerConfig.StaticKey takes. Without it an SDK-only consumer can
	// generate a protected key and has no way to give it to the server —
	// GenerateNoiseStaticKey and NoiseServerConfig were re-exported here
	// while the adapter that joins them was not, so the two halves compiled
	// individually and could not be used together.
	NoiseServerStaticKey = pkgbootstrap.NoiseServerStaticKey

	// WipeNoiseBytes zeroes a buffer that held Noise key material. Re-exported
	// because EncodeNoiseStaticKey hands the caller the responsibility for the
	// buffer it wrote into.
	WipeNoiseBytes = pkgbootstrap.WipeNoiseBytes
)

// The FIPS-approved bootstrap suite, TSBOOT1_P256_AESGCM_SHA256.
//
// Noise_NK mandates X25519, which SP 800-56A Rev. 3 does not approve, so
// go-truststrap compiles its Noise DH out under the `fips` build tag and a FIPS
// build had no working bootstrap handshake at all. This set is what an
// SDK-only consumer needs to run the approved one (go-xkms#269).
//
// It is re-exported COMPLETE, deliberately. The Noise set above records what a
// partial re-export costs: the generator and the config were exposed while the
// adapter joining them was not, so both halves compiled and could not be used
// together. A key type without its encoder, or a suite constant without the
// check that says whether this binary can run it, repeats that.

// P256StaticKey is a P-256 static key pair for the approved handshake. Its
// private scalar lives in protected memory; the owner must Destroy it.
//
// Unlike the Noise key it needs no adapter: NoiseServerConfig takes this type
// directly in its P256StaticKey field.
type P256StaticKey = pkgbootstrap.P256StaticKey

const (
	// P256HexKeySize is the buffer length EncodeP256StaticKey requires.
	P256HexKeySize = pkgbootstrap.P256HexKeySize

	// P256PublicKeySize is the length of the uncompressed P-256 point a client
	// is provisioned with as the server's pinned responder key.
	P256PublicKeySize = pkgbootstrap.P256PublicKeySize

	// SuiteNoiseNK identifies Noise_NK_25519_ChaChaPoly_SHA256 on the wire. It
	// is not FIPS-approved and is unavailable in a `fips` build.
	SuiteNoiseNK = pkgbootstrap.SuiteNoiseNK

	// SuiteP256AESGCM identifies TSBOOT1_P256_AESGCM_SHA256 on the wire.
	SuiteP256AESGCM = pkgbootstrap.SuiteP256AESGCM
)

// ErrSuiteUnavailable is the sentinel EnsureSuiteAvailable returns when this
// binary cannot run the named suite. Test for it with errors.Is.
var ErrSuiteUnavailable = pkgbootstrap.ErrSuiteUnavailable

// Re-exported P-256 key helpers and the suite availability check.
var (
	// GenerateP256StaticKey generates a P-256 static key pair with the private
	// scalar drawn straight into protected memory. It succeeds in a FIPS
	// build, which is the point of the suite.
	GenerateP256StaticKey = pkgbootstrap.GenerateP256StaticKey

	// NewP256StaticKey reconstructs a key from a scalar already in protected
	// memory.
	NewP256StaticKey = pkgbootstrap.NewP256StaticKey

	// EncodeP256StaticKey hex-encodes a P-256 static private key into the
	// caller's buffer, which must be at least P256HexKeySize bytes and should
	// itself be protected memory. As with the Noise form there is no
	// encode-to-string variant: a Go string cannot be wiped.
	EncodeP256StaticKey = pkgbootstrap.EncodeP256StaticKey

	// DecodeP256StaticKey decodes a hex-encoded P-256 static key into
	// protected memory. The caller's encoded bytes remain theirs to wipe.
	DecodeP256StaticKey = pkgbootstrap.DecodeP256StaticKey

	// EnsureSuiteAvailable reports whether this binary can run a suite,
	// returning a typed error when it cannot. Call it while CONFIGURING a
	// bootstrap listener so a build with no usable suite says so once and
	// actionably at startup, rather than binding a listener and refusing every
	// handshake.
	EnsureSuiteAvailable = pkgbootstrap.EnsureSuiteAvailable
)
