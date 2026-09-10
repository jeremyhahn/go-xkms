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

package bootstrap

import (
	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-truststrap/pkg/noiseproto"
	noiseboot "github.com/jeremyhahn/go-truststrap/pkg/noiseproto/bootstrap"
	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
)

// Server-side Noise_NK bootstrap surface. xkms is the single composition
// point for go-truststrap in the stack; consumers that host a Noise
// bootstrap listener (quicbaas, go-trusted-platform) reach the server
// primitives through these re-exports instead of importing go-truststrap
// directly.

// BundleProvider provides CA certificate bundles for trust bootstrapping.
// Any type implementing CABundle() ([]byte, error) satisfies it, including
// xkms's CA bundlers.
type BundleProvider = truststrap.BundleProvider

// NoiseStaticKey is a Curve25519 static key pair for the Noise_NK handshake.
// Its private scalar lives in protected memory outside the Go heap; the owner
// must Destroy it once every session built from it has finished.
//
// Pass it to a NoiseServerConfig with NoiseServerStaticKey.
type NoiseStaticKey = noiseproto.StaticKey

// NoiseHexKeySize is the required length of an EncodeNoiseStaticKey
// destination buffer.
const NoiseHexKeySize = noiseproto.HexKeySize

// NoiseServer serves CA certificate bundles over Noise_NK encrypted TCP
// connections for secure trust bootstrapping without TLS.
type NoiseServer = noiseboot.Server

// NoiseServerConfig configures the Noise_NK bootstrap server.
type NoiseServerConfig = noiseboot.ServerConfig

// NoiseBundleProvider is the bundle source consumed by the Noise server.
// It is structurally identical to BundleProvider.
type NoiseBundleProvider = noiseboot.BundleProvider

// NewNoiseServer constructs a Noise_NK bootstrap server.
var NewNoiseServer = noiseboot.NewServer

// The sentinels NoiseServer's lifecycle returns, re-exported so a consumer
// dispatches on them with errors.Is without importing go-truststrap, which
// only this package composes (go-xkms#498).
//
//   - ErrNoiseShutdownIncomplete: Stop's caller deadline expired before every
//     handshake worker drained; the static key was retained and a later Stop
//     may still complete the drain.
//   - ErrNoiseServerNotStarted: Stop before Start.
//   - ErrNoiseServerAlreadyStarted: Start on a server that already started;
//     a NoiseServer is single-use.
var (
	ErrNoiseShutdownIncomplete   = noiseboot.ErrShutdownIncomplete
	ErrNoiseServerNotStarted     = noiseboot.ErrServerNotStarted
	ErrNoiseServerAlreadyStarted = noiseboot.ErrServerAlreadyStarted
)

// NoiseServerStaticKey adapts a protected NoiseStaticKey to the key pair
// NoiseServerConfig.StaticKey takes:
//
//	key, err := bootstrap.GenerateNoiseStaticKey()
//	...
//	cfg := &bootstrap.NoiseServerConfig{
//		StaticKey: bootstrap.NoiseServerStaticKey(key),
//		...
//	}
//
// It exists because the two re-exports do not otherwise compose. NoiseStaticKey
// holds its private scalar in protected memory, while the server config takes a
// plain key pair, so assigning one to the other does not type-check and a
// consumer would have to reach into the embedded field itself — which means
// importing flynn/noise just to name a type this package already re-exports.
//
// The returned pair ALIASES key's protected pages. It stays valid exactly as
// long as key does, and destroying key invalidates any server still holding it.
func NoiseServerStaticKey(key *NoiseStaticKey) *noise.DHKey {
	if key == nil {
		return nil
	}
	return &key.DHKey
}

// GenerateNoiseStaticKey generates a Curve25519 static key pair for the
// Noise_NK handshake, with the private scalar drawn straight into protected
// memory. The caller owns the key and must Destroy it.
var GenerateNoiseStaticKey = noiseproto.GenerateStaticKey

// EncodeNoiseStaticKey hex-encodes a Noise static private key into the
// caller's buffer, which must be at least NoiseHexKeySize bytes and should
// itself be protected memory. There is deliberately no encode-to-string form:
// a Go string is immutable and cannot be wiped after use.
var EncodeNoiseStaticKey = noiseproto.EncodeStaticKey

// DecodeNoiseStaticKey decodes a hex-encoded Noise static key into protected
// memory. The encoded slice stays the caller's to wipe.
var DecodeNoiseStaticKey = noiseproto.DecodeStaticKey

// WipeNoiseBytes zeroes a buffer that held Noise key material.
var WipeNoiseBytes = noiseproto.WipeBytes
