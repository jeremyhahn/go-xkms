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
type NoiseStaticKey = noise.DHKey

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

// GenerateNoiseStaticKey generates a Curve25519 static key pair for the
// Noise_NK handshake.
var GenerateNoiseStaticKey = noiseproto.GenerateStaticKey

// EncodeNoiseStaticKey encodes a Noise static key as a hex string.
var EncodeNoiseStaticKey = noiseproto.EncodeStaticKey

// DecodeNoiseStaticKey decodes a hex-encoded Noise static key.
var DecodeNoiseStaticKey = noiseproto.DecodeStaticKey
