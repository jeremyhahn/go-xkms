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
	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// Server-side surface for the FIPS-approved bootstrap suite,
// TSBOOT1_P256_AESGCM_SHA256, alongside the Noise_NK re-exports in
// noise_server.go.
//
// It exists because Noise_NK mandates X25519, which SP 800-56A Rev. 3 does not
// approve: go-truststrap's Noise DH is compiled out under the `fips` build tag
// and every entry point returns ErrFIPSUnsupported, so a FIPS build had no
// working bootstrap handshake at all. Consumers reach go-truststrap only
// through this package, so the approved suite has to surface here or it cannot
// be reached from quicbaas or go-trusted-platform (go-xkms#269).
//
// The shape deliberately mirrors the Noise set name for name -- StaticKey,
// Generate/Encode/Decode, HexKeySize -- because p256proto mirrors noiseproto's
// surface. A reader who knows one knows the other, and the pairing makes an
// omission on either side visible.

// P256StaticKey is a P-256 static key pair for the TSBOOT1_P256_AESGCM_SHA256
// handshake. Like NoiseStaticKey, its private scalar lives in protected memory
// outside the Go heap and the owner must Destroy it once every session built
// from it has finished.
//
// Pass it to a NoiseServerConfig's P256StaticKey field. Unlike the Noise key it
// needs no adapter: the config takes this type directly.
type P256StaticKey = p256proto.StaticKey

// P256HexKeySize is the required length of an EncodeP256StaticKey destination
// buffer.
const P256HexKeySize = p256proto.HexKeySize

// P256PublicKeySize is the length of an uncompressed P-256 point
// (0x04 || X || Y), the form a client is provisioned with as the server's
// pinned responder key.
const P256PublicKeySize = p256proto.PublicKeySize

// GenerateP256StaticKey generates a P-256 static key pair for the approved
// handshake, with the private scalar drawn straight into protected memory by
// rejection sampling -- it is never materialised as an ordinary heap slice.
// The caller owns the key and must Destroy it.
//
// Unlike GenerateNoiseStaticKey this succeeds in a FIPS build, which is the
// whole point of the suite.
var GenerateP256StaticKey = p256proto.GenerateStaticKey

// NewP256StaticKey reconstructs a P-256 static key from a scalar already held
// in protected memory.
var NewP256StaticKey = p256proto.NewStaticKey

// EncodeP256StaticKey hex-encodes a P-256 static private key into the caller's
// buffer, which must be at least P256HexKeySize bytes and should itself be
// protected memory. As with the Noise form there is deliberately no
// encode-to-string variant: a Go string is immutable and cannot be wiped.
var EncodeP256StaticKey = p256proto.EncodeStaticKey

// DecodeP256StaticKey decodes a hex-encoded P-256 static key into protected
// memory. The encoded buffer stays the caller's to wipe.
var DecodeP256StaticKey = p256proto.DecodeStaticKey
