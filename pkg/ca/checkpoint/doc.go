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

// Package checkpoint implements transparency log checkpoints
// (c2sp.org/tlog-checkpoint) carried in signed notes (c2sp.org/signed-note),
// for the transparency-log SPEC row. Both specifications are copied under
// docs/references/.
//
// A Checkpoint is the note text: origin, decimal tree size, base64 root hash
// and optional extension lines (tlog-checkpoint §Note text). Sign and Open
// handle the signed note itself (signed-note §Format, §Signatures): Open
// ignores signatures from unknown keys, refuses a note when a known key's
// signature does not verify, and refuses a note with no verified signature.
// NewVerifier parses, and Signer.VerifierKey builds, the
// <name>+<hex(key ID)>+<base64(type || public key)> verifier key encoding
// (signed-note §Verifier keys).
//
// # Algorithms
//
// The signature algorithm is configurable and registrable (owner ruling
// 122). A Signer wraps a crypto.Signer, so the private key stays in its key
// provider, and its algorithm follows from the public key unless
// WithAlgorithm names one. Algorithms are dispatched from a registry keyed by
// ID and by type byte; Register adds an application's own algorithm.
//
// An algorithm that signed-note §Signature types assigns a type byte uses
// that byte: Ed25519 is 0x01 and witness ECDSA (P-256, P-384 or P-521 over
// SHA-256, DER SubjectPublicKeyInfo key, key ID SHA-256(SPKI)[:4]) is 0x02.
// Every other algorithm uses the extended type byte 0xff followed by its own
// identifier, encoded as
//
//	0xff || uint8(len(ID)) || ID
//
// in the verifier key and in the key ID hash, which signed-note §Signatures
// computes as SHA-256(name || 0x0A || type || public key)[:4]. The built-in
// extended identifiers are go-xkms/ecdsa-p224-sha256,
// go-xkms/ecdsa-p384-sha384, go-xkms/ecdsa-p521-sha512,
// go-xkms/rsa-pkcs1-sha{256,384,512}, go-xkms/rsa-pss-sha{256,384,512} and
// go-xkms/ml-dsa-{44,65,87}. Pure ML-DSA uses 0xff rather than 0x06, which
// signed-note assigns to the timestamped ML-DSA-44 checkpoint cosignature of
// c2sp.org/tlog-cosignature, a different signed message.
package checkpoint
