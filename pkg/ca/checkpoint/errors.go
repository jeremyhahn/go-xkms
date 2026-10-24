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

package checkpoint

import "errors"

// Checkpoint body errors (tlog-checkpoint §Note text).
var (
	// ErrMalformedCheckpoint indicates note text that is not a checkpoint
	// body: fewer than three lines, an empty line, a missing final newline,
	// or a line that cannot be encoded.
	ErrMalformedCheckpoint = errors.New("checkpoint: malformed checkpoint")

	// ErrInvalidTreeSize indicates a tree size that is not an ASCII decimal
	// without extra leading zeros, or does not fit in 64 bits.
	ErrInvalidTreeSize = errors.New("checkpoint: invalid tree size")

	// ErrInvalidRootHash indicates a root hash that is not the canonical
	// base64 encoding of a 32-byte RFC 6962 SHA-256 Merkle tree root.
	ErrInvalidRootHash = errors.New("checkpoint: invalid root hash")
)

// Signed note errors (signed-note §Format, §Signatures).
var (
	// ErrMalformedNote indicates a note that is not valid UTF-8, contains
	// a control character other than newline, lacks the blank line that
	// separates text from signatures, or has a malformed signature line.
	ErrMalformedNote = errors.New("checkpoint: malformed signed note")

	// ErrInvalidText indicates note text that cannot be signed: empty, not
	// ending in newline, not valid UTF-8, or containing a control character
	// other than newline.
	ErrInvalidText = errors.New("checkpoint: invalid note text")

	// ErrInvalidKeyName indicates a key name that is empty or contains a
	// Unicode space or a plus sign.
	ErrInvalidKeyName = errors.New("checkpoint: invalid key name")

	// ErrTooManySignatures indicates a note carrying more signature lines
	// than MaxSignatures.
	ErrTooManySignatures = errors.New("checkpoint: too many signatures")

	// ErrDuplicateSignature indicates two signature lines with both the same
	// key name and the same key ID (tlog-checkpoint §Signatures).
	ErrDuplicateSignature = errors.New("checkpoint: duplicate signature")

	// ErrSignatureInvalid indicates a signature from a known key that does
	// not verify; the whole note is refused.
	ErrSignatureInvalid = errors.New("checkpoint: signature from a known key does not verify")

	// ErrNoValidSignature indicates a note with no signature from a known
	// key.
	ErrNoValidSignature = errors.New("checkpoint: no signature from a known key")

	// ErrNoSigner indicates a Sign call without a signer.
	ErrNoSigner = errors.New("checkpoint: no signer")

	// ErrNoVerifier indicates an Open call without a verifier.
	ErrNoVerifier = errors.New("checkpoint: no verifier")

	// ErrDuplicateVerifier indicates two verifiers sharing both a key name
	// and a key ID, which would make a signature ambiguous.
	ErrDuplicateVerifier = errors.New("checkpoint: duplicate verifier")

	// ErrSigningFailed indicates the crypto.Signer refused to sign.
	ErrSigningFailed = errors.New("checkpoint: signing failed")
)

// Verifier key errors (signed-note §Verifier keys).
var (
	// ErrMalformedVerifierKey indicates a verifier key that is not
	// <name>+<8 lowercase hex>+<canonical base64>.
	ErrMalformedVerifierKey = errors.New("checkpoint: malformed verifier key")

	// ErrKeyIDMismatch indicates a verifier key whose key ID is not the one
	// its algorithm derives from the key name and public key.
	ErrKeyIDMismatch = errors.New("checkpoint: verifier key ID does not match the key")
)

// Algorithm registry errors (owner ruling 122, signed-note §Signature types).
var (
	// ErrUnknownAlgorithm indicates a signature type, extended identifier
	// or algorithm ID that no registered algorithm carries.
	ErrUnknownAlgorithm = errors.New("checkpoint: unknown signature algorithm")

	// ErrUnsupportedKey indicates a public key that no registered algorithm
	// signs with, or that the chosen algorithm cannot encode.
	ErrUnsupportedKey = errors.New("checkpoint: unsupported public key")

	// ErrAmbiguousAlgorithm indicates a key that more than one registered
	// algorithm accepts, none of them with an assigned type byte; the
	// configuration must name one with WithAlgorithm.
	ErrAmbiguousAlgorithm = errors.New("checkpoint: key matches more than one algorithm")

	// ErrInvalidAlgorithm indicates an algorithm definition with a missing
	// ID or function, or an extended identifier that cannot be encoded.
	ErrInvalidAlgorithm = errors.New("checkpoint: invalid algorithm definition")

	// ErrReservedType indicates a registration for a signature type byte
	// that signed-note §Signature types reserves or has not assigned.
	ErrReservedType = errors.New("checkpoint: reserved or unassigned signature type")

	// ErrDuplicateAlgorithm indicates a registration whose ID or signature
	// type is already registered.
	ErrDuplicateAlgorithm = errors.New("checkpoint: algorithm already registered")
)
