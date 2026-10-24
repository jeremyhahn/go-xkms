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

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"maps"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// TypeExtended is the signature type byte signed-note §Signature types
// reserves for signature types without an assigned identifier byte. In this
// package it is always followed by the algorithm's extended identifier:
//
//	0xff || uint8(len(ID)) || ID
const TypeExtended byte = 0xff

// MaxIdentifierLength is the longest algorithm ID: an extended identifier's
// length is encoded in one byte.
const MaxIdentifierLength = 255

// assignedTypes are the signature type bytes signed-note §Signature types
// assigns to a signature type. Every other byte except TypeExtended is
// reserved (0x03, 0xfa–0xfe) or not yet assigned, and is refused.
var assignedTypes = map[byte]bool{
	0x01: true, // Ed25519 signatures
	0x02: true, // ECDSA signatures as implemented by transparency-dev/witness
	0x04: true, // timestamped Ed25519 checkpoint cosignatures
	0x05: true, // RFC 6962 TreeHeadSignatures
	0x06: true, // timestamped ML-DSA-44 checkpoint cosignatures
}

// An Algorithm is one note signature algorithm: how a key of that algorithm
// signs note text, how its public key is encoded in a verifier key, and how a
// signature is verified.
//
// An algorithm with a signature type byte assigned by signed-note
// §Signature types uses that byte as its Type. Every other algorithm, built
// in or registered, uses TypeExtended and is identified on the wire by its ID
// (owner ruling 122).
type Algorithm struct {
	// ID names the algorithm in the registry and in WithAlgorithm. For a
	// TypeExtended algorithm it is also the extended identifier written
	// after the 0xff byte, so it should be namespaced to avoid collisions
	// (signed-note §Signature types recommends "a longer identifier that is
	// unlikely to collide"), for example "example.com/my-algorithm". It is
	// 1 to MaxIdentifierLength bytes of printable ASCII without spaces.
	ID string

	// Type is the signature type byte: an assigned byte, or TypeExtended.
	Type byte

	// SignerOpts is passed to crypto.Signer.Sign. When its HashFunc is zero
	// the note text itself is signed; otherwise the text is hashed with
	// that function and the digest is signed.
	SignerOpts crypto.SignerOpts

	// EncodePublicKey returns the public key material of pub, or an error
	// when pub is not a key of this algorithm.
	EncodePublicKey func(pub crypto.PublicKey) ([]byte, error)

	// DecodePublicKey parses public key material written by
	// EncodePublicKey.
	DecodePublicKey func(material []byte) (crypto.PublicKey, error)

	// Verify reports whether sig is a valid signature of the note text
	// under pub.
	Verify func(pub crypto.PublicKey, text, sig []byte) bool

	// keyID derives the key ID. Nil selects the signed-note §Signatures
	// recommendation; only built-ins whose signature type defines its own
	// key ID set it.
	keyID func(name string, keyType, material []byte) uint32
}

// keyType returns the bytes that precede the public key in a verifier key
// and in the key ID hash: the type byte, followed for TypeExtended by the
// length-prefixed extended identifier.
func (a *Algorithm) keyType() []byte {
	if a.Type != TypeExtended {
		return []byte{a.Type}
	}
	out := make([]byte, 0, 2+len(a.ID))
	out = append(out, TypeExtended, byte(len(a.ID)))
	return append(out, a.ID...)
}

// computeKeyID derives the key ID of a key with this algorithm.
func (a *Algorithm) computeKeyID(name string, material []byte) uint32 {
	if a.keyID != nil {
		return a.keyID(name, a.keyType(), material)
	}
	return recommendedKeyID(name, a.keyType(), material)
}

// recommendedKeyID implements the signed-note §Signatures recommendation:
//
//	key ID = SHA-256(key name || 0x0A || signature type || public key)[:4]
//
// For a TypeExtended algorithm the signature type is the whole
// 0xff || length || identifier sequence, so two extended algorithms never
// share a key ID for the same name and key.
func recommendedKeyID(name string, keyType, material []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n'})
	h.Write(keyType)
	h.Write(material)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// registry is an immutable snapshot of the registered algorithms. A
// registration publishes a new snapshot, so lookups never lock.
type registry struct {
	byID   map[string]*Algorithm
	byType map[byte]*Algorithm
}

// algorithms is the current registry snapshot.
var algorithms atomic.Pointer[registry]

func init() {
	r := &registry{byID: map[string]*Algorithm{}, byType: map[byte]*Algorithm{}}
	for i := range builtinAlgorithms {
		r.add(&builtinAlgorithms[i])
	}
	algorithms.Store(r)
}

// add records alg in the snapshot under construction.
func (r *registry) add(alg *Algorithm) {
	r.byID[alg.ID] = alg
	if alg.Type != TypeExtended {
		r.byType[alg.Type] = alg
	}
}

// clone copies the snapshot so a registration can extend it.
func (r *registry) clone() *registry {
	return &registry{byID: maps.Clone(r.byID), byType: maps.Clone(r.byType)}
}

// Register adds an application's own note signature algorithm (owner ruling
// 122). The registry is safe for concurrent use; a registered algorithm is
// visible to every Signer and verifier key parsed after Register returns.
//
// An algorithm without an assigned signature type byte uses TypeExtended
// and is identified by its ID. An assigned byte (signed-note §Signature
// types) may be registered only while no algorithm holds it. Register
// refuses an incomplete definition (ErrInvalidAlgorithm), a reserved or
// unassigned type byte (ErrReservedType), and an ID or type byte that is
// already registered (ErrDuplicateAlgorithm).
func Register(alg Algorithm) error {
	if err := validateAlgorithm(&alg); err != nil {
		return err
	}
	for {
		current := algorithms.Load()
		if _, taken := current.byID[alg.ID]; taken {
			return &errs.Detail{Err: ErrDuplicateAlgorithm, Detail: alg.ID}
		}
		if _, taken := current.byType[alg.Type]; taken {
			return &errs.Detail{Err: ErrDuplicateAlgorithm, Detail: "signature type " + hexByte(alg.Type)}
		}
		next := current.clone()
		next.add(&alg)
		if algorithms.CompareAndSwap(current, next) {
			return nil
		}
	}
}

// validateAlgorithm refuses an algorithm definition that cannot be used.
func validateAlgorithm(alg *Algorithm) error {
	if !validIdentifier(alg.ID) {
		return &errs.Detail{Err: ErrInvalidAlgorithm, Detail: "ID must be 1-255 bytes of printable ASCII without spaces"}
	}
	if alg.SignerOpts == nil || alg.EncodePublicKey == nil || alg.DecodePublicKey == nil || alg.Verify == nil {
		return &errs.Detail{Err: ErrInvalidAlgorithm, Detail: alg.ID + ": SignerOpts, EncodePublicKey, DecodePublicKey and Verify are required"}
	}
	if alg.Type != TypeExtended && !assignedTypes[alg.Type] {
		return &errs.Detail{Err: ErrReservedType, Detail: hexByte(alg.Type)}
	}
	return nil
}

// validIdentifier reports whether id can be an algorithm ID: 1 to
// MaxIdentifierLength bytes in U+0021–U+007E.
func validIdentifier(id string) bool {
	if id == "" || len(id) > MaxIdentifierLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] <= ' ' || id[i] > '~' {
			return false
		}
	}
	return true
}

// lookupID returns the registered algorithm with the given ID.
func lookupID(id string) (*Algorithm, error) {
	alg, ok := algorithms.Load().byID[id]
	if !ok {
		return nil, &errs.Detail{Err: ErrUnknownAlgorithm, Detail: id}
	}
	return alg, nil
}

// lookupKeyType parses the signature type prefix of a verifier key's
// decoded key bytes and returns its algorithm and the remaining public key
// material.
func lookupKeyType(keyBytes []byte) (*Algorithm, []byte, error) {
	if len(keyBytes) < 2 {
		return nil, nil, &errs.Detail{Err: ErrMalformedVerifierKey, Detail: "key bytes too short"}
	}
	if keyBytes[0] != TypeExtended {
		alg, ok := algorithms.Load().byType[keyBytes[0]]
		if !ok {
			return nil, nil, &errs.Detail{Err: ErrUnknownAlgorithm, Detail: "signature type " + hexByte(keyBytes[0])}
		}
		return alg, keyBytes[1:], nil
	}
	n := int(keyBytes[1])
	if n == 0 || len(keyBytes) < 2+n+1 {
		return nil, nil, &errs.Detail{Err: ErrMalformedVerifierKey, Detail: "truncated extended identifier"}
	}
	alg, err := lookupID(string(keyBytes[2 : 2+n]))
	if err != nil {
		return nil, nil, err
	}
	if alg.Type != TypeExtended {
		return nil, nil, &errs.Detail{Err: ErrUnknownAlgorithm, Detail: alg.ID + " has an assigned signature type"}
	}
	return alg, keyBytes[2+n:], nil
}

// selectAlgorithm chooses the algorithm for pub and returns it with the
// encoded public key. A non-empty id names the algorithm. Otherwise the
// algorithm follows from the key: the one algorithm with an assigned type
// byte that accepts it, else the one algorithm that accepts it.
func selectAlgorithm(pub crypto.PublicKey, id string) (*Algorithm, []byte, error) {
	if id != "" {
		alg, err := lookupID(id)
		if err != nil {
			return nil, nil, err
		}
		material, err := alg.EncodePublicKey(pub)
		if err != nil {
			return nil, nil, &errs.Joined{Lead: ErrUnsupportedKey, Detail: id, Cause: err}
		}
		return alg, material, nil
	}

	var assigned, extended []*Algorithm
	materials := map[*Algorithm][]byte{}
	for _, alg := range algorithms.Load().byID {
		material, err := alg.EncodePublicKey(pub)
		if err != nil {
			continue
		}
		materials[alg] = material
		if alg.Type == TypeExtended {
			extended = append(extended, alg)
		} else {
			assigned = append(assigned, alg)
		}
	}
	candidates := assigned
	if len(candidates) == 0 {
		candidates = extended
	}
	if len(candidates) == 0 {
		return nil, nil, ErrUnsupportedKey
	}
	if len(candidates) == 1 {
		return candidates[0], materials[candidates[0]], nil
	}
	ids := make([]string, len(candidates))
	for i, alg := range candidates {
		ids[i] = alg.ID
	}
	slices.Sort(ids)
	return nil, nil, &errs.Detail{Err: ErrAmbiguousAlgorithm, Detail: strings.Join(ids, ", ")}
}

// hexByte renders b as 0xNN for error details.
func hexByte(b byte) string {
	const digits = "0123456789abcdef"
	return "0x" + string([]byte{digits[b>>4], digits[b&0x0f]})
}
