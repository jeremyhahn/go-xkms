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

package securityevent

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"

	"github.com/fxamacker/cbor/v2"
)

// Hash algorithm identifiers from the IANA "COSE Algorithms" registry
// (RFC 9054 §2), the only registry RFC 9711 §4.2.18.2 allows.
const (
	AlgSHA256 = -16
	AlgSHA384 = -43
	AlgSHA512 = -44
)

// Detached Submodule Digest errors; test for them with errors.Is.
var (
	// ErrMalformedDigest reports a Detached-Submodule-Digest that is not a
	// CBOR array of an algorithm (int or text) and a byte string of that
	// algorithm's digest length.
	ErrMalformedDigest = errors.New("securityevent: malformed detached submodule digest")

	// ErrUnsupportedAlgorithm reports an algorithm that is not SHA-256,
	// SHA-384 or SHA-512.
	ErrUnsupportedAlgorithm = errors.New("securityevent: unsupported digest algorithm")

	// ErrDigestMismatch reports a record whose digest is not the one the
	// signed evidence carries.
	ErrDigestMismatch = errors.New("securityevent: record does not match its detached digest")
)

func newHash(alg int) (hash.Hash, error) {
	switch alg {
	case AlgSHA256:
		return sha256.New(), nil
	case AlgSHA384:
		return sha512.New384(), nil
	case AlgSHA512:
		return sha512.New(), nil
	}
	return nil, fmt.Errorf("%w: COSE algorithm %d", ErrUnsupportedAlgorithm, alg)
}

func algByName(name string) (int, error) {
	switch name {
	case "SHA-256":
		return AlgSHA256, nil
	case "SHA-384":
		return AlgSHA384, nil
	case "SHA-512":
		return AlgSHA512, nil
	}
	return 0, fmt.Errorf("%w: COSE algorithm %q", ErrUnsupportedAlgorithm, name)
}

func sum(alg int, data []byte) ([]byte, error) {
	h, err := newHash(alg)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return h.Sum(nil), nil
}

// DetachedDigest returns the RFC 9711 §4.2.18.2 Detached-Submodule-Digest,
// [alg, digest], of an encoded Claims-Set. The digest input is the
// Claims-Set bytes as they are, with no wrapping. The device puts this value
// in the submodule of the evidence it signs over the Verifier's eat_nonce
// (owner ruling 7dbbb72, item 181), and the record travels beside it.
func DetachedDigest(claimsSet []byte, alg int) ([]byte, error) {
	d, err := sum(alg, claimsSet)
	if err != nil {
		return nil, err
	}
	return encMode.Marshal([]any{alg, d})
}

// VerifyDetached checks a detached Claims-Set against the
// Detached-Submodule-Digest taken from verified, device-signed evidence,
// then decodes it. The caller has already checked that evidence's signature
// and its eat_nonce; VerifyDetached proves only that claimsSet is the record
// the evidence vouches for.
func VerifyDetached(claimsSet, dsd []byte) (Record, error) {
	var parts []cbor.RawMessage
	if err := decMode.Unmarshal(dsd, &parts); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrMalformedDigest, err)
	}
	if len(parts) != 2 {
		return Record{}, fmt.Errorf("%w: %d elements, want 2", ErrMalformedDigest, len(parts))
	}
	alg, err := decodeAlg(parts[0])
	if err != nil {
		return Record{}, err
	}
	var want []byte
	if err := decMode.Unmarshal(parts[1], &want); err != nil {
		return Record{}, fmt.Errorf("%w: digest: %v", ErrMalformedDigest, err)
	}
	got, err := sum(alg, claimsSet)
	if err != nil {
		return Record{}, err
	}
	if len(want) != len(got) {
		return Record{}, fmt.Errorf("%w: digest is %d bytes, want %d", ErrMalformedDigest, len(want), len(got))
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return Record{}, ErrDigestMismatch
	}
	return Decode(claimsSet)
}

func decodeAlg(raw cbor.RawMessage) (int, error) {
	var v any
	if err := decMode.Unmarshal(raw, &v); err != nil {
		return 0, fmt.Errorf("%w: algorithm: %v", ErrMalformedDigest, err)
	}
	switch a := v.(type) {
	case int64:
		if a < -1<<31 || a > 1<<31-1 {
			return 0, fmt.Errorf("%w: COSE algorithm %d", ErrUnsupportedAlgorithm, a)
		}
		_, err := newHash(int(a))
		return int(a), err
	case uint64:
		return 0, fmt.Errorf("%w: COSE algorithm %d", ErrUnsupportedAlgorithm, a)
	case string:
		return algByName(a)
	}
	return 0, fmt.Errorf("%w: algorithm is %T, want int or text", ErrMalformedDigest, v)
}
