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

package kdf

import (
	"encoding/binary"
	"hash"
)

// concatCounterBytes is the width of the 32-bit big-endian counter both
// concatenation KDFs prepend or append to each hash invocation.
const concatCounterBytes = 4

// ConcatAdapter implements the two single-step concatenation KDFs used by
// ECDH key agreement. Unlike the SP 800-108 family these are plain hash
// constructions rather than HMAC PRFs.
//
//	ANSI X9.63:     K(i) = H(Z || [i]_32 || SharedInfo)
//	NIST SP 800-56A: K(i) = H([i]_32 || Z || OtherInfo)
//
// The shared info / other info is taken from KDFParams.Info.
type ConcatAdapter struct {
	mode KDFAlgorithm
}

// NewX963Adapter creates an ANSI X9.63 concatenation KDF adapter.
func NewX963Adapter() *ConcatAdapter {
	return &ConcatAdapter{mode: AlgorithmX963}
}

// NewSP80056AAdapter creates a NIST SP 800-56A concatenation KDF adapter.
func NewSP80056AAdapter() *ConcatAdapter {
	return &ConcatAdapter{mode: AlgorithmSP80056A}
}

// Algorithm returns the KDF algorithm this adapter implements.
func (a *ConcatAdapter) Algorithm() KDFAlgorithm {
	return a.mode
}

// ValidateParams validates the parameters for a concatenation KDF.
func (a *ConcatAdapter) ValidateParams(params *KDFParams) error {
	_, err := a.blocks(params)
	return err
}

// blocks validates params and returns the number of hash invocations needed.
func (a *ConcatAdapter) blocks(params *KDFParams) (int, error) {
	if params == nil {
		return 0, ErrInvalidIKM
	}
	if params.KeyLength <= 0 {
		return 0, ErrInvalidKeyLength
	}
	if !params.Hash.Available() {
		return 0, ErrInvalidHash
	}

	hashLen := params.Hash.Size()
	reps := (params.KeyLength + hashLen - 1) / hashLen

	// The counter is a 32-bit field; more blocks than it can enumerate would
	// repeat hash inputs.
	if uint64(reps) > uint64(^uint32(0)) {
		return 0, ErrOutputTooLong
	}

	return reps, nil
}

// DeriveKey derives keying material from the shared secret z.
func (a *ConcatAdapter) DeriveKey(z []byte, params *KDFParams) ([]byte, error) {
	if len(z) == 0 {
		return nil, ErrInvalidIKM
	}

	reps, err := a.blocks(params)
	if err != nil {
		return nil, err
	}

	h := params.Hash.New()
	result := make([]byte, 0, reps*h.Size())
	counter := make([]byte, concatCounterBytes)

	for i := 1; i <= reps; i++ {
		binary.BigEndian.PutUint32(counter, uint32(i))
		h.Reset()
		a.writeInput(h, z, counter, params.Info)
		result = h.Sum(result)
	}

	return result[:params.KeyLength], nil
}

// writeInput writes the per-iteration hash input in the order the selected
// standard mandates. The only difference between the two is where the counter
// sits relative to the shared secret.
func (a *ConcatAdapter) writeInput(h hash.Hash, z, counter, info []byte) {
	if a.mode == AlgorithmSP80056A {
		h.Write(counter)
		h.Write(z)
	} else {
		h.Write(z)
		h.Write(counter)
	}
	h.Write(info)
}

// Ensure ConcatAdapter implements KDFAdapter
var _ KDFAdapter = (*ConcatAdapter)(nil)
