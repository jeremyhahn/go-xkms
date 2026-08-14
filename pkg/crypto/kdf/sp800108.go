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
	"crypto/hmac"
	"encoding/binary"
	"hash"
	"math"
)

// Counter locations recognized by the SP 800-108 fixed-input format. The
// location controls where the iteration counter [i]_r is placed relative to
// the remaining fixed input data, exactly as enumerated by the NIST CAVP
// KDF108 test format.
//
//	CounterLocationBefore: [i]_r || Label || 0x00 || Context || [L]_2
//	CounterLocationMiddle: Label || 0x00 || [i]_r || Context || [L]_2
//	CounterLocationAfter:  Label || 0x00 || Context || [L]_2 || [i]_r
const (
	CounterLocationBefore = "before"
	CounterLocationMiddle = "middle"
	CounterLocationAfter  = "after"
)

const (
	// DefaultCounterLength is the counter width in bits used when
	// KDFParams.CounterLength is left at its zero value.
	DefaultCounterLength = 32

	// lengthEncodingBytes is the width of the [L]_2 encoding. SP 800-108r1
	// requires L to be encoded as a fixed-width big-endian binary string; this
	// implementation uses the 32-bit encoding mandated by the NIST CAVP
	// KDF108 fixed-input format.
	lengthEncodingBytes = 4

	// counterSeparator is the 0x00 byte that separates the Label from the
	// Context in the SP 800-108 fixed input data.
	counterSeparator = 0x00

	// counterBufferBytes is the scratch width used to encode [i]_r before it
	// is truncated to the configured counter width. It holds the widest
	// counter SP 800-108 permits.
	counterBufferBytes = 4
)

// maxOutputBytes is the largest requested output whose bit length still fits
// the 32-bit [L]_2 encoding.
const maxOutputBytes = math.MaxUint32 / 8

// validCounterLengths lists the counter widths (in bits) permitted by
// SP 800-108r1. Map-based membership keeps validation O(1).
var validCounterLengths = map[int]struct{}{
	8:  {},
	16: {},
	24: {},
	32: {},
}

// validCounterLocations lists the counter placements this implementation
// supports within the fixed input data.
var validCounterLocations = map[string]struct{}{
	CounterLocationBefore: {},
	CounterLocationMiddle: {},
	CounterLocationAfter:  {},
}

// SP800108Adapter implements the NIST SP 800-108r1 key derivation functions in
// Counter Mode, Feedback Mode, and Double-Pipeline Iteration Mode. The PRF is
// HMAC keyed with the key derivation key (KDK) using the caller's configured
// hash.
//
// Reference: NIST Special Publication 800-108 Revision 1,
// "Recommendation for Key Derivation Using Pseudorandom Functions".
type SP800108Adapter struct {
	mode KDFAlgorithm
}

// NewSP800108CounterAdapter creates a new SP 800-108 Counter Mode KDF adapter.
func NewSP800108CounterAdapter() *SP800108Adapter {
	return &SP800108Adapter{mode: AlgorithmSP800108Counter}
}

// NewSP800108FeedbackAdapter creates a new SP 800-108 Feedback Mode KDF adapter.
func NewSP800108FeedbackAdapter() *SP800108Adapter {
	return &SP800108Adapter{mode: AlgorithmSP800108Feedback}
}

// NewSP800108DoublePipelineAdapter creates a new SP 800-108 Double-Pipeline
// Iteration Mode KDF adapter.
func NewSP800108DoublePipelineAdapter() *SP800108Adapter {
	return &SP800108Adapter{mode: AlgorithmSP800108DoublePipeline}
}

// Algorithm returns the KDF algorithm this adapter implements.
func (a *SP800108Adapter) Algorithm() KDFAlgorithm {
	return a.mode
}

// ValidateParams validates the parameters for the SP 800-108 KDF. Parameter
// combinations SP 800-108 does not permit are rejected rather than coerced,
// because silently adjusting a KDF input yields a different key than the
// caller asked for.
func (a *SP800108Adapter) ValidateParams(params *KDFParams) error {
	_, err := a.plan(params)
	return err
}

// DeriveKey derives keying material using the SP 800-108 KDF. The ikm is the
// key derivation key (KDK) that keys the HMAC PRF.
func (a *SP800108Adapter) DeriveKey(ikm []byte, params *KDFParams) ([]byte, error) {
	if len(ikm) == 0 {
		return nil, ErrInvalidIKM
	}

	p, err := a.plan(params)
	if err != nil {
		return nil, err
	}

	switch a.mode {
	case AlgorithmSP800108Counter:
		return a.deriveCounterMode(ikm, p), nil
	case AlgorithmSP800108Feedback:
		return a.deriveFeedbackMode(ikm, p), nil
	case AlgorithmSP800108DoublePipeline:
		return a.deriveDoublePipelineMode(ikm, p), nil
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// derivationPlan holds the validated, fully resolved inputs for one
// derivation. Building it once keeps validation and derivation from drifting
// apart and removes per-iteration branching from the PRF loop.
type derivationPlan struct {
	newHash func() hash.Hash

	// prefix is Label || 0x00 and suffix is Context || [L]_2. The counter is
	// spliced between, before, or after them according to location.
	prefix []byte
	suffix []byte

	location     string
	counterBytes int
	blocks       int
	outputLen    int
	prfLen       int
	iv           []byte
}

// plan validates params against SP 800-108r1 and resolves every derived
// quantity the PRF loop needs.
func (a *SP800108Adapter) plan(params *KDFParams) (*derivationPlan, error) {
	if params == nil {
		return nil, ErrInvalidIKM
	}

	if params.KeyLength <= 0 {
		return nil, ErrInvalidKeyLength
	}
	if params.KeyLength > maxOutputBytes {
		return nil, ErrOutputTooLong
	}

	if !params.Hash.Available() {
		return nil, ErrInvalidHash
	}

	counterBits := params.CounterLength
	if counterBits == 0 {
		counterBits = DefaultCounterLength
	}
	if _, ok := validCounterLengths[counterBits]; !ok {
		return nil, ErrInvalidCounterLength
	}

	location := params.CounterLocation
	if location == "" {
		location = CounterLocationBefore
	}
	if _, ok := validCounterLocations[location]; !ok {
		return nil, ErrInvalidCounterLocation
	}

	// The IV chains K(i-1) into the PRF and exists only in Feedback Mode.
	// Accepting it elsewhere would silently discard a caller-supplied input.
	if len(params.IV) > 0 && a.mode != AlgorithmSP800108Feedback {
		return nil, ErrIVNotPermitted
	}

	prfLen := params.Hash.Size()
	blocks := (params.KeyLength + prfLen - 1) / prfLen

	// SP 800-108r1 requires n <= 2^r - 1 so that every iteration has a
	// distinct counter encoding. Exceeding it would wrap the counter and
	// repeat PRF inputs.
	maxBlocks := (uint64(1) << uint(counterBits)) - 1
	if uint64(blocks) > maxBlocks {
		return nil, ErrOutputTooLong
	}

	prefix, suffix, err := fixedInputSegments(params, location)
	if err != nil {
		return nil, err
	}

	return &derivationPlan{
		newHash:      params.Hash.New,
		prefix:       prefix,
		suffix:       suffix,
		location:     location,
		counterBytes: counterBits / 8,
		blocks:       blocks,
		outputLen:    params.KeyLength,
		prfLen:       prfLen,
		iv:           params.IV,
	}, nil
}

// fixedInputSegments returns the fixed input data as the two segments the
// counter is spliced between: prefix is Label || 0x00 and suffix is
// Context || [L]_2. A caller-supplied FixedInput is used verbatim as the
// prefix, with an empty suffix, because an opaque blob has no interior split
// point.
func fixedInputSegments(params *KDFParams, location string) (prefix, suffix []byte, err error) {
	if len(params.FixedInput) > 0 {
		if len(params.Label) > 0 || len(params.Context) > 0 {
			return nil, nil, ErrFixedInputConflict
		}
		// An opaque blob has no defined interior split point.
		if location == CounterLocationMiddle {
			return nil, nil, ErrInvalidCounterLocation
		}
		return params.FixedInput, nil, nil
	}

	lengthEncoding := make([]byte, lengthEncodingBytes)
	binary.BigEndian.PutUint32(lengthEncoding, uint32(params.KeyLength)*8)

	prefix = make([]byte, 0, len(params.Label)+1)
	prefix = append(prefix, params.Label...)
	prefix = append(prefix, counterSeparator)

	suffix = make([]byte, 0, len(params.Context)+lengthEncodingBytes)
	suffix = append(suffix, params.Context...)
	suffix = append(suffix, lengthEncoding...)

	return prefix, suffix, nil
}

// writeFixedInput writes Label || 0x00 || Context || [L]_2 with the counter
// spliced in at the configured location.
func (p *derivationPlan) writeFixedInput(mac hash.Hash, counter []byte) {
	switch p.location {
	case CounterLocationBefore:
		mac.Write(counter)
		mac.Write(p.prefix)
		mac.Write(p.suffix)
	case CounterLocationMiddle:
		mac.Write(p.prefix)
		mac.Write(counter)
		mac.Write(p.suffix)
	default: // CounterLocationAfter, validated in plan.
		mac.Write(p.prefix)
		mac.Write(p.suffix)
		mac.Write(counter)
	}
}

// counterEncoding returns the big-endian [i]_r encoding for iteration i,
// truncated to the plan's counter width. buf is caller-owned scratch of
// counterBufferBytes; plan has already guaranteed i fits the width.
func (p *derivationPlan) counterEncoding(buf []byte, i int) []byte {
	binary.BigEndian.PutUint32(buf, uint32(i))
	return buf[counterBufferBytes-p.counterBytes:]
}

// deriveCounterMode implements SP 800-108r1 Section 4.1, KDF in Counter Mode:
//
//	K(i) = PRF(KDK, [i]_r || Label || 0x00 || Context || [L]_2)
//	KM   = K(1) || K(2) || ... || K(n), truncated to L bits
func (a *SP800108Adapter) deriveCounterMode(kdk []byte, p *derivationPlan) []byte {
	result := make([]byte, 0, p.blocks*p.prfLen)
	counterBuf := make([]byte, counterBufferBytes)
	mac := hmac.New(p.newHash, kdk)

	for i := 1; i <= p.blocks; i++ {
		mac.Reset()
		p.writeFixedInput(mac, p.counterEncoding(counterBuf, i))
		result = mac.Sum(result)
	}

	return result[:p.outputLen]
}

// deriveFeedbackMode implements SP 800-108r1 Section 4.2, KDF in Feedback
// Mode:
//
//	K(0) = IV
//	K(i) = PRF(KDK, K(i-1) || [i]_r || Label || 0x00 || Context || [L]_2)
//
// The chaining value K(i-1) always precedes the fixed input data; the counter
// placement applies within the fixed input data.
func (a *SP800108Adapter) deriveFeedbackMode(kdk []byte, p *derivationPlan) []byte {
	result := make([]byte, 0, p.blocks*p.prfLen)
	counterBuf := make([]byte, counterBufferBytes)
	mac := hmac.New(p.newHash, kdk)

	feedback := p.iv
	for i := 1; i <= p.blocks; i++ {
		mac.Reset()
		mac.Write(feedback)
		p.writeFixedInput(mac, p.counterEncoding(counterBuf, i))

		start := len(result)
		result = mac.Sum(result)
		feedback = result[start:]
	}

	return result[:p.outputLen]
}

// deriveDoublePipelineMode implements SP 800-108r1 Section 4.3, KDF in
// Double-Pipeline Iteration Mode:
//
//	A(0) = Label || 0x00 || Context || [L]_2
//	A(i) = PRF(KDK, A(i-1))
//	K(i) = PRF(KDK, A(i) || [i]_r || Label || 0x00 || Context || [L]_2)
func (a *SP800108Adapter) deriveDoublePipelineMode(kdk []byte, p *derivationPlan) []byte {
	result := make([]byte, 0, p.blocks*p.prfLen)
	counterBuf := make([]byte, counterBufferBytes)
	mac := hmac.New(p.newHash, kdk)

	// A(0) is the fixed input data with no counter.
	pipeline := make([]byte, 0, len(p.prefix)+len(p.suffix))
	pipeline = append(pipeline, p.prefix...)
	pipeline = append(pipeline, p.suffix...)

	for i := 1; i <= p.blocks; i++ {
		mac.Reset()
		mac.Write(pipeline)
		pipeline = mac.Sum(pipeline[:0])

		mac.Reset()
		mac.Write(pipeline)
		p.writeFixedInput(mac, p.counterEncoding(counterBuf, i))
		result = mac.Sum(result)
	}

	return result[:p.outputLen]
}

// Ensure SP800108Adapter implements KDFAdapter
var _ KDFAdapter = (*SP800108Adapter)(nil)
