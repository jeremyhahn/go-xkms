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
)

// SP800108Adapter implements NIST SP 800-108 Key Derivation Functions.
// It supports Counter Mode, Feedback Mode, and Double-Pipeline Iteration Mode.
//
// Reference: NIST Special Publication 800-108 Rev. 1
// "Recommendation for Key Derivation Using Pseudorandom Functions"
type SP800108Adapter struct {
	mode KDFAlgorithm
}

// NewSP800108CounterAdapter creates a new SP800-108 Counter Mode KDF adapter.
func NewSP800108CounterAdapter() *SP800108Adapter {
	return &SP800108Adapter{mode: AlgorithmSP800108Counter}
}

// NewSP800108FeedbackAdapter creates a new SP800-108 Feedback Mode KDF adapter.
func NewSP800108FeedbackAdapter() *SP800108Adapter {
	return &SP800108Adapter{mode: AlgorithmSP800108Feedback}
}

// NewSP800108DoublePipelineAdapter creates a new SP800-108 Double-Pipeline Mode KDF adapter.
func NewSP800108DoublePipelineAdapter() *SP800108Adapter {
	return &SP800108Adapter{mode: AlgorithmSP800108DoublePipeline}
}

// Algorithm returns the KDF algorithm this adapter implements.
func (a *SP800108Adapter) Algorithm() KDFAlgorithm {
	return a.mode
}

// ValidateParams validates the parameters for SP800-108 KDF.
func (a *SP800108Adapter) ValidateParams(params *KDFParams) error {
	if params == nil {
		return ErrInvalidIKM
	}

	if params.KeyLength <= 0 {
		return ErrInvalidKeyLength
	}

	if !params.Hash.Available() {
		return ErrInvalidHash
	}

	// Validate counter length (must be 8, 16, 24, or 32 bits)
	if params.CounterLength != 0 && params.CounterLength != 8 &&
		params.CounterLength != 16 && params.CounterLength != 24 &&
		params.CounterLength != 32 {
		return ErrInvalidCounterLength
	}

	// Calculate maximum output length based on counter size
	counterLen := params.CounterLength
	if counterLen == 0 {
		counterLen = 32 // default
	}
	maxIterations := uint64(1) << counterLen
	hashSize := params.Hash.Size()
	maxOutput := maxIterations * uint64(hashSize)

	if uint64(params.KeyLength) > maxOutput {
		return ErrOutputTooLong
	}

	return nil
}

// DeriveKey derives a key using SP800-108 KDF.
// The ikm (input key material) is the key derivation key (KDK).
func (a *SP800108Adapter) DeriveKey(ikm []byte, params *KDFParams) ([]byte, error) {
	if len(ikm) == 0 {
		return nil, ErrInvalidIKM
	}

	if err := a.ValidateParams(params); err != nil {
		return nil, err
	}

	switch a.mode {
	case AlgorithmSP800108Counter:
		return a.deriveCounterMode(ikm, params)
	case AlgorithmSP800108Feedback:
		return a.deriveFeedbackMode(ikm, params)
	case AlgorithmSP800108DoublePipeline:
		return a.deriveDoublePipelineMode(ikm, params)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// deriveCounterMode implements SP800-108 Counter Mode.
// K(i) = PRF(KDK, [i]_r || Label || 0x00 || Context || [L]_r)
// Where:
//   - [i]_r is the counter in r bits
//   - Label is the purpose/label string
//   - Context is the context/application-specific info
//   - [L]_r is the total output length in bits
func (a *SP800108Adapter) deriveCounterMode(kdk []byte, params *KDFParams) ([]byte, error) {
	hashFunc := params.Hash.New
	h := hashFunc()
	hashSize := h.Size()
	outputLen := params.KeyLength

	// Calculate number of iterations needed
	n := (outputLen + hashSize - 1) / hashSize

	// Get counter configuration
	counterLen := params.CounterLength
	if counterLen == 0 {
		counterLen = 32
	}
	counterBytes := counterLen / 8

	counterLocation := params.CounterLocation
	if counterLocation == "" {
		counterLocation = "before"
	}

	// Build fixed data: Label || 0x00 || Context || [L]
	// L is the output length in bits (4 bytes, big-endian)
	outputLenBits := make([]byte, 4)
	binary.BigEndian.PutUint32(outputLenBits, uint32(outputLen*8))

	fixedData := make([]byte, 0, len(params.Label)+1+len(params.Context)+4)
	fixedData = append(fixedData, params.Label...)
	fixedData = append(fixedData, 0x00) // separator
	fixedData = append(fixedData, params.Context...)
	fixedData = append(fixedData, outputLenBits...)

	// Derive key material
	result := make([]byte, 0, n*hashSize)
	counterBuf := make([]byte, 4) // max 32-bit counter

	for i := 1; i <= n; i++ {
		// Encode counter
		binary.BigEndian.PutUint32(counterBuf, uint32(i))
		counter := counterBuf[4-counterBytes:] // use only the required bytes

		// Compute PRF(KDK, counter || fixedData) or PRF(KDK, fixedData || counter)
		mac := hmac.New(hashFunc, kdk)
		if counterLocation == "before" {
			mac.Write(counter)
			mac.Write(fixedData)
		} else {
			mac.Write(fixedData)
			mac.Write(counter)
		}
		result = append(result, mac.Sum(nil)...)
	}

	return result[:outputLen], nil
}

// deriveFeedbackMode implements SP800-108 Feedback Mode.
// K(0) = IV (or empty if no IV)
// K(i) = PRF(KDK, K(i-1) || [i]_r || Label || 0x00 || Context || [L]_r)
func (a *SP800108Adapter) deriveFeedbackMode(kdk []byte, params *KDFParams) ([]byte, error) {
	hashFunc := params.Hash.New
	h := hashFunc()
	hashSize := h.Size()
	outputLen := params.KeyLength

	n := (outputLen + hashSize - 1) / hashSize

	counterLen := params.CounterLength
	if counterLen == 0 {
		counterLen = 32
	}
	counterBytes := counterLen / 8

	// Build fixed data
	outputLenBits := make([]byte, 4)
	binary.BigEndian.PutUint32(outputLenBits, uint32(outputLen*8))

	fixedData := make([]byte, 0, len(params.Label)+1+len(params.Context)+4)
	fixedData = append(fixedData, params.Label...)
	fixedData = append(fixedData, 0x00)
	fixedData = append(fixedData, params.Context...)
	fixedData = append(fixedData, outputLenBits...)

	// Initialize feedback value (K(0))
	var feedback []byte
	if len(params.IV) > 0 {
		feedback = params.IV
	}

	result := make([]byte, 0, n*hashSize)
	counterBuf := make([]byte, 4)

	for i := 1; i <= n; i++ {
		binary.BigEndian.PutUint32(counterBuf, uint32(i))
		counter := counterBuf[4-counterBytes:]

		mac := hmac.New(hashFunc, kdk)
		mac.Write(feedback) // K(i-1)
		mac.Write(counter)
		mac.Write(fixedData)

		feedback = mac.Sum(nil)
		result = append(result, feedback...)
	}

	return result[:outputLen], nil
}

// deriveDoublePipelineMode implements SP800-108 Double-Pipeline Iteration Mode.
// A(0) = Label || 0x00 || Context || [L]_r
// A(i) = PRF(KDK, A(i-1))
// K(i) = PRF(KDK, A(i) || [i]_r || Label || 0x00 || Context || [L]_r)
func (a *SP800108Adapter) deriveDoublePipelineMode(kdk []byte, params *KDFParams) ([]byte, error) {
	hashFunc := params.Hash.New
	h := hashFunc()
	hashSize := h.Size()
	outputLen := params.KeyLength

	n := (outputLen + hashSize - 1) / hashSize

	counterLen := params.CounterLength
	if counterLen == 0 {
		counterLen = 32
	}
	counterBytes := counterLen / 8

	// Build fixed data (A(0))
	outputLenBits := make([]byte, 4)
	binary.BigEndian.PutUint32(outputLenBits, uint32(outputLen*8))

	fixedData := make([]byte, 0, len(params.Label)+1+len(params.Context)+4)
	fixedData = append(fixedData, params.Label...)
	fixedData = append(fixedData, 0x00)
	fixedData = append(fixedData, params.Context...)
	fixedData = append(fixedData, outputLenBits...)

	// pipeline = A(0) = fixedData
	pipeline := fixedData

	result := make([]byte, 0, n*hashSize)
	counterBuf := make([]byte, 4)

	for i := 1; i <= n; i++ {
		// A(i) = PRF(KDK, A(i-1))
		aMac := hmac.New(hashFunc, kdk)
		aMac.Write(pipeline)
		pipeline = aMac.Sum(nil)

		// K(i) = PRF(KDK, A(i) || [i]_r || fixedData)
		binary.BigEndian.PutUint32(counterBuf, uint32(i))
		counter := counterBuf[4-counterBytes:]

		kMac := hmac.New(hashFunc, kdk)
		kMac.Write(pipeline)
		kMac.Write(counter)
		kMac.Write(fixedData)
		result = append(result, kMac.Sum(nil)...)
	}

	return result[:outputLen], nil
}

// Ensure SP800108Adapter implements KDFAdapter
var _ KDFAdapter = (*SP800108Adapter)(nil)
