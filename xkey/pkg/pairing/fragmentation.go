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

package pairing

import (
	"encoding/binary"
	"sync"
)

// Fragment header constants.
const (
	// FragmentHeaderSize is the size of the fragment header in bytes.
	// Header format: [1 byte flags] [2 bytes sequence] [2 bytes total] [2 bytes length]
	FragmentHeaderSize = 7

	// FlagFirstFragment indicates this is the first fragment of a message.
	FlagFirstFragment = 0x01

	// FlagLastFragment indicates this is the last fragment of a message.
	FlagLastFragment = 0x02

	// FlagSingleFragment indicates the message fits in a single fragment (first + last).
	FlagSingleFragment = FlagFirstFragment | FlagLastFragment
)

// Fragment represents a single BLE packet with fragmentation header.
type Fragment struct {
	Flags    byte   // Fragment flags (first, last)
	Sequence uint16 // Sequence number within the message
	Total    uint16 // Total number of fragments
	Length   uint16 // Length of payload in this fragment
	Payload  []byte // Fragment payload data
}

// Fragmenter handles message fragmentation and reassembly.
type Fragmenter struct {
	mu  sync.Mutex
	mtu int // Maximum Transmission Unit (payload size per BLE packet)
}

// NewFragmenter creates a new Fragmenter with the specified MTU.
func NewFragmenter(mtu int) *Fragmenter {
	if mtu < MinMTU {
		mtu = MinMTU
	}
	return &Fragmenter{
		mtu: mtu,
	}
}

// SetMTU updates the MTU value.
func (f *Fragmenter) SetMTU(mtu int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if mtu >= MinMTU {
		f.mtu = mtu
	}
}

// MTU returns the current MTU value.
func (f *Fragmenter) MTU() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mtu
}

// maxPayloadSize returns the maximum payload size per fragment.
func (f *Fragmenter) maxPayloadSize() int {
	return f.mtu - FragmentHeaderSize
}

// Fragment splits a message into BLE-sized fragments.
func (f *Fragmenter) Fragment(message []byte) ([][]byte, error) {
	f.mu.Lock()
	maxPayload := f.maxPayloadSize()
	f.mu.Unlock()

	if maxPayload <= 0 {
		return nil, ErrMTUTooSmall
	}

	if len(message) == 0 {
		// Empty message still needs a fragment
		return [][]byte{f.encodeFragment(&Fragment{
			Flags:    FlagSingleFragment,
			Sequence: 0,
			Total:    1,
			Length:   0,
			Payload:  nil,
		})}, nil
	}

	// Calculate number of fragments needed
	numFragments := (len(message) + maxPayload - 1) / maxPayload
	if numFragments > 65535 {
		return nil, ErrFragmentationError
	}

	fragments := make([][]byte, numFragments)
	offset := 0

	for i := range numFragments {
		end := offset + maxPayload
		if end > len(message) {
			end = len(message)
		}

		frag := &Fragment{
			Sequence: uint16(i),
			Total:    uint16(numFragments),
			Length:   uint16(end - offset),
			Payload:  message[offset:end],
		}

		// Set flags
		if i == 0 {
			frag.Flags |= FlagFirstFragment
		}
		if i == numFragments-1 {
			frag.Flags |= FlagLastFragment
		}

		fragments[i] = f.encodeFragment(frag)
		offset = end
	}

	return fragments, nil
}

// encodeFragment encodes a Fragment to wire format.
func (f *Fragmenter) encodeFragment(frag *Fragment) []byte {
	buf := make([]byte, FragmentHeaderSize+len(frag.Payload))

	buf[0] = frag.Flags
	binary.BigEndian.PutUint16(buf[1:3], frag.Sequence)
	binary.BigEndian.PutUint16(buf[3:5], frag.Total)
	binary.BigEndian.PutUint16(buf[5:7], frag.Length)

	copy(buf[FragmentHeaderSize:], frag.Payload)

	return buf
}

// DecodeFragment decodes a wire-format fragment.
func DecodeFragment(data []byte) (*Fragment, error) {
	if len(data) < FragmentHeaderSize {
		return nil, ErrInvalidFragment
	}

	frag := &Fragment{
		Flags:    data[0],
		Sequence: binary.BigEndian.Uint16(data[1:3]),
		Total:    binary.BigEndian.Uint16(data[3:5]),
		Length:   binary.BigEndian.Uint16(data[5:7]),
	}

	payloadLen := int(frag.Length)
	if len(data) < FragmentHeaderSize+payloadLen {
		return nil, ErrInvalidFragment
	}

	if payloadLen > 0 {
		frag.Payload = make([]byte, payloadLen)
		copy(frag.Payload, data[FragmentHeaderSize:FragmentHeaderSize+payloadLen])
	}

	return frag, nil
}

// Reassembler collects fragments and reassembles complete messages.
type Reassembler struct {
	mu            sync.Mutex
	fragments     map[uint16][]byte
	totalExpected uint16
	received      uint16
	complete      bool
}

// NewReassembler creates a new Reassembler.
func NewReassembler() *Reassembler {
	return &Reassembler{
		fragments: make(map[uint16][]byte),
	}
}

// Reset clears the reassembler state for a new message.
func (r *Reassembler) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.fragments = make(map[uint16][]byte)
	r.totalExpected = 0
	r.received = 0
	r.complete = false
}

// AddFragment adds a fragment to the reassembler.
// Returns true if the message is complete after adding this fragment.
func (r *Reassembler) AddFragment(frag *Fragment) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.complete {
		return true, nil
	}

	// First fragment sets total
	if frag.Flags&FlagFirstFragment != 0 {
		if r.totalExpected != 0 && r.totalExpected != frag.Total {
			return false, ErrSequenceNumber
		}
		r.totalExpected = frag.Total
	}

	// Validate sequence number
	if frag.Sequence >= frag.Total {
		return false, ErrSequenceNumber
	}

	// Check for duplicate
	if _, exists := r.fragments[frag.Sequence]; exists {
		// Already have this fragment, skip
		return r.received == r.totalExpected, nil
	}

	// Store fragment
	r.fragments[frag.Sequence] = frag.Payload
	r.received++

	// Check if complete
	if frag.Flags&FlagLastFragment != 0 {
		r.totalExpected = frag.Total
	}

	if r.totalExpected > 0 && r.received == r.totalExpected {
		r.complete = true
		return true, nil
	}

	return false, nil
}

// Assemble returns the complete message once all fragments are received.
func (r *Reassembler) Assemble() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.complete {
		return nil, ErrFragmentationError
	}

	// Calculate total size
	totalSize := 0
	for _, payload := range r.fragments {
		totalSize += len(payload)
	}

	// Assemble in order
	result := make([]byte, 0, totalSize)
	for i := range r.totalExpected {
		payload, ok := r.fragments[i]
		if !ok {
			return nil, ErrSequenceNumber
		}
		result = append(result, payload...)
	}

	return result, nil
}

// IsComplete returns true if all fragments have been received.
func (r *Reassembler) IsComplete() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.complete
}

// Progress returns the number of fragments received and total expected.
func (r *Reassembler) Progress() (received, total uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.received, r.totalExpected
}
