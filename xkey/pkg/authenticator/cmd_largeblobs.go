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

package authenticator

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"

	"github.com/fxamacker/cbor/v2"
)

// authenticatorLargeBlobs (CTAP 2.1 §6.10) request map keys.
const (
	largeBlobsKeyGet               = 1
	largeBlobsKeySet               = 2
	largeBlobsKeyOffset            = 3
	largeBlobsKeyLength            = 4
	largeBlobsKeyPinUvAuthParam    = 5
	largeBlobsKeyPinUvAuthProtocol = 6
)

// largeBlobsResponseKeyFragment is the only key in an authenticatorLargeBlobs
// response, present for a Get and carrying the requested fragment of the
// serialized large-blob array.
const largeBlobsResponseKeyFragment = 1

const (
	// largeBlobFixedOverhead is the CTAP 2.1 §6.10.2 fixed per-message
	// overhead subtracted from the authenticator's maxMsgSize to compute the
	// largest get/set fragment length it will accept or return in a single
	// message.
	largeBlobFixedOverhead = 64

	// largeBlobChecksumLength is the length, in bytes, of the truncated
	// SHA-256 checksum CTAP 2.1 §6.10.2 appends to the CBOR-encoded large
	// blob array to form the "serialized large blob array".
	largeBlobChecksumLength = 16

	// minSerializedLargeBlobArray is the smallest valid serialized large
	// blob array: the 1-byte CBOR encoding of an empty array (0x80),
	// followed by its 16-byte truncated checksum.
	minSerializedLargeBlobArray = 1 + largeBlobChecksumLength
)

// Large blob errors.
var (
	// ErrLargeBlobsGetSetConflict indicates a request named neither, or both,
	// of the mutually exclusive get and set parameters.
	ErrLargeBlobsGetSetConflict = errors.New("authenticator: exactly one of get or set must be present")

	// ErrLargeBlobsMissingOffset indicates the always-required offset
	// parameter was not present.
	ErrLargeBlobsMissingOffset = errors.New("authenticator: offset is required")

	// ErrLargeBlobsMissingLength indicates a Set at offset 0 did not carry
	// the required total-length parameter.
	ErrLargeBlobsMissingLength = errors.New("authenticator: length is required for the first fragment of a set")

	// ErrLargeBlobsInvalidLength indicates a get fragment length exceeds the
	// authenticator's fragment limit, or a set fragment exceeds the fragment
	// limit, or a declared total length is below the minimum valid serialized
	// large blob array size.
	ErrLargeBlobsInvalidLength = errors.New("authenticator: invalid length")

	// ErrLargeBlobsSetExceedsLength indicates a set fragment's offset and size
	// together extend past the total length declared by the offset-0 fragment
	// of the write in progress. CTAP 2.1 §6.10.2 maps this to
	// CTAP1_ERR_INVALID_PARAMETER, distinct from ErrLargeBlobsInvalidLength.
	ErrLargeBlobsSetExceedsLength = errors.New("authenticator: set fragment exceeds the declared total length")

	// ErrLargeBlobsMissingPinUvAuthProtocol indicates a set fragment carried a
	// pinUvAuthParam but no pinUvAuthProtocol. CTAP 2.1 §6.10.2 maps an absent
	// pinUvAuthProtocol to CTAP2_ERR_MISSING_PARAMETER, distinct from an
	// unsupported protocol value (ErrUnsupportedPINProtocol).
	ErrLargeBlobsMissingPinUvAuthProtocol = errors.New("authenticator: pinUvAuthProtocol is required when pinUvAuthParam is present")

	// ErrLargeBlobsInvalidOffset indicates a get offset lies beyond the end
	// of the currently stored serialized large blob array.
	ErrLargeBlobsInvalidOffset = errors.New("authenticator: offset out of range")

	// ErrLargeBlobsInvalidSeq indicates a set fragment's offset does not
	// equal the number of bytes already received for the write in progress
	// (including a fragment received with no write in progress at all).
	ErrLargeBlobsInvalidSeq = errors.New("authenticator: unexpected offset for the write in progress")

	// ErrLargeBlobsStorageFull indicates a set's declared total length
	// exceeds the authenticator's configured storage limit.
	ErrLargeBlobsStorageFull = errors.New("authenticator: large blob array exceeds the authenticator's storage limit")

	// ErrLargeBlobsChecksumInvalid indicates the completed serialized large
	// blob array's trailing checksum does not match its payload.
	ErrLargeBlobsChecksumInvalid = errors.New("authenticator: large blob array checksum is invalid")
)

// largeBlobPendingWrite assembles an authenticatorLargeBlobs Set operation
// across the (possibly several) CTAP2 messages a platform fragments it into.
// It is never persisted: see Authenticator.largeBlobPending.
type largeBlobPendingWrite struct {
	// expected is the total length declared by the offset-0 fragment.
	expected uint32

	// buf accumulates fragments in order; len(buf) is always the offset the
	// next fragment must arrive at.
	buf []byte
}

// largeBlobsRequest is the decoded form of an authenticatorLargeBlobs
// request (CTAP 2.1 §6.10.1).
type largeBlobsRequest struct {
	hasGet bool
	get    uint32

	hasSet bool
	set    []byte

	offset uint32

	hasLength bool
	length    uint32

	pinUvAuthParam []byte

	hasProtocol       bool
	pinUvAuthProtocol uint8
}

// handleLargeBlobs implements the CTAP2 authenticatorLargeBlobs command
// (0x0C), reading and writing the authenticator-wide serialized large blob
// array in fixed-size fragments (CTAP 2.1 §6.10).
func (a *Authenticator) handleLargeBlobs(data []byte) ([]byte, error) {
	if !a.config.EnableLargeBlobs {
		return nil, ErrNotImplemented
	}

	req, err := decodeLargeBlobsRequest(data)
	if err != nil {
		return nil, err
	}

	switch {
	case req.hasGet == req.hasSet:
		// Neither present, or both present: CTAP 2.1 §6.10.2 requires exactly one.
		return nil, ErrLargeBlobsGetSetConflict
	case req.hasGet:
		return a.handleLargeBlobsGet(req)
	default:
		return a.handleLargeBlobsSet(req)
	}
}

// decodeLargeBlobsRequest decodes a CBOR-encoded authenticatorLargeBlobs
// request.
func decodeLargeBlobsRequest(data []byte) (*largeBlobsRequest, error) {
	if len(data) == 0 {
		return nil, ErrLargeBlobsMissingOffset
	}

	var raw map[int]interface{}
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return nil, ErrCBORDecodingFailed
	}

	req := &largeBlobsRequest{}

	if v, ok := raw[largeBlobsKeyGet]; ok {
		n, err := toUint32(v)
		if err != nil {
			return nil, ErrInvalidParameter
		}
		req.hasGet = true
		req.get = n
	}

	if v, ok := raw[largeBlobsKeySet]; ok {
		b, ok := v.([]byte)
		if !ok {
			return nil, ErrInvalidParameter
		}
		req.hasSet = true
		req.set = b
	}

	offsetRaw, ok := raw[largeBlobsKeyOffset]
	if !ok {
		return nil, ErrLargeBlobsMissingOffset
	}
	offset, err := toUint32(offsetRaw)
	if err != nil {
		return nil, ErrInvalidParameter
	}
	req.offset = offset

	if v, ok := raw[largeBlobsKeyLength]; ok {
		n, err := toUint32(v)
		if err != nil {
			return nil, ErrInvalidParameter
		}
		req.hasLength = true
		req.length = n
	}

	if v, ok := raw[largeBlobsKeyPinUvAuthParam]; ok {
		b, ok := v.([]byte)
		if !ok {
			return nil, ErrInvalidParameter
		}
		req.pinUvAuthParam = b
	}

	if v, ok := raw[largeBlobsKeyPinUvAuthProtocol]; ok {
		p, err := toUint8(v)
		if err != nil {
			return nil, ErrInvalidParameter
		}
		req.hasProtocol = true
		req.pinUvAuthProtocol = p
	}

	return req, nil
}

// maxLargeBlobFragmentLength returns the largest get/set fragment this
// authenticator will return or accept in a single message.
func (a *Authenticator) maxLargeBlobFragmentLength() uint32 {
	return uint32(defaultMaxMsgSize) - largeBlobFixedOverhead
}

// handleLargeBlobsGet implements the Get half of authenticatorLargeBlobs: it
// returns up to req.get bytes of the current serialized large blob array
// starting at req.offset. Reading requires no authentication — the array is
// not secret, only its individual largeBlobKey-encrypted entries are.
func (a *Authenticator) handleLargeBlobsGet(req *largeBlobsRequest) ([]byte, error) {
	// CTAP 2.1 §6.10.2: length, pinUvAuthParam and pinUvAuthProtocol are Set-only
	// parameters and must not accompany a Get.
	if req.hasLength {
		return nil, ErrInvalidParameter
	}
	if len(req.pinUvAuthParam) > 0 || req.hasProtocol {
		return nil, ErrInvalidParameter
	}

	// A zero-length get is a valid request for an empty substring; only a
	// request exceeding the authenticator's fragment limit is refused.
	if req.get > a.maxLargeBlobFragmentLength() {
		return nil, ErrLargeBlobsInvalidLength
	}

	a.mu.RLock()
	array := a.state.LargeBlobArray
	a.mu.RUnlock()

	if array == nil {
		array = initialLargeBlobArray()
	}

	if req.offset > uint32(len(array)) {
		return nil, ErrLargeBlobsInvalidOffset
	}

	end := req.offset + req.get
	if end > uint32(len(array)) {
		end = uint32(len(array))
	}

	response := map[int]interface{}{
		largeBlobsResponseKeyFragment: array[req.offset:end],
	}

	encoded, err := encodeCBOR(response)
	if err != nil {
		return nil, err
	}

	return a.successResponse(encoded), nil
}

// handleLargeBlobsSet implements the Set half of authenticatorLargeBlobs: it
// accumulates fragments of a new serialized large blob array, authenticating
// each one, and commits the array once every declared byte has arrived.
func (a *Authenticator) handleLargeBlobsSet(req *largeBlobsRequest) ([]byte, error) {
	if uint32(len(req.set)) > a.maxLargeBlobFragmentLength() {
		return nil, ErrLargeBlobsInvalidLength
	}

	// CTAP 2.1 §6.10.2 evaluates the offset and sequence conditions before
	// authenticating the fragment, so a request that violates both an
	// ordering check and authentication must report the ordering failure.
	// Validate first while holding a.mu for reading, then release it before
	// authenticating: AuthorizePinUvAuthToken takes its own lock, and this
	// authenticator never nests locks across its own public entry points. The
	// checks are re-run under the write lock immediately before mutating
	// state, so a write that raced in between cannot invalidate them.
	a.mu.RLock()
	err := a.validateLargeBlobsSetLocked(req)
	a.mu.RUnlock()
	if err != nil {
		return nil, err
	}

	if err := a.verifyLargeBlobsWriteAuth(req); err != nil {
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if err := a.validateLargeBlobsSetLocked(req); err != nil {
		return nil, err
	}

	if req.offset == 0 {
		// A fresh offset-0 fragment starts (or restarts) the write in
		// progress, discarding whatever came before it.
		a.largeBlobPending = &largeBlobPendingWrite{
			expected: req.length,
			buf:      make([]byte, 0, req.length),
		}
	}

	a.largeBlobPending.buf = append(a.largeBlobPending.buf, req.set...)

	if uint32(len(a.largeBlobPending.buf)) < a.largeBlobPending.expected {
		// More fragments still expected.
		return a.successResponse(nil), nil
	}

	completed := a.largeBlobPending.buf
	a.largeBlobPending = nil

	if err := validateSerializedLargeBlobArray(completed); err != nil {
		return nil, err
	}

	a.state.LargeBlobArray = completed
	if err := a.storage.SaveState(a.state); err != nil {
		if a.logger != nil {
			a.logger.Error("failed to persist large blob array", slog.String("error", err.Error()))
		}
		return nil, err
	}

	return a.successResponse(nil), nil
}

// validateLargeBlobsSetLocked checks the offset and sequence conditions CTAP
// 2.1 §6.10.2 requires a Set fragment to satisfy, without mutating any state.
// The caller must hold a.mu for at least reading.
func (a *Authenticator) validateLargeBlobsSetLocked(req *largeBlobsRequest) error {
	if req.offset == 0 {
		if !req.hasLength {
			return ErrLargeBlobsMissingLength
		}
		if req.length > uint32(a.config.MaxLargeBlobArray) {
			return ErrLargeBlobsStorageFull
		}
		if req.length < minSerializedLargeBlobArray || uint32(len(req.set)) > req.length {
			return ErrLargeBlobsInvalidLength
		}
		return nil
	}

	// length is only meaningful on the offset-0 fragment that declares the
	// total; the spec rejects it on any later fragment.
	if req.hasLength {
		return ErrInvalidParameter
	}

	pending := a.largeBlobPending
	if pending == nil || uint32(len(pending.buf)) != req.offset {
		return ErrLargeBlobsInvalidSeq
	}
	if req.offset+uint32(len(req.set)) > pending.expected {
		return ErrLargeBlobsSetExceedsLength
	}

	return nil
}

// verifyLargeBlobsWriteAuth enforces the CTAP 2.1 §6.10.2 authentication
// requirement for a Set fragment: every fragment must carry a valid
// pinUvAuthParam for a token holding the lbw (large-blob-write) permission
// whenever the authenticator has a PIN configured, or whenever the alwaysUv
// option is enabled. An authenticator with neither has nothing to
// authenticate the caller against, so the spec permits the write
// unauthenticated in that case.
func (a *Authenticator) verifyLargeBlobsWriteAuth(req *largeBlobsRequest) error {
	// The negated-conjunction form is deliberate and stays. The doc above
	// states CTAP 2.1 §6.10.2 as "whenever the authenticator has a PIN
	// configured, or whenever alwaysUv is enabled ... an authenticator with
	// NEITHER has nothing to authenticate the caller against", and this line
	// is that sentence: !(PIN configured) && !(alwaysUv). De Morgan would
	// distribute "has a PIN configured" into a disjunction and break the
	// one-to-one reading against the spec — in the predicate that decides
	// whether a large-blob write proceeds UNAUTHENTICATED.
	//
	// QF1001 is staticcheck's quickfix family: a rewrite, not a defect. This
	// repo already draws that line, restricting gocritic to diagnostic tags
	// because "the style and opinionated tags flag rewrites rather than
	// defects" (.golangci.yml).
	//nolint:staticcheck // QF1001: see above.
	if !(a.config.EnablePIN && a.IsPINSet()) && !a.config.AlwaysUV {
		return nil
	}

	if len(req.pinUvAuthParam) == 0 {
		return ErrPINRequired
	}

	if !req.hasProtocol {
		return ErrLargeBlobsMissingPinUvAuthProtocol
	}

	if req.pinUvAuthProtocol != PINProtocol1 && req.pinUvAuthProtocol != PINProtocol2 {
		return ErrUnsupportedPINProtocol
	}

	msg := largeBlobsPinAuthMessage(req.offset, req.set)
	return a.AuthorizePinUvAuthToken(msg, req.pinUvAuthParam, PINPermissionLargeBlobWrite, "")
}

// largeBlobsPinAuthMessage builds the message authenticated by a Set
// fragment's pinUvAuthParam, per CTAP 2.1 §6.10.2:
//
//	32×0xff || h'0c00' || uint32LittleEndian(offset) || SHA-256(fragment)
//
// The two-byte h'0c00' field is fixed: 0x0c (CmdLargeBlobs) followed by a
// reserved 0x00 byte. It is not a command-plus-subcommand pair the way
// authenticatorConfig's equivalent message is — authenticatorLargeBlobs has
// no subcommand — so both bytes are literal, not derived.
func largeBlobsPinAuthMessage(offset uint32, fragment []byte) []byte {
	sum := sha256.Sum256(fragment)

	msg := make([]byte, 0, 32+2+4+len(sum))
	for i := 0; i < 32; i++ {
		msg = append(msg, 0xFF)
	}
	msg = append(msg, CmdLargeBlobs, 0x00)

	offsetLE := make([]byte, 4)
	binary.LittleEndian.PutUint32(offsetLE, offset)
	msg = append(msg, offsetLE...)
	msg = append(msg, sum[:]...)

	return msg
}

// initialLargeBlobArray returns the CTAP 2.1 §6.10.2-defined initial
// serialized large blob array reported before any Set has completed: the
// 1-byte CBOR encoding of an empty array (0x80) followed by the leftmost 16
// bytes of its SHA-256 hash.
func initialLargeBlobArray() []byte {
	empty := []byte{0x80}
	sum := sha256.Sum256(empty)
	return append(empty, sum[:largeBlobChecksumLength]...)
}

// validateSerializedLargeBlobArray checks that data is at least the minimum
// valid size and that its trailing checksum matches its payload, per CTAP
// 2.1 §6.10.2.
func validateSerializedLargeBlobArray(data []byte) error {
	if len(data) < minSerializedLargeBlobArray {
		return ErrLargeBlobsInvalidLength
	}

	payload := data[:len(data)-largeBlobChecksumLength]
	checksum := data[len(data)-largeBlobChecksumLength:]

	sum := sha256.Sum256(payload)
	if !bytes.Equal(sum[:largeBlobChecksumLength], checksum) {
		return ErrLargeBlobsChecksumInvalid
	}

	return nil
}

// toUint32 converts CBOR-decoded integer types to uint32, rejecting negative
// values and values that would overflow.
func toUint32(v interface{}) (uint32, error) {
	switch n := v.(type) {
	case int:
		if n < 0 || n > int(^uint32(0)) {
			return 0, ErrInvalidParameter
		}
		return uint32(n), nil
	case int8:
		if n < 0 {
			return 0, ErrInvalidParameter
		}
		return uint32(n), nil
	case int16:
		if n < 0 {
			return 0, ErrInvalidParameter
		}
		return uint32(n), nil
	case int32:
		if n < 0 {
			return 0, ErrInvalidParameter
		}
		return uint32(n), nil
	case int64:
		if n < 0 || n > int64(^uint32(0)) {
			return 0, ErrInvalidParameter
		}
		return uint32(n), nil
	case uint:
		if uint64(n) > uint64(^uint32(0)) {
			return 0, ErrInvalidParameter
		}
		return uint32(n), nil
	case uint8:
		return uint32(n), nil
	case uint16:
		return uint32(n), nil
	case uint32:
		return n, nil
	case uint64:
		if n > uint64(^uint32(0)) {
			return 0, ErrInvalidParameter
		}
		return uint32(n), nil
	default:
		return 0, ErrInvalidParameter
	}
}
