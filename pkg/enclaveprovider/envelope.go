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

package enclaveprovider

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"maps"
	"slices"
	"strconv"

	enclave "github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// The envelope wraps a backend's types.SealedData. All integers are
// big-endian, and every field is a uint32 length followed by its bytes:
//
//	magic       "XKEP"
//	version     1 byte, envelopeVersion
//	purpose     1 byte, purposeKey or purposeRoot
//	backend, key ID, ciphertext, nonce, tag, wrapped DEK,
//	TPM public, TPM private                       8 fields
//	key version uint32
//	metadata    uint32 count, then key and value fields, keys strictly ascending
//	tag         HMAC-SHA256 over everything above
//
// The tag's key is derived with HKDF-SHA256 (Expand) from the protected key, so
// only the holder of that key can produce a valid tag. Backends authenticate
// their ciphertext but not always the fields beside it (a TPM handle in the
// metadata, a key version); the tag makes every byte count.
const (
	envelopeMagic   = "XKEP"
	envelopeVersion = 1

	// maxEnvelopeSize bounds an envelope. No backend's sealed 32-byte key
	// comes near it; decode refuses anything larger before parsing.
	maxEnvelopeSize = 64 << 10

	// tagInfo is the HKDF info that derives the tag key from the protected
	// key, separating it from every other use of that key.
	tagInfo = "go-xkms/enclaveprovider/v1/envelope-tag"
)

// purpose names what an envelope protects. It is written into the envelope
// and selects the AAD the sealer binds, so one seam's blob never opens
// through the other.
type purpose byte

const (
	// purposeKey is a per-value data key protected by KeyProtector.Protect.
	purposeKey purpose = 1
	// purposeRoot is a process root key sealed by ProvisionRoot.
	purposeRoot purpose = 2
)

// purposeAAD is the additional authenticated data the sealer binds for each
// purpose.
var purposeAAD = map[purpose]string{
	purposeKey:  "go-xkms/enclaveprovider/v1/protected-key",
	purposeRoot: "go-xkms/enclaveprovider/v1/sealed-root",
}

// aad returns p's additional authenticated data as a fresh slice, so no
// backend can alter the shared label.
func (p purpose) aad() []byte {
	return []byte(purposeAAD[p])
}

// envelope is a decoded blob: the sealed data to unseal, and the signed body
// and tag to verify once the key is recovered.
type envelope struct {
	sealed *types.SealedData
	body   []byte
	tag    []byte
}

// sealedFields lists the byte fields of sd in envelope order.
func sealedFields(sd *types.SealedData) [][]byte {
	return [][]byte{
		[]byte(sd.Backend), []byte(sd.KeyID), sd.Ciphertext, sd.Nonce, sd.Tag,
		sd.WrappedDEK, sd.TPMPublic, sd.TPMPrivate,
	}
}

// encodeEnvelope seals sd into a blob for p, tagged under key.
func encodeEnvelope(p purpose, sd *types.SealedData, key []byte) ([]byte, error) {
	body := make([]byte, 0, 256)
	body = append(body, envelopeMagic...)
	body = append(body, envelopeVersion, byte(p))
	for _, field := range sealedFields(sd) {
		body = appendField(body, field)
	}
	body = binary.BigEndian.AppendUint32(body, sd.KeyVersion)
	names := slices.Sorted(maps.Keys(sd.Metadata))
	body = binary.BigEndian.AppendUint32(body, uint32(len(names)))
	for _, name := range names {
		body = appendField(body, []byte(name))
		body = appendField(body, sd.Metadata[name])
	}
	if len(body)+sha256.Size > maxEnvelopeSize {
		return nil, &errs.Detail{Err: ErrEnvelopeTooLarge, Detail: strconv.Itoa(len(body)) + " bytes"}
	}
	tag, err := envelopeTag(key, body)
	if err != nil {
		return nil, err
	}
	return append(body, tag...), nil
}

// appendField appends field with its uint32 length prefix.
func appendField(b, field []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(field)))
	return append(b, field...)
}

// decodeEnvelope parses blob as an envelope made for want. Every failure is
// an authentication error: the blob is not one this package wrote for want.
// The returned sealed data copies blob, which is never retained or modified.
func decodeEnvelope(blob []byte, want purpose) (*envelope, error) {
	if len(blob) > maxEnvelopeSize || len(blob) < len(envelopeMagic)+2+sha256.Size {
		return nil, authenticationError(ErrMalformedEnvelope, "envelope is "+strconv.Itoa(len(blob))+" bytes")
	}
	split := len(blob) - sha256.Size
	r := envelopeReader{rest: blob[:split]}
	magic, version, use := r.next(len(envelopeMagic)), r.next(1), r.next(1)
	if r.failed || string(magic) != envelopeMagic || version[0] != envelopeVersion {
		return nil, authenticationError(ErrMalformedEnvelope, "not a version "+strconv.Itoa(envelopeVersion)+" envelope")
	}
	if purpose(use[0]) != want {
		return nil, authenticationError(ErrWrongPurpose, "purpose "+strconv.Itoa(int(use[0])))
	}
	sd := &types.SealedData{}
	sd.Backend = types.BackendType(r.field())
	sd.KeyID = string(r.field())
	sd.Ciphertext = r.field()
	sd.Nonce = r.field()
	sd.Tag = r.field()
	sd.WrappedDEK = r.field()
	sd.TPMPublic = r.field()
	sd.TPMPrivate = r.field()
	sd.KeyVersion = r.uint32()
	sd.Metadata = r.metadata()
	if r.failed || len(r.rest) != 0 {
		return nil, authenticationError(ErrMalformedEnvelope, "fields do not span the envelope")
	}
	return &envelope{
		sealed: sd,
		body:   bytes.Clone(blob[:split]),
		tag:    bytes.Clone(blob[split:]),
	}, nil
}

// envelopeReader consumes an envelope body. The first short read sets failed
// and every later read returns nothing, so a decoder checks once at the end.
type envelopeReader struct {
	rest   []byte
	failed bool
}

// next consumes n bytes, or returns nil and fails the reader.
func (r *envelopeReader) next(n int) []byte {
	if r.failed || n < 0 || n > len(r.rest) {
		r.failed = true
		return nil
	}
	b := r.rest[:n]
	r.rest = r.rest[n:]
	return b
}

// uint32 consumes a big-endian uint32.
func (r *envelopeReader) uint32() uint32 {
	b := r.next(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// field consumes a length-prefixed field and returns a copy of it, nil when
// it is empty.
func (r *envelopeReader) field() []byte {
	b := r.next(int(r.uint32()))
	if len(b) == 0 {
		return nil
	}
	return bytes.Clone(b)
}

// metadata consumes the metadata count and entries. Names must be strictly
// ascending, so each map has one encoding.
func (r *envelopeReader) metadata() map[string][]byte {
	count := r.uint32()
	if count == 0 || r.failed {
		return nil
	}
	// Each entry is at least two length prefixes; a larger count cannot fit.
	if uint64(count) > uint64(len(r.rest)/8) {
		r.failed = true
		return nil
	}
	metadata := make(map[string][]byte, count)
	previous := ""
	for i := range count {
		name := string(r.field())
		value := r.field()
		if r.failed || (i > 0 && name <= previous) {
			r.failed = true
			return nil
		}
		metadata[name] = value
		previous = name
	}
	return metadata
}

// envelopeTag computes the HMAC-SHA256 tag of body under a key derived from
// key with HKDF-SHA256.
//
// key is already uniformly random, so it is HKDF-Expand's pseudorandom key
// and Extract is skipped. That is also what keeps it off the heap: Extract
// would hash key as a message, leaving it in a SHA-256 block buffer, while
// Expand only keys an HMAC, whose pads hold key XORed, never key itself.
func envelopeTag(key, body []byte) ([]byte, error) {
	tagKey, err := hkdf.Expand(sha256.New, key, tagInfo, sha256.Size)
	if err != nil {
		return nil, err
	}
	defer enclave.Wipe(tagKey)
	mac := hmac.New(sha256.New, tagKey)
	if _, err := mac.Write(body); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// verify checks e's tag under key in constant time.
func (e *envelope) verify(key []byte) error {
	want, err := envelopeTag(key, e.body)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, e.tag) {
		return authenticationError(ErrEnvelopeTag, "")
	}
	return nil
}
