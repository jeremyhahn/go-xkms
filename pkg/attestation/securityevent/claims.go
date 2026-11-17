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
	"bytes"
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"
)

// ClaimKey is the claim key of the record in its Claims-Set. EAT (RFC 9711)
// registers no claim for a device security-event record, so the key is
// go-xkms's own, taken from the CWT private-use range (RFC 8392 §9.1:
// integer keys below -65536), until one is registered.
const ClaimKey int64 = -71765

// MaxEntries is the most entries a record holds: count is one byte.
const MaxEntries = math.MaxUint8

// Member keys of the record map and of each entry map.
const (
	keyCount   = 1
	keyDropped = 2
	keyEntries = 3

	keyAt     = 1
	keyKind   = 2
	keyWhat   = 3
	keyResult = 4
)

// Record is the device's tamper-response record.
type Record struct {
	// Count is the number of entries the device holds, 0..Count-1.
	Count uint8
	// Dropped is the number of entries lost after the log filled. The
	// device saturates it at 0xFFFF.
	Dropped uint16
	// Entries are the entries in index order; len(Entries) == Count.
	Entries []Entry
}

// Entry is one entry of the record.
type Entry struct {
	// At is the engine's clock when the entry was written. It is not a
	// time, so it is never an iat claim.
	At uint32
	// Kind is signal, decision or action.
	Kind uint8
	// What is what was signalled, decided or done.
	What uint8
	// Result is its outcome.
	Result uint8
}

var (
	encMode = mustEncMode()
	decMode = mustDecMode()
)

func mustEncMode() cbor.EncMode {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return em
}

func mustDecMode() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		TagsMd:           cbor.TagsForbidden,
		MaxArrayElements: MaxEntries + 1,
		MaxMapPairs:      16,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return dm
}

// Encode returns r's Claims-Set in core deterministic encoding. It refuses
// a record whose Count is not len(Entries) with ErrCountMismatch.
func Encode(r Record) ([]byte, error) {
	if len(r.Entries) != int(r.Count) {
		return nil, fmt.Errorf("%w: count %d, %d entries", ErrCountMismatch, r.Count, len(r.Entries))
	}
	entries := make([]map[uint64]uint64, 0, len(r.Entries))
	for _, e := range r.Entries {
		entries = append(entries, map[uint64]uint64{
			keyAt: uint64(e.At), keyKind: uint64(e.Kind), keyWhat: uint64(e.What), keyResult: uint64(e.Result),
		})
	}
	return encMode.Marshal(map[int64]map[uint64]any{
		ClaimKey: {keyCount: uint64(r.Count), keyDropped: uint64(r.Dropped), keyEntries: entries},
	})
}

// Decode reads a record from its Claims-Set. It refuses input that breaks
// any rule of the format with ErrMalformed, ErrUnknownKey, ErrMissingKey,
// ErrOutOfRange, ErrCountMismatch or ErrNotDeterministic.
func Decode(data []byte) (Record, error) {
	var top map[any]cbor.RawMessage
	if err := unmarshal(data, &top, "Claims-Set"); err != nil {
		return Record{}, err
	}
	for k := range top {
		if k != any(ClaimKey) {
			return Record{}, fmt.Errorf("%w: Claims-Set key %s", ErrUnknownKey, describeKey(k))
		}
	}
	raw, ok := top[ClaimKey]
	if !ok {
		return Record{}, fmt.Errorf("%w: Claims-Set has no claim %d", ErrMissingKey, ClaimKey)
	}
	rec, err := decodeRecord(raw)
	if err != nil {
		return Record{}, err
	}
	canonical, err := Encode(rec)
	if err != nil {
		return Record{}, err
	}
	if !bytes.Equal(canonical, data) {
		return Record{}, ErrNotDeterministic
	}
	return rec, nil
}

func decodeRecord(raw cbor.RawMessage) (Record, error) {
	m, err := members(raw, keyEntries, "record")
	if err != nil {
		return Record{}, err
	}
	count, err := uintMember(m[keyCount-1], math.MaxUint8, "count")
	if err != nil {
		return Record{}, err
	}
	dropped, err := uintMember(m[keyDropped-1], math.MaxUint16, "dropped")
	if err != nil {
		return Record{}, err
	}
	var rawEntries []cbor.RawMessage
	if err := unmarshal(m[keyEntries-1], &rawEntries, "entries"); err != nil {
		return Record{}, err
	}
	rec := Record{Count: uint8(count), Dropped: uint16(dropped)}
	for i, re := range rawEntries {
		e, err := decodeEntry(re)
		if err != nil {
			return Record{}, fmt.Errorf("entry %d: %w", i, err)
		}
		rec.Entries = append(rec.Entries, e)
	}
	if len(rec.Entries) != int(rec.Count) {
		return Record{}, fmt.Errorf("%w: count %d, %d entries", ErrCountMismatch, rec.Count, len(rec.Entries))
	}
	return rec, nil
}

func decodeEntry(raw cbor.RawMessage) (Entry, error) {
	m, err := members(raw, keyResult, "entry")
	if err != nil {
		return Entry{}, err
	}
	at, err := uintMember(m[keyAt-1], math.MaxUint32, "at")
	if err != nil {
		return Entry{}, err
	}
	var small [3]uint8
	for i, name := range []string{"kind", "what", "result"} {
		v, err := uintMember(m[keyKind-1+i], math.MaxUint8, name)
		if err != nil {
			return Entry{}, err
		}
		small[i] = uint8(v)
	}
	return Entry{At: uint32(at), Kind: small[0], What: small[1], Result: small[2]}, nil
}

// members decodes a map whose keys are exactly 1..n and returns its values
// by key-1.
func members(raw cbor.RawMessage, n int, what string) ([]cbor.RawMessage, error) {
	var m map[any]cbor.RawMessage
	if err := unmarshal(raw, &m, what); err != nil {
		return nil, err
	}
	out := make([]cbor.RawMessage, n)
	for k, v := range m {
		u, ok := k.(uint64)
		if !ok || u < 1 || u > uint64(n) {
			return nil, fmt.Errorf("%w: %s key %s", ErrUnknownKey, what, describeKey(k))
		}
		out[u-1] = v
	}
	for i, v := range out {
		if v == nil {
			return nil, fmt.Errorf("%w: %s key %d", ErrMissingKey, what, i+1)
		}
	}
	return out, nil
}

// uintMember decodes an unsigned integer no larger than limit.
func uintMember(raw cbor.RawMessage, limit uint64, name string) (uint64, error) {
	var v any
	if err := unmarshal(raw, &v, name); err != nil {
		return 0, err
	}
	switch n := v.(type) {
	case uint64:
		if n > limit {
			return 0, fmt.Errorf("%w: %s %d exceeds %d", ErrOutOfRange, name, n, limit)
		}
		return n, nil
	case int64:
		return 0, fmt.Errorf("%w: %s is negative", ErrOutOfRange, name)
	default:
		return 0, fmt.Errorf("%w: %s is a %T, not an unsigned integer", ErrMalformed, name, v)
	}
}

func unmarshal(data []byte, v any, what string) error {
	if err := decMode.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrMalformed, what, err)
	}
	return nil
}

// describeKey names a map key for an error without echoing a text key,
// which the input chooses and may be long.
func describeKey(k any) string {
	switch k.(type) {
	case uint64, int64:
		return fmt.Sprint(k)
	default:
		return fmt.Sprintf("of type %T", k)
	}
}
