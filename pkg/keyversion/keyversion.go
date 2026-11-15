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

// Package keyversion is the key-version model of xkms: which versions a key
// has, which one is current, and the state of each.
//
// A version is its own backend key. Version 1 is the key as generated, under
// its own name K; version n > 1 is the backend key "K--v<n>". The
// "--v<digits>" suffix is reserved, so no caller can create a key that
// collides with a version. A Record, persisted per key by Store, lists the
// versions and marks the current one; a key without a record is version 1,
// alone and enabled (Implicit).
//
// The package holds the model and its storage only. Generating, deleting
// and using the backend keys is the xkms service's work (pkg/xkms).
package keyversion

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// versionSeparator joins a key ID and a version number into the backend
// name of that version: "K--v2".
const versionSeparator = "--v"

// State is the lifecycle state of one key version.
type State string

const (
	// StateEnabled marks a version every operation may use.
	StateEnabled State = "enabled"

	// StateDisabled marks a version no operation may use until it is
	// enabled again. Its backend key is kept.
	StateDisabled State = "disabled"

	// StateRetired marks a version whose backend key has been deleted. It
	// can never be used or enabled again.
	StateRetired State = "retired"
)

// Version is one version of a key.
type Version struct {
	// Number is the version number, counted from 1.
	Number uint32 `json:"number"`

	// State is the version's lifecycle state.
	State State `json:"state"`

	// CreatedAt is when the version was created. It is zero for version 1
	// of a key whose record was created by its first rotation, because the
	// key predates the record.
	CreatedAt time.Time `json:"created_at,omitempty"`

	// CreatedBy is the subject of the identity that created the version,
	// when one was known.
	CreatedBy string `json:"created_by,omitempty"`
}

// Record is the version record of one key.
type Record struct {
	// KeyID is the key's ID: the backend name of version 1.
	KeyID string `json:"key_id"`

	// Backend is the name of the backend the key and all its versions live
	// in.
	Backend string `json:"backend"`

	// Current is the version sign and encrypt use.
	Current uint32 `json:"current"`

	// Versions lists every version, ascending by Number.
	Versions []Version `json:"versions"`
}

// Name returns the backend name of version n of keyID: keyID itself for
// version 1, and "keyID--v<n>" for any later version.
func Name(keyID string, n uint32) string {
	if n <= 1 {
		return keyID
	}
	return keyID + versionSeparator + strconv.FormatUint(uint64(n), 10)
}

// Parse splits a backend key name into the key ID and version number it
// names. It reports ok only for the names Name produces for a version after
// the first: "K--v<n>" with n >= 2 written without leading zeros. Any other
// name, including K itself, is not a version name.
func Parse(name string) (keyID string, n uint32, ok bool) {
	i := strings.LastIndex(name, versionSeparator)
	if i <= 0 {
		return "", 0, false
	}
	digits := name[i+len(versionSeparator):]
	if digits == "" || digits[0] == '0' || !allDigits(digits) {
		return "", 0, false
	}
	v, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || v < 2 {
		return "", 0, false
	}
	return name[:i], uint32(v), true
}

// BaseKeyID returns the key ID a backend key name belongs to: the key ID
// Parse recovers from a version name, or name itself for any other name.
func BaseKeyID(name string) string {
	if keyID, _, ok := Parse(name); ok {
		return keyID
	}
	return name
}

// IsReserved reports whether keyID ends in the reserved version suffix
// "--v<digits>" -- any digits, so "--v1" and "--v01" are reserved too.
func IsReserved(keyID string) bool {
	i := strings.LastIndex(keyID, versionSeparator)
	if i < 0 {
		return false
	}
	digits := keyID[i+len(versionSeparator):]
	return digits != "" && allDigits(digits)
}

// CheckKeyID refuses a key ID a caller may not create a key under: one
// ending in the reserved version suffix. It returns *ReservedKeyIDError.
func CheckKeyID(keyID string) error {
	if IsReserved(keyID) {
		return &ReservedKeyIDError{KeyID: keyID}
	}
	return nil
}

// allDigits reports whether s holds only ASCII digits.
func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Implicit returns the record of a key that has never been rotated:
// version 1, current and enabled.
func Implicit(keyID, backend string) *Record {
	return &Record{
		KeyID:    keyID,
		Backend:  backend,
		Current:  1,
		Versions: []Version{{Number: 1, State: StateEnabled}},
	}
}

// Version returns version n of the record. A zero n is refused with
// *InvalidVersionError, and a number the record does not hold with
// *VersionNotFoundError.
func (r *Record) Version(n uint32) (*Version, error) {
	if n == 0 {
		return nil, &InvalidVersionError{Version: n}
	}
	for i := range r.Versions {
		if r.Versions[i].Number == n {
			return &r.Versions[i], nil
		}
	}
	return nil, &VersionNotFoundError{KeyID: r.KeyID, Version: n}
}

// Usable returns version n when an operation may use it: it must exist and
// be enabled. A disabled or retired version is refused with
// *VersionUnavailableError.
func (r *Record) Usable(n uint32) (*Version, error) {
	v, err := r.Version(n)
	if err != nil {
		return nil, err
	}
	if v.State != StateEnabled {
		return nil, &VersionUnavailableError{KeyID: r.KeyID, Version: n, State: v.State}
	}
	return v, nil
}

// Enabled returns the numbers of the enabled versions, newest first.
func (r *Record) Enabled() []uint32 {
	enabled := make([]uint32, 0, len(r.Versions))
	for i := len(r.Versions) - 1; i >= 0; i-- {
		if r.Versions[i].State == StateEnabled {
			enabled = append(enabled, r.Versions[i].Number)
		}
	}
	return enabled
}

// Next returns the number the next version will take: one past the highest
// version the record has ever held, retired ones included, so a number is
// never reused.
func (r *Record) Next() uint32 {
	var highest uint32
	for _, v := range r.Versions {
		highest = max(highest, v.Number)
	}
	return highest + 1
}

// AddCurrent records version n, enabled, created at by createdBy, and makes
// it current.
func (r *Record) AddCurrent(n uint32, at time.Time, createdBy string) {
	r.Versions = append(r.Versions, Version{Number: n, State: StateEnabled, CreatedAt: at, CreatedBy: createdBy})
	slices.SortFunc(r.Versions, func(a, b Version) int { return cmp.Compare(a.Number, b.Number) })
	r.Current = n
}

// SetState enables or disables version n. The current version cannot be
// disabled (*CurrentVersionError), and a retired version cannot change
// state (*RetiredVersionError). Retiring goes through Retire, which the
// caller pairs with deleting the version's backend key. It reports whether
// the state changed.
func (r *Record) SetState(n uint32, state State) (bool, error) {
	v, err := r.Version(n)
	if err != nil {
		return false, err
	}
	if v.State == StateRetired {
		return false, &RetiredVersionError{KeyID: r.KeyID, Version: n}
	}
	if state == StateDisabled && n == r.Current {
		return false, &CurrentVersionError{KeyID: r.KeyID, Version: n, Operation: "disable"}
	}
	if v.State == state {
		return false, nil
	}
	v.State = state
	return true, nil
}

// Retire marks version n retired. The current version cannot be retired
// (*CurrentVersionError), and a version already retired is refused with
// *RetiredVersionError: retiring is final and happens once.
func (r *Record) Retire(n uint32) error {
	v, err := r.Version(n)
	if err != nil {
		return err
	}
	if v.State == StateRetired {
		return &RetiredVersionError{KeyID: r.KeyID, Version: n}
	}
	if n == r.Current {
		return &CurrentVersionError{KeyID: r.KeyID, Version: n, Operation: "retire"}
	}
	v.State = StateRetired
	return nil
}

// SetAll sets every version that can take state to it: enabling reaches
// every disabled version, and disabling every enabled version except the
// current one. Retired versions are never touched. It returns the numbers of
// the versions whose state changed, ascending.
func (r *Record) SetAll(state State) []uint32 {
	var changed []uint32
	for i := range r.Versions {
		v := &r.Versions[i]
		if v.State == StateRetired || v.State == state {
			continue
		}
		if state == StateDisabled && v.Number == r.Current {
			continue
		}
		v.State = state
		changed = append(changed, v.Number)
	}
	return changed
}
