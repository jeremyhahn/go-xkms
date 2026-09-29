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

package pairing

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// Device naming and identity errors (#1307).
//
// A PairedDevice's Name is peer-chosen: the CLI stores the BLE-advertised
// local name, and the GUI stores the name the phone returns in the pairing
// confirmation RPC. Both are untrusted input from the device being paired,
// yet the CLI and the GUI both also use Name as the key for looking up
// which pinned Noise static key to trust on a later connection. Left
// unchecked, a malicious or malfunctioning peer can pick a name that is
// empty, unprintable, or identical to an already-paired device's name, and
// each of those breaks the lookup in a different way -- see
// ValidateDeviceName, ConflictingPairedDevice and FindPairedDeviceByName.
var (
	// ErrDeviceNameInvalid indicates a device name is unusable as a stored
	// record's key: empty, longer than MaxDeviceNameLength, or containing a
	// non-printable character.
	ErrDeviceNameInvalid = errors.New("pairing: invalid device name")

	// ErrDeviceNameCollision indicates a device name is already used by a
	// different paired device -- one pinned to a different Noise static
	// key, not the device being paired or re-paired. Persisting the new
	// record anyway would make every later lookup by that name ambiguous
	// between the two devices.
	ErrDeviceNameCollision = errors.New("pairing: device name is already used by a different paired device")

	// ErrDeviceNameAmbiguous indicates more than one paired device record
	// has the requested name, so FindPairedDeviceByName cannot choose
	// between them. This should be unreachable once every writer refuses
	// ErrDeviceNameCollision, but a lookup must still refuse rather than
	// guess if it ever happens -- from a record written before this check
	// existed, or a devices file edited by hand.
	ErrDeviceNameAmbiguous = errors.New("pairing: more than one paired device has this name")
)

// MaxDeviceNameLength bounds a paired device's display name. It is
// generous enough for any real device name while still refusing the
// unbounded strings a malicious peer could otherwise advertise into a
// config file, log line, or terminal prompt.
const MaxDeviceNameLength = 64

// ValidateDeviceName rejects a device name unsuitable for storage, display,
// or use as a lookup key: empty, longer than MaxDeviceNameLength, or
// containing a rune that is not printable (control characters, escape
// sequences, and similar terminal-injection payloads a malicious peer could
// advertise or return in the pairing confirmation RPC).
//
// It does not, and must not, reject on uniqueness -- that is
// ConflictingPairedDevice's job, which needs the rest of the paired
// device set and applies a different rule (same name, different key).
func ValidateDeviceName(name string) error {
	if name == "" {
		return &DetailError{Err: ErrDeviceNameInvalid, Detail: ": name is empty"}
	}
	if n := utf8.RuneCountInString(name); n > MaxDeviceNameLength {
		return &DetailError{
			Err:    ErrDeviceNameInvalid,
			Detail: fmt.Sprintf(": name is %d characters, exceeds the %d character limit", n, MaxDeviceNameLength),
		}
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return &DetailError{
				Err:    ErrDeviceNameInvalid,
				Detail: fmt.Sprintf(": name contains a non-printable character %U", r),
			}
		}
	}
	return nil
}

// ConflictingPairedDevice returns the first existing record that would
// collide with persisting a device named name, at address, pinned to
// noisePublicKeyB64 (base64), or nil if none does.
//
// A record collides when it shares the name but identifies as a DIFFERENT
// device: neither its address nor its pinned key match (see
// SamePairedDeviceIndices, which this delegates that match to). That
// combination can only mean two distinct devices were given the same
// display name, which would make every future name lookup ambiguous
// between them.
//
// A record that shares the name AND matches by address or key is not a
// collision -- it is the very record a (re-)pair under that name is about
// to replace, whatever key or address it last held: an app reinstall
// regenerates the phone's Noise identity key at the same address, and
// Android's RPA rotation changes the address for the same key, and either
// alone is enough to identify it as the same device. Neither is a record
// with a different name.
func ConflictingPairedDevice(devices []PairedDevice, name, address, noisePublicKeyB64 string) *PairedDevice {
	sameDevice := make(map[int]bool)
	for _, i := range SamePairedDeviceIndices(devices, address, noisePublicKeyB64) {
		sameDevice[i] = true
	}
	for i := range devices {
		if devices[i].Name == name && !sameDevice[i] {
			return &devices[i]
		}
	}
	return nil
}

// SamePairedDeviceIndices returns the indices of every record in devices
// that identify the SAME physical device as address or noisePublicKeyB64:
// a match on either field is enough. Android's periodic RPA rotation
// changes an already-paired phone's BLE address without changing its
// persistent Noise identity key, and a re-pair after an app reinstall can
// do the reverse, so requiring both to agree would miss either case.
//
// An empty address or key never matches -- callers that have not resolved
// one of the two yet must not pass "" and get every record with an empty
// field back.
//
// Matching on the union, rather than name, is what lets a caller replace
// every stale record for the device actually being re-paired without also
// touching an unrelated device that merely shares its display name; see
// ConflictingPairedDevice for that case instead.
func SamePairedDeviceIndices(devices []PairedDevice, address, noisePublicKeyB64 string) []int {
	var indices []int
	for i := range devices {
		if (address != "" && devices[i].Address == address) ||
			(noisePublicKeyB64 != "" && devices[i].NoisePublicKey == noisePublicKeyB64) {
			indices = append(indices, i)
		}
	}
	return indices
}

// ReplacePairedDevices returns devices with every record at an index in
// indices removed and one copy of replacement inserted at the position of
// the first removed index, preserving the order of everything else. It is
// SamePairedDeviceIndices' complement: collapsing every stale record that
// identifies the same physical device down to the one fresh record a
// successful (re-)pair just produced, rather than leaving old entries
// behind or accumulating duplicates across repeated re-pairs.
//
// indices must be indices into devices (as SamePairedDeviceIndices
// returns); duplicates are tolerated. An empty indices appends replacement.
func ReplacePairedDevices(devices []PairedDevice, indices []int, replacement PairedDevice) []PairedDevice {
	remove := make(map[int]bool, len(indices))
	for _, i := range indices {
		remove[i] = true
	}

	result := make([]PairedDevice, 0, len(devices)-len(remove)+1)
	inserted := false
	for i, d := range devices {
		if remove[i] {
			if !inserted {
				result = append(result, replacement)
				inserted = true
			}
			continue
		}
		result = append(result, d)
	}
	if !inserted {
		result = append(result, replacement)
	}
	return result
}

// FindPairedDeviceByName returns the paired device record named name.
//
// It returns (nil, nil) when no record has that name -- the caller decides
// what "not found" means for its surface, the same contract callers had
// before this existed. It returns a non-nil error, wrapping
// ErrDeviceNameAmbiguous, when MORE than one record shares the name: a
// lookup by name is how a caller picks which pinned key to trust for a
// connection, and resolving that collision by list order would let
// whichever device was paired first or last win silently, decided by an
// attacker who controls when their device pairs relative to the legitimate
// one. See ConflictingPairedDevice for refusing the collision at write time
// instead, which is what should make this case unreachable in practice.
func FindPairedDeviceByName(devices []PairedDevice, name string) (*PairedDevice, error) {
	var found *PairedDevice
	count := 0
	for i := range devices {
		if devices[i].Name == name {
			found = &devices[i]
			count++
		}
	}
	switch count {
	case 0:
		return nil, nil
	case 1:
		return found, nil
	default:
		return nil, &DetailError{
			Err:    ErrDeviceNameAmbiguous,
			Detail: fmt.Sprintf(": %d paired devices are named %q; re-pair or remove the duplicate", count, name),
		}
	}
}
