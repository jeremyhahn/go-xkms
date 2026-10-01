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

package signserver

import "errors"

// Configuration errors.
var (
	// ErrSocketPathRequired reports a Config with no socket path.
	ErrSocketPathRequired = errors.New("signserver: socket path is required")

	// ErrNoAllowedPeers reports a Config that admits no uid or gid.
	ErrNoAllowedPeers = errors.New("signserver: at least one allowed uid or gid is required")

	// ErrBackendsRequired reports a Config with no key backend.
	ErrBackendsRequired = errors.New("signserver: at least one key backend is required")

	// ErrStateStorageRequired reports a Config with no token store.
	ErrStateStorageRequired = errors.New("signserver: token state storage is required")

	// ErrSlotsRequired reports a Config with no slot.
	ErrSlotsRequired = errors.New("signserver: at least one slot is required")

	// ErrSlotTokenRequired reports a slot with no token label.
	ErrSlotTokenRequired = errors.New("signserver: slot token label is required")

	// ErrSlotDuplicate reports two slots with the same token label.
	ErrSlotDuplicate = errors.New("signserver: slot token label is configured twice")

	// ErrSlotKeysRequired reports a slot that names no key, or an empty one.
	ErrSlotKeysRequired = errors.New("signserver: slot must name at least one non-empty key label")
)

// Request errors.
var (
	// ErrUnknownSlot reports a token label that is not a configured slot.
	ErrUnknownSlot = errors.New("signserver: token is not a configured slot")

	// ErrKeyNotNamed reports a CreateKey for a label the slot does not name.
	ErrKeyNotNamed = errors.New("signserver: key label is not one of the slot's keys")

	// ErrKeyNotAdmitted reports a Sign naming a key no slot exposes.
	ErrKeyNotAdmitted = errors.New("signserver: key is not exposed by any slot")

	// ErrTokenWriteDenied reports a token write outside the lockout counters.
	ErrTokenWriteDenied = errors.New("signserver: only PIN-lockout counters may be written on a sign-only slot")

	// ErrRequestShape reports a request whose type does not match its method.
	ErrRequestShape = errors.New("signserver: request does not match its method")
)

// Error reports the server operation that failed and why.
type Error struct {
	// Op names the operation.
	Op string
	// Err is the cause.
	Err error
}

// Error implements error.
func (e *Error) Error() string { return "signserver: " + e.Op + ": " + e.Err.Error() }

// Unwrap returns the cause.
func (e *Error) Unwrap() error { return e.Err }

// SlotError adds the slot a failure concerns.
type SlotError struct {
	// Token is the slot's token label.
	Token string
	// Err is the cause.
	Err error
}

// Error implements error.
func (e *SlotError) Error() string { return "slot " + e.Token + ": " + e.Err.Error() }

// Unwrap returns the cause.
func (e *SlotError) Unwrap() error { return e.Err }
