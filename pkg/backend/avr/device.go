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

package avr

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	aggeneric "github.com/jeremyhahn/trusted-firmware/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// statusErrors maps the wire's status codes onto this package's sentinels.
//
// A map rather than a switch so that a status with no entry is a lookup miss
// and lands on ErrDeviceRefused. Status codes extend and never renumber, so an
// unrecognised one must degrade to the generic refusal — reading it as the
// nearest known code would turn "this host is older than the firmware" into a
// specific, wrong diagnosis.
var statusErrors = map[aggeneric.Status]error{
	aggeneric.StatusErrUnknownCmd:      ErrCommandUnavailable,
	aggeneric.StatusErrNotProvisioned:  ErrNotProvisioned,
	aggeneric.StatusErrCrypto:          ErrDeviceCrypto,
	aggeneric.StatusErrAuthRequired:    ErrAuthRequired,
	aggeneric.StatusErrBusy:            ErrDeviceBusy,
	aggeneric.StatusErrProtectedRegion: ErrProtectedRegion,
	aggeneric.StatusErrInternal:        ErrDeviceInternal,
	aggeneric.StatusErrTimeout:         ErrDeviceUnreachable,
	aggeneric.StatusErrCRC:             ErrDeviceProtocol,
	aggeneric.StatusErrFraming:         ErrDeviceProtocol,
	aggeneric.StatusErrUnsupported:     ErrUnsupportedByDevice,
	aggeneric.StatusErrNACK:            ErrElementUnreachable,
	aggeneric.StatusErrRange:           ErrInvalidArgument,
	aggeneric.StatusErrBadArgc:         ErrInvalidArgument,
}

// deviceError translates an SDK error into this package's vocabulary.
//
// The distinction a caller acts on is not the sentence but what to do next:
// reconnect, retry, refuse the device, or fix its own argument. So a link or
// timeout failure becomes ErrDeviceUnreachable, an unreadable frame becomes
// ErrDeviceProtocol, and anything the device itself answered becomes the
// sentinel its status maps to.
//
// The SDK's own error is JOINED rather than flattened into a string, so both
// sides stay reachable: errors.Is against this package's sentinel says what to
// do, and errors.As against the SDK's type reaches the values that say why --
// the computed and claimed checksums, the two lengths, the elapsed time. It
// also keeps io.EOF reachable underneath a link failure, which is how a closed
// port, needing a reconnect, is told from a stalled one.
func deviceError(err error) error {
	if err == nil {
		return nil
	}

	// A cancelled or expired context is the CALLER's decision, not the
	// device's answer, and is returned unchanged so errors.Is against
	// context.Canceled keeps working through this layer.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	return &errs.Joined{Lead: classify(err), Cause: err}
}

// classify picks the sentinel that says what a caller should do next.
func classify(err error) error {
	var status aggeneric.Status
	if errors.As(err, &status) {
		sentinel, ok := statusErrors[status]
		if !ok {
			// A status this build has no mapping for. Degraded to the generic
			// refusal rather than to the nearest known code: statuses extend
			// and never renumber, so an unrecognised one means this host is
			// older than the firmware, not that a different failure occurred.
			return ErrDeviceRefused
		}
		return sentinel
	}

	var version *aggeneric.ProtocolVersionError
	if errors.As(err, &version) {
		return ErrProtocolVersion
	}

	var short *aggeneric.ShortReplyError
	if errors.As(err, &short) {
		return ErrDeviceProtocol
	}

	// An argument the SDK refused before it built a frame. Classified here so
	// it cannot fall through to "the device did not answer", which would send
	// a caller to look at the cable for a fault in its own call.
	var argRange *aggeneric.ArgRangeError
	if errors.As(err, &argRange) {
		return ErrInvalidArgument
	}

	switch {
	case errors.Is(err, aggeneric.ErrBadCRC),
		errors.Is(err, aggeneric.ErrBadFormat),
		errors.Is(err, aggeneric.ErrShortFrame),
		errors.Is(err, aggeneric.ErrPayloadTooLarge):
		return ErrDeviceProtocol
	}

	// Everything left -- a link failure, a timeout, or a transport error this
	// package has never seen -- is a device that did not answer. Never nil:
	// an unclassified failure is still a failure.
	return ErrDeviceUnreachable
}

// Identity is the hardware identity of the secure element in the attached
// device, as the element itself reports it.
//
// The serial number is the element's own, burned in at the die, so it names the
// same physical component across a reflash, a re-enrolment and every name a
// host ever gave it. It is NOT what a device record is keyed on, because it is
// readable only from a provisioning image: the commands that read it are
// compiled out of the firmware a part ships with. A record is keyed on the
// identity public key, which a fielded device will answer for; this is the
// bench-time cross-check that the key belongs to the element it should.
type Identity struct {
	// Serial is the element's nine-byte serial number, lower-case hex.
	Serial string

	// SerialBytes is the same value unencoded, for a caller placing it in a
	// certificate extension or a database key rather than in a log line.
	SerialBytes []byte

	// Revision identifies the die. The third byte is 0x60 on the 608 family.
	Revision []byte

	// ConfigLocked and DataLocked are the two zones' lock states.
	//
	// Both are reported because they mean different things. A locked config
	// zone says the slot layout -- which slot holds the identity, what may read
	// it -- is fixed. A locked data zone says the key material itself can no
	// longer be written. A part with a locked config zone and an open data zone
	// is part-way through provisioning, which is neither a blank nor a finished
	// device and must not be mistaken for either.
	//
	// Note the polarity upstream decodes from: the element writes 0x55 for
	// UNLOCKED, so the value that looks like a flag being set is the zone being
	// open. These fields are already the right way round; do not re-invert.
	ConfigLocked bool
	DataLocked   bool
}

// Provisioned reports whether both zones are locked, which is the only state in
// which the identity is fixed and the key material can no longer be rewritten.
func (i Identity) Provisioned() bool { return i.ConfigLocked && i.DataLocked }

// String renders the identity for a log line.
func (i Identity) String() string {
	return fmt.Sprintf("element %s (config locked %t, data locked %t)",
		i.Serial, i.ConfigLocked, i.DataLocked)
}

// newIdentity converts what the SDK read off the element.
func newIdentity(info *aggeneric.ElementInfo) *Identity {
	serial := make([]byte, len(info.Serial))
	copy(serial, info.Serial[:])
	revision := make([]byte, len(info.Revision))
	copy(revision, info.Revision[:])

	return &Identity{
		Serial:       hex.EncodeToString(serial),
		SerialBytes:  serial,
		Revision:     revision,
		ConfigLocked: info.ConfigLocked,
		DataLocked:   info.DataLocked,
	}
}

// Health is the device's runtime state.
//
// Uptime is NOT a timestamp and must never be used as one. No part in this
// family has a clock, so nothing the device reports can establish when
// anything happened; freshness is always the verifier's nonce. Uptime says how
// long the part has been running, which is context — a device that keeps
// restarting is a device to look at — and the reset cause says why it last
// did.
type Health struct {
	Uptime     time.Duration
	FreeRAM    uint16
	ResetCause aggeneric.ResetCause
}
