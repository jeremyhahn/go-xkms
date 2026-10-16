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

package evidence

import (
	"errors"
	"strconv"
)

// Class says what kind of failure an *Error reports.
type Class int

const (
	// ClassForged reports evidence that was present and is wrong: a
	// signature that does not verify, a digest that does not match, a
	// structure no TPM emits.
	ClassForged Class = iota + 1

	// ClassAbsent reports a check that could not run: the evidence, or a
	// value the check needs, is missing or outside what can be compared.
	// Nothing was proven wrong.
	ClassAbsent
)

// String implements fmt.Stringer.
func (c Class) String() string {
	switch c {
	case ClassForged:
		return "forged"
	case ClassAbsent:
		return "absent"
	default:
		return "unknown"
	}
}

// The checks an *Error names.
const (
	CheckQuote          = "quote"
	CheckSignature      = "signature"
	CheckQualifyingData = "qualifying-data"
	CheckPCRDigest      = "pcr-digest"
	CheckBaseline       = "baseline"
	CheckAKCertificate  = "ak-certificate"
	CheckEKCertificate  = "ek-certificate"
	CheckEventLog       = "event-log"
)

// Sentinels matched by errors.Is against an *Error of the same class.
var (
	// ErrForged matches every ClassForged *Error.
	ErrForged = errors.New("evidence: forged")

	// ErrAbsent matches every ClassAbsent *Error.
	ErrAbsent = errors.New("evidence: absent")
)

// Error is the failure of one evidence check.
type Error struct {
	// Class is the kind of failure.
	Class Class
	// Check names the check that failed (one of the Check constants).
	Check string
	// Reason says what was wrong, in words a log reader can act on.
	Reason string
	// Cause is an underlying error, when there is one.
	Cause error
}

// Error implements error.
func (e *Error) Error() string {
	return "evidence: " + e.Check + ": " + e.Reason
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error { return e.Cause }

// Is matches ErrForged and ErrAbsent by class.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrForged:
		return e.Class == ClassForged
	case ErrAbsent:
		return e.Class == ClassAbsent
	}
	return false
}

// forged builds a ClassForged *Error.
func forged(check, reason string) *Error {
	return &Error{Class: ClassForged, Check: check, Reason: reason}
}

// absent builds a ClassAbsent *Error.
func absent(check, reason string) *Error {
	return &Error{Class: ClassAbsent, Check: check, Reason: reason}
}

// ErrEventLogMalformed matches every *EventLogError.
var ErrEventLogMalformed = errors.New("evidence: malformed event log")

// EventLogError reports an event log that does not parse as a TCG PC Client
// crypto-agile log.
type EventLogError struct {
	// Offset is the byte offset at which parsing failed.
	Offset int
	// Event is the 0-based index of the record being parsed.
	Event int
	// Reason says what was wrong.
	Reason string
}

// Error implements error.
func (e *EventLogError) Error() string {
	return "evidence: malformed event log: event " + strconv.Itoa(e.Event) +
		" at offset " + strconv.Itoa(e.Offset) + ": " + e.Reason
}

// Is matches ErrEventLogMalformed.
func (e *EventLogError) Is(target error) bool { return target == ErrEventLogMalformed }

// SubstitutionError reports a replay substitution (EventLog.ReplayWith) that
// cannot be applied to the log.
type SubstitutionError struct {
	// PCR and Ordinal name the event the substitution replaces.
	PCR     int
	Ordinal int
	// Reason says what was wrong.
	Reason string
}

// Error implements error.
func (e *SubstitutionError) Error() string {
	return "evidence: replay substitution for PCR " + strconv.Itoa(e.PCR) +
		" event " + strconv.Itoa(e.Ordinal) + ": " + e.Reason
}
