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

package audit

import (
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/metrics"
)

// Severity classifies an EventType by how a failed write to the audit sink
// must be handled. See docs/audit-log/engineering.md for the policy this
// implements.
type Severity int

const (
	// SeverityInformational events are audited best-effort: a failed write
	// is logged and counted but never fails the request that produced it.
	SeverityInformational Severity = iota

	// SeveritySecurity events must be provably audited: a failed write
	// fails the request that produced it rather than let a security-
	// relevant action proceed unaudited.
	SeveritySecurity
)

// informationalEvents is the fixed set of EventType values classified
// SeverityInformational: ACME account, order, authorization, and challenge
// protocol-lifecycle progress that is not itself a security decision.
// EventChallengeFailed is deliberately excluded — a failed challenge can
// signal an attack attempt and is classified SeveritySecurity below.
//
// Every EventType not listed here — including the Security Events, CA
// Lifecycle Events, Certificate Authority Events, and TPM/Attestation
// Events groups in types.go, and any event added later without updating
// this set — classifies SeveritySecurity by default (see Severity):
// fail-closed is the safe default for an event nobody has explicitly
// reviewed and classified informational.
var informationalEvents = map[EventType]bool{
	EventAccountCreated:     true,
	EventAccountUpdated:     true,
	EventAccountDeactivated: true,

	EventOrderCreated:   true,
	EventOrderFinalized: true,
	EventOrderCanceled:  true,

	EventAuthorizationCreated:     true,
	EventAuthorizationValidated:   true,
	EventAuthorizationDeactivated: true,

	EventChallengeInitiated: true,
	EventChallengeCompleted: true,
	EventChallengeValidated: true,
}

// Severity returns e's audit write-failure classification. An EventType
// not listed in informationalEvents — known or not — classifies
// SeveritySecurity.
func (e EventType) Severity() Severity {
	if informationalEvents[e] {
		return SeverityInformational
	}
	return SeveritySecurity
}

// ErrAuditWriteFailed is returned when a SeveritySecurity audit event fails
// to persist. Callers must fail the operation that produced the event
// rather than proceed with an unaudited security-relevant action.
type ErrAuditWriteFailed struct {
	EventType EventType
	Cause     error
}

// Error implements the error interface.
func (e *ErrAuditWriteFailed) Error() string {
	return fmt.Sprintf("audit: security event %q failed to persist: %v", e.EventType, e.Cause)
}

// Unwrap returns the underlying write failure.
func (e *ErrAuditWriteFailed) Unwrap() error {
	return e.Cause
}

// HandleWriteFailure applies the go-xkms audit write-failure policy to the
// error returned from an AuditLogger.Log / LogWithContext call. writeErr
// must be that error (nil means the write succeeded, in which case
// HandleWriteFailure is a no-op).
//
// For a SeveritySecurity event, HandleWriteFailure returns
// *ErrAuditWriteFailed; the caller must propagate it and fail the request
// rather than complete a security-relevant ACME operation that could not
// be audited.
//
// For a SeverityInformational event, HandleWriteFailure logs the failure
// through slogger (a nil slogger is permitted and simply skips the log
// line), increments metrics.AuditWriteFailuresTotal, and returns nil so
// the caller proceeds.
func HandleWriteFailure(slogger *slog.Logger, eventType EventType, writeErr error) error {
	if writeErr == nil {
		return nil
	}
	if eventType.Severity() == SeverityInformational {
		if slogger != nil {
			slogger.Error("audit: informational event failed to persist", "eventType", string(eventType), "error", writeErr)
		}
		metrics.AuditWriteFailuresTotal.WithLabelValues(string(eventType)).Inc()
		return nil
	}
	return &ErrAuditWriteFailed{EventType: eventType, Cause: writeErr}
}
