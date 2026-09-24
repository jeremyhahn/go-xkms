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

// Severity classifies an Event's Action by how a failed write to the audit
// sink must be handled. See docs/audit-log/engineering.md for the policy
// this implements.
type Severity int

const (
	// SeverityInformational actions are audited best-effort: a failed write
	// is logged and counted but never fails the request that produced it.
	SeverityInformational Severity = iota

	// SeveritySecurity actions must be provably audited: a failed write
	// fails the request that produced it rather than let a security-
	// relevant action proceed unaudited.
	SeveritySecurity
)

// informationalActions is the fixed set of xkms Event.Action values
// classified SeverityInformational. An action must be explicitly listed
// here to receive best-effort treatment; ClassifyAction defaults every
// other action, known or not, to SeveritySecurity — fail-closed is the
// safe default for an action nobody has explicitly reviewed and
// classified informational. Every action this package currently emits
// ("authorize", "seal", "unseal") is authentication/authorization or
// barrier seal/unseal, so this set is empty today; it exists so a future
// informational action has somewhere to be classified without touching
// ClassifyAction's default.
var informationalActions = map[string]bool{}

// ClassifyAction returns the Severity for an Event.Action. Unrecognized
// actions classify as SeveritySecurity: an audited action that nobody has
// explicitly reviewed and placed in informationalActions is treated as
// security-relevant rather than silently downgraded.
func ClassifyAction(action string) Severity {
	if informationalActions[action] {
		return SeverityInformational
	}
	return SeveritySecurity
}

// ErrAuditWriteFailed is returned when a SeveritySecurity audit event fails
// to persist. Callers must fail the operation that produced the event
// rather than proceed with an unaudited security-relevant action.
type ErrAuditWriteFailed struct {
	Action string
	Cause  error
}

// Error implements the error interface.
func (e *ErrAuditWriteFailed) Error() string {
	return fmt.Sprintf("audit: security event %q failed to persist: %v", e.Action, e.Cause)
}

// Unwrap returns the underlying write failure.
func (e *ErrAuditWriteFailed) Unwrap() error {
	return e.Cause
}

// HandleWriteFailure applies the go-xkms audit write-failure policy to the
// error returned from a Logger.Log call. writeErr must be the error Log
// itself returned (nil means the write succeeded, in which case
// HandleWriteFailure is a no-op).
//
// For a SeveritySecurity action, HandleWriteFailure returns
// *ErrAuditWriteFailed; the caller must propagate it and fail the request
// rather than complete a security-relevant action that could not be
// audited.
//
// For a SeverityInformational action, HandleWriteFailure logs the failure
// through slogger (a nil slogger is permitted and simply skips the log
// line), increments metrics.AuditWriteFailuresTotal, and returns nil so
// the caller proceeds.
func HandleWriteFailure(slogger *slog.Logger, action string, writeErr error) error {
	if writeErr == nil {
		return nil
	}
	if ClassifyAction(action) == SeverityInformational {
		if slogger != nil {
			slogger.Error("audit: informational event failed to persist", "action", action, "error", writeErr)
		}
		metrics.AuditWriteFailuresTotal.WithLabelValues(action).Inc()
		return nil
	}
	return &ErrAuditWriteFailed{Action: action, Cause: writeErr}
}
