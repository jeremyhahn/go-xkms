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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Severity classifies an OperationType by how a failed write to the audit
// sink must be handled. See docs/audit-log/engineering.md for the policy
// this implements.
type Severity int

const (
	// SeverityInformational operations are audited best-effort: a failed
	// write is logged and counted but never fails the caller.
	SeverityInformational Severity = iota

	// SeveritySecurity operations must be provably audited: a failed
	// write fails the operation that triggered it rather than let a
	// security-relevant action proceed unaudited.
	SeveritySecurity
)

// informationalOps is the fixed set of OperationType values classified
// SeverityInformational: connection/pairing progress, service lifecycle,
// user-presence/touch telemetry, IPC dispatch, extension transport
// handshake, SecretService session bookkeeping, and configuration change.
// None of these gate access to a credential, key, or PIN. Every other
// OperationType — including every operation not yet defined — classifies
// SeveritySecurity by default (see Severity): fail-closed is the safe
// default for an operation nobody has explicitly reviewed and placed here.
var informationalOps = map[OperationType]bool{
	OpConnectionEstablished: true,
	OpConnectionClosed:      true,

	OpServiceStarted: true,
	OpServiceStopped: true,

	OpUserPresenceRequested: true,
	OpUserPresenceConfirmed: true,
	OpUserPresenceTimedOut:  true,
	OpUserPresenceCancelled: true,

	OpExtensionHandshake:    true,
	OpExtensionRelay:        true,
	OpExtensionDisconnected: true,

	OpPairingStarted:   true,
	OpPairingCompleted: true,
	OpPairingUnpaired:  true,
	OpPairingManifest:  true,

	OpIPCMessageDispatched: true,
	OpIPCMessageFailed:     true,

	OpSecretServiceSessionOpened: true,
	OpSecretServiceSessionClosed: true,
	OpSecretServiceSearch:        true,

	OpAutofillRequested: true,

	OpConfigUpdated: true,

	// gui/services.AutoFillService declares these OperationType values
	// locally (pkg/gui/services/autofill_service.go) rather than in this
	// package; they are mirrored here by value so ClassifyAction sees them.
	// A domain search does not reveal a stored secret, and the ignored-
	// domain list is a user preference, not a credential — both stay
	// informational. Credential/TOTP access, save, and CTAP2 authentication
	// are not listed here and so default to SeveritySecurity.
	OperationType("autofill_search"):        true,
	OperationType("autofill_ignore_domain"): true,
}

// Severity returns op's audit write-failure classification. An
// OperationType not listed in informationalOps — known or not — classifies
// SeveritySecurity.
func (op OperationType) Severity() Severity {
	if informationalOps[op] {
		return SeverityInformational
	}
	return SeveritySecurity
}

// ErrAuditWriteFailed is returned when a SeveritySecurity audit event fails
// to persist. Callers must fail the operation that produced the event
// rather than proceed with an unaudited security-relevant action.
type ErrAuditWriteFailed struct {
	Operation OperationType
	Cause     error
}

// Error implements the error interface.
func (e *ErrAuditWriteFailed) Error() string {
	return fmt.Sprintf("audit: security event %q failed to persist: %v", e.Operation, e.Cause)
}

// Unwrap returns the underlying write failure.
func (e *ErrAuditWriteFailed) Unwrap() error {
	return e.Cause
}

// handleWriteFailure applies the go-xkms audit write-failure policy to the
// error returned from a persistent write (xkms.StorageBackend.Put or the
// qrdb DAO's Save). writeErr must be that error (nil means the write
// succeeded, in which case handleWriteFailure is a no-op).
//
// For a SeveritySecurity operation, handleWriteFailure returns
// *ErrAuditWriteFailed; the caller must propagate it and fail the
// operation rather than complete a security-relevant action that could
// not be audited.
//
// For a SeverityInformational operation, handleWriteFailure logs the
// failure through slogger (a nil slogger is permitted and simply skips the
// log line), increments xkms.AuditWriteFailuresTotal (the same counter
// go-xkms's server-side audit package uses — xkey and xkmsd are separate
// processes, so sharing the metric definition is safe and avoids a second,
// drifting copy of the same Prometheus descriptor), and returns nil so the
// caller proceeds.
func handleWriteFailure(slogger *slog.Logger, op OperationType, writeErr error) error {
	if writeErr == nil {
		return nil
	}
	if op.Severity() == SeverityInformational {
		if slogger != nil {
			slogger.Error("audit: informational event failed to persist", "operation", string(op), "error", writeErr)
		}
		xkms.AuditWriteFailuresTotal.WithLabelValues(string(op)).Inc()
		return nil
	}
	return &ErrAuditWriteFailed{Operation: op, Cause: writeErr}
}
