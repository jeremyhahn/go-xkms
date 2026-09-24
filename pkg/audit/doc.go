// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

/*
Package audit defines the xkms audit emission seam and routes events to the
hosted go-qrdb node's HMAC-chained audit subsystem.

# Architecture

xkms owns no audit storage of its own. It defines a minimal emission interface
and adapts it onto the canonical qrdb audit chain:

 1. Logger — the emission contract used by every xkms transport (REST, gRPC,
    QUIC) and the seal subsystem: Log(ctx, *Event) error plus Close() error.
 2. Event — the transport-facing audit DTO (subject, action, resource,
    resourceID, outcome, details).
 3. QRDBLogger — the production Logger. It maps Event onto the qrdb transport
    AuditEvent and emits through the node's AuditClient
    (Client().Audit().EmitAudit), which appends it to the tamper-evident,
    HMAC-chained log owned by the qrdb node. The tenant id is resolved from the
    authenticated identity on the context so per-tenant audit queries work.
 4. NoOpLogger — discards events; used only when no qrdb client is present.

The audit STORAGE (file persistence, in-memory query model, severity/type
taxonomy) lives in go-qrdb's pkg/audit and is reached exclusively through the
SDK. xkms supplies the node's audit sink at node construction via
sdk.WithAuditLogger and queries it through Client().Audit().QueryAudit.

# Usage

The server selects the Logger after the qrdb node is up:

	if s.qrdbClient != nil {
	    s.auditLogger = audit.NewQRDBLogger(s.qrdbClient.Audit())
	} else {
	    s.auditLogger = &audit.NoOpLogger{}
	}

# Write-failure policy

Log's returned error is never discarded. ClassifyAction (severity.go)
classifies every Event.Action as SeveritySecurity or SeverityInformational;
HandleWriteFailure applies the resulting policy to the error Log returned:

  - SeveritySecurity (e.g. "authorize", "seal", "unseal"): a failed write
    returns *ErrAuditWriteFailed, which the caller must propagate and use to
    fail the request. A security-relevant action must not complete
    unaudited.
  - SeverityInformational: a failed write is logged via slog and counted in
    metrics.AuditWriteFailuresTotal; HandleWriteFailure returns nil so the
    caller proceeds.

Transports call HandleWriteFailure around every Log:

	if auditErr := audit.HandleWriteFailure(logger, "unseal", s.auditLogger.Log(ctx, &audit.Event{
	    Subject:  identity.Subject,
	    Action:   "unseal",
	    Resource: "barrier",
	    Outcome:  audit.OutcomeAllow,
	    Details:  map[string]string{"transport": "grpc"},
	})); auditErr != nil {
	    return auditErr
	}

See docs/audit-log/engineering.md for the full policy and classification
table.
*/
package audit
