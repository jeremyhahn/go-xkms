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

package seal

import (
	"context"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
)

// AuditLoggerFromXKMS exposes the node audit sink as the barrier's qrdb
// AuditLogger. The barrier speaks qrdbsdk.AuditEvent; the adapter lifts it
// onto the product audit.Event and emits it on the sink. Returns nil if sink
// is nil, which disables audit logging.
func AuditLoggerFromXKMS(sink qrdbsdk.NodeAuditLogger) qrdbsdk.AuditLogger {
	if sink == nil {
		return nil
	}
	return &auditLoggerAdapter{inner: sink}
}

type auditLoggerAdapter struct {
	inner qrdbsdk.NodeAuditLogger
}

func (a *auditLoggerAdapter) Log(ctx context.Context, event *qrdbsdk.AuditEvent) error {
	return audit.Emit(ctx, a.inner, &audit.Event{
		Timestamp:  event.Timestamp,
		Subject:    event.Subject,
		Action:     event.Action,
		Resource:   event.Resource,
		ResourceID: event.ResourceID,
		Outcome:    event.Outcome,
		Details:    event.Details,
	})
}

// Close is a no-op: the adapter does not own the sink, whose lifecycle
// belongs to the node that created it.
func (a *auditLoggerAdapter) Close() error {
	return nil
}

// emitAudit is the PlatformSealer audit helper. If the audit write fails,
// emitAudit returns *qrdbsdk.AuditGateError so the caller fails the
// seal/unseal request rather than complete a security-relevant operation that
// could not be audited (docs/audit-log/engineering.md). A nil sink disables
// audit logging entirely (opt-in wiring) and is not itself a failure.
func emitAudit(sink qrdbsdk.NodeAuditLogger, action, resource, resourceID, outcome string, details map[string]string) error {
	return audit.Emit(context.Background(), sink, &audit.Event{
		Timestamp:  time.Now(),
		Subject:    "seal",
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Outcome:    outcome,
		Details:    details,
	})
}
