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

// AuditLoggerFromXKMS wraps an xkms audit.Logger as a qrdb AuditLogger.
// This bridges the event type difference between the two packages.
// Returns nil if logger is nil, which disables audit logging.
func AuditLoggerFromXKMS(logger audit.Logger) qrdbsdk.AuditLogger {
	if logger == nil {
		return nil
	}
	return &auditLoggerAdapter{inner: logger}
}

type auditLoggerAdapter struct {
	inner audit.Logger
}

func (a *auditLoggerAdapter) Log(ctx context.Context, event *qrdbsdk.AuditEvent) error {
	return a.inner.Log(ctx, &audit.Event{
		Timestamp:  event.Timestamp,
		Subject:    event.Subject,
		Action:     event.Action,
		Resource:   event.Resource,
		ResourceID: event.ResourceID,
		Outcome:    event.Outcome,
		Details:    event.Details,
	})
}

func (a *auditLoggerAdapter) Close() error {
	return a.inner.Close()
}

// emitAudit is a fire-and-forget helper for PlatformSealer audit events.
// It silently ignores nil loggers and logging errors.
func emitAudit(logger audit.Logger, action, resource, resourceID, outcome string, details map[string]string) {
	if logger == nil {
		return
	}
	_ = logger.Log(context.Background(), &audit.Event{
		Timestamp:  time.Now(),
		Subject:    "seal",
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Outcome:    outcome,
		Details:    details,
	})
}
