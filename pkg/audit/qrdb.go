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

package audit

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/auth"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// QRDBLogger routes xkms audit events to the hosted qrdb node's HMAC-chained
// audit subsystem. It is the single production audit sink: it adapts xkms's
// transport-facing Event DTO onto the qrdb AuditEvent and emits it through the
// node's AuditClient (Client().Audit()), which appends it to the tamper-evident
// chain owned by the node.
//
// Log's returned error is not discarded: every xkms emit site runs it
// through HandleWriteFailure (severity.go), which fails the request for a
// SeveritySecurity action (e.g. "authorize", "seal", "unseal") and logs and
// counts the failure for a SeverityInformational one. See
// docs/audit-log/engineering.md.
type QRDBLogger struct {
	client qrdbtransport.AuditClient
}

// NewQRDBLogger returns a Logger that emits to the qrdb node's audit subsystem
// through the supplied AuditClient (typically Client().Audit()).
func NewQRDBLogger(client qrdbtransport.AuditClient) *QRDBLogger {
	return &QRDBLogger{client: client}
}

// Log converts the xkms Event to a qrdb AuditEvent and emits it through the
// node's audit subsystem. The actor, action, resource, and outcome map
// directly; ResourceID and all Details entries are carried in Attributes so no
// detail is lost in the chain. The remote address and role are lifted into the
// dedicated ClientIP/Role fields when present, and the tenant id is resolved
// from the authenticated identity on the context so per-tenant queries work.
func (l *QRDBLogger) Log(ctx context.Context, event *Event) error {
	if event == nil {
		return ErrNilEvent
	}
	return l.client.EmitAudit(ctx, toTransportEvent(ctx, event))
}

// toTransportEvent maps an xkms audit Event onto the canonical qrdb audit
// record: actor/action/resource/outcome map directly, ResourceID and every
// Details entry ride Attributes so no detail is lost in the chain, the
// remote address and role lift into their dedicated fields, and the tenant
// resolves from the authenticated identity on the context. Shared by every
// sink so the record shape cannot drift between the qrdb-hosted chain and
// the local chained file.
func toTransportEvent(ctx context.Context, event *Event) qrdbtransport.AuditEvent {
	attributes := make(map[string]any, len(event.Details)+1)
	for k, v := range event.Details {
		attributes[k] = v
	}
	if event.ResourceID != "" {
		attributes["resource_id"] = event.ResourceID
	}

	ev := qrdbtransport.AuditEvent{
		Timestamp:  event.Timestamp,
		Actor:      event.Subject,
		Action:     event.Action,
		Resource:   event.Resource,
		Outcome:    event.Outcome,
		Attributes: attributes,
		ClientIP:   event.Details["remote_addr"],
		Role:       event.Details["role"],
	}
	if id := auth.GetIdentity(ctx); id != nil {
		ev.TenantID = id.TenantID
	}
	return ev
}

// Close is a no-op: QRDBLogger does not own the AuditClient lifecycle. The
// underlying node sink is closed by the server when it tears down the node.
func (l *QRDBLogger) Close() error {
	return nil
}

// Compile-time interface compliance check.
var _ Logger = (*QRDBLogger)(nil)
