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
Package audit carries go-xkms's product audit events onto go-qrdb's audit
logger.

xkms owns no audit sink, no logger interface and no severity taxonomy: the
sink is a qrdbsdk.NodeAuditLogger (the node's own, or a file chain from
qrdbsdk.NewAuditFileLogger when no node is hosted), and storage, chaining and
query live in go-qrdb. This package holds only Event, the product operation
record, and Emit, which maps it onto the canonical qrdb record (actor, tenant,
role, client address, attributes) and writes it.

# Usage

	err := audit.Emit(ctx, s.auditLogger, &audit.Event{
	    Subject:  identity.Subject,
	    Action:   "unseal",
	    Resource: "barrier",
	    Outcome:  audit.OutcomeAllow,
	    Details:  map[string]string{"transport": "grpc"},
	})
	if err != nil {
	    return err
	}

# Write failure

Emit never discards a failed write. The error is a *qrdbsdk.AuditGateError
(Component = the event's Action) wrapping the sink's *NodeAuditWriteError; the
caller fails the operation that produced the event rather than let it
complete unaudited. A nil sink means audit is not wired and is not a failure.

See docs/audit-log/engineering.md.
*/
package audit
