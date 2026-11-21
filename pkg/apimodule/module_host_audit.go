package apimodule

import (
	"context"
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// errHostAuditQuery reports Query on the module's host audit sink: the
// service only records decisions; the trail is read through the node.
var errHostAuditQuery = errors.New("apimodule: the host audit sink records only; query the node's audit plane")

// clientAuditSink records the self-built service's decisions on the host
// node's audit plane (the qrdb client's AuditClient). The write runs under
// the CALLER's context, never the host's service context
// (WithServiceContext): the node stamps an emitted event with the tenant of
// the context it is emitted under, and emitting needs no RBAC permission, so
// the caller's own context is what keeps a tenant's decisions in that
// tenant's trail rather than the system tenant's.
type clientAuditSink struct {
	audit qrdbtransport.AuditClient
}

var _ qrdbsdk.NodeAuditLogger = (*clientAuditSink)(nil)

// hostAuditSink is the sink the module installs over the host node's audit
// client. A node built without an audit logger exposes none (Client.Audit
// returns nil); the sink is then the nil interface, the service's
// documented auditing-off posture, not an adapter around a nil client.
func hostAuditSink(ac qrdbtransport.AuditClient) qrdbsdk.NodeAuditLogger {
	if ac == nil {
		return nil
	}
	return &clientAuditSink{audit: ac}
}

// Emit writes ev to the node's audit plane and returns its failure, which
// the service's audit seam turns into an AuditGateError (fail closed).
func (c *clientAuditSink) Emit(ctx context.Context, ev qrdbsdk.NodeAuditEvent) error {
	return c.audit.EmitAudit(ctx, qrdbtransport.AuditEvent(ev))
}

// Query is not served here; see errHostAuditQuery.
func (c *clientAuditSink) Query(context.Context, qrdbsdk.NodeAuditFilter) (*qrdbsdk.NodeAuditPage, error) {
	return nil, errHostAuditQuery
}

// Close releases nothing: the node owns its audit plane.
func (c *clientAuditSink) Close() error { return nil }
