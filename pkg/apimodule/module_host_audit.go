package apimodule

import (
	"context"
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// errHostAuditQuery reports Query on the module's host audit sink: the
// service only records decisions; the trail is read through the node.
var errHostAuditQuery = errors.New("apimodule: the host audit sink records only; query the node's audit plane")

// clientAuditSink records the self-built service's decisions on the host
// node's audit plane (the qrdb client's AuditClient), bound to the host's
// service context (WithServiceContext) so the write runs as the node's
// service principal, not as the caller being refused.
type clientAuditSink struct {
	audit qrdbtransport.AuditClient
	bind  qrdbstorage.CallContext
}

var _ qrdbsdk.NodeAuditLogger = (*clientAuditSink)(nil)

// Emit writes ev to the node's audit plane and returns its failure, which
// the service's audit seam turns into an AuditGateError (fail closed).
func (c *clientAuditSink) Emit(ctx context.Context, ev qrdbsdk.NodeAuditEvent) error {
	if c.bind != nil {
		bound, err := c.bind(ctx)
		if err != nil {
			return err
		}
		ctx = bound
	}
	return c.audit.EmitAudit(ctx, qrdbtransport.AuditEvent(ev))
}

// Query is not served here; see errHostAuditQuery.
func (c *clientAuditSink) Query(context.Context, qrdbsdk.NodeAuditFilter) (*qrdbsdk.NodeAuditPage, error) {
	return nil, errHostAuditQuery
}

// Close releases nothing: the node owns its audit plane.
func (c *clientAuditSink) Close() error { return nil }
