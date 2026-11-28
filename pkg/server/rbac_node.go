package server

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// nodeRBAC is the SDK RBAC client with its decisions made by the node's own
// authorizer on the full identity the decision context carries, so a
// delegated caller's ScopePermissions count; the SDK projection drops them.
type nodeRBAC struct {
	qrdbtransport.RBACClient
	node qrdbsdk.Authorizer
}

// Authorize decides on the identity auth.Authorizer bound into ctx.
func (r nodeRBAC) Authorize(ctx context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	identity := auth.GetIdentity(ctx)
	if identity == nil {
		return auth.ErrUnauthenticated
	}
	return r.node.Authorize(ctx, identity, resource, action)
}

// newNodeAuthorizer returns the server's authorizer: rbac lists permissions
// and sets the posture (nil disables authorization), and node, when set,
// makes every decision on the caller's full identity.
func newNodeAuthorizer(rbac qrdbtransport.RBACClient, node qrdbsdk.Authorizer) *auth.Authorizer {
	if rbac == nil || node == nil {
		return auth.NewAuthorizer(rbac)
	}
	return auth.NewAuthorizer(nodeRBAC{RBACClient: rbac, node: node})
}
