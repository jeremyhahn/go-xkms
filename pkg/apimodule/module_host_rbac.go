package apimodule

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// hostRBAC is the host's SDK RBAC client with its decisions made by the
// host's target-aware authorizer (the AuthMiddleware its transports gate on),
// which reads the full identity auth.Authorizer binds into ctx.
type hostRBAC struct {
	qrdbtransport.RBACClient
	target qrdbsdk.TenantTargetAuthorizer
}

// Authorize decides resource:action in the identity's own tenant.
func (r hostRBAC) Authorize(ctx context.Context, identity *qrdbtransport.Identity, resource, action string) error {
	return r.target.AuthorizeTenantTarget(ctx, identity.TenantID, qrdbsdk.Permission(resource+":"+action))
}
