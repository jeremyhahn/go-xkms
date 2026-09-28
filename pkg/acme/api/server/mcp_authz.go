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

package server

import (
	"context"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// MCPMethodPermissions maps every dispatchable ACME admin MCP method to the
// canonical go-qrdb grant its caller must hold. Each pair is identical to the
// one the equivalent REST route and gRPC method request, so an operator who
// revokes a grant revokes it on every transport at once.
//
// A method that is dispatchable but absent from this table is denied: see
// authorizeMCPMethod. The /mcp endpoint previously carried no authentication
// and no authorization at all, so every operation below — including
// admin.deleteTenant, admin.revokeCertificate, admin.createEAB, and the whole
// role/user administration surface — was reachable by any unauthenticated
// caller that could open a TCP connection to the admin listener.
var MCPMethodPermissions = map[string]Permission{
	// Server status.
	"admin.getStatus": {auth.ResourceAdmin, auth.ActionStatus},
	"admin.getStats":  {auth.ResourceAdmin, auth.ActionStatus},

	// Certificates.
	"admin.listCertificates":  {auth.ResourceCerts, auth.ActionList},
	"admin.getCertificate":    {auth.ResourceCerts, auth.ActionRead},
	"admin.revokeCertificate": {auth.ResourceCerts, auth.ActionRevoke},

	// ACME accounts.
	"admin.listAccounts":   {auth.ResourceACMEAccounts, auth.ActionList},
	"admin.getAccount":     {auth.ResourceACMEAccounts, auth.ActionRead},
	"admin.disableAccount": {auth.ResourceACMEAccounts, auth.ActionDisable},

	// Tenants.
	"admin.createTenant": {auth.ResourceTenants, auth.ActionCreate},
	"admin.getTenant":    {auth.ResourceTenants, auth.ActionRead},
	"admin.updateTenant": {auth.ResourceTenants, auth.ActionUpdate},
	"admin.deleteTenant": {auth.ResourceTenants, auth.ActionDelete},
	"admin.listTenants":  {auth.ResourceTenants, auth.ActionList},

	// External Account Bindings.
	"admin.createEAB": {auth.ResourceACMEEAB, auth.ActionCreate},
	"admin.getEAB":    {auth.ResourceACMEEAB, auth.ActionRead},
	"admin.deleteEAB": {auth.ResourceACMEEAB, auth.ActionDelete},
	"admin.listEABs":  {auth.ResourceACMEEAB, auth.ActionList},

	// Role management.
	"admin.createRole": {auth.ResourceRoles, auth.ActionCreate},
	"admin.getRole":    {auth.ResourceRoles, auth.ActionRead},
	"admin.updateRole": {auth.ResourceRoles, auth.ActionUpdate},
	"admin.deleteRole": {auth.ResourceRoles, auth.ActionDelete},
	"admin.listRoles":  {auth.ResourceRoles, auth.ActionList},

	// User management.
	"admin.createUser": {auth.ResourceUsers, auth.ActionCreate},
	"admin.getUser":    {auth.ResourceUsers, auth.ActionRead},
	"admin.updateUser": {auth.ResourceUsers, auth.ActionUpdate},
	"admin.deleteUser": {auth.ResourceUsers, auth.ActionDelete},
	"admin.listUsers":  {auth.ResourceUsers, auth.ActionList},
}

// authorizeMCPMethod gates an ACME admin JSON-RPC method against the
// qrdb-backed PermissionGate.
//
// An unknown method (one with no handler) is allowed through so the dispatcher
// can answer "method not found" — it reaches no service code. A dispatchable
// method with no permission mapping is a registration bug and is denied.
func (s *MultiProtocolServer) authorizeMCPMethod(ctx context.Context, method string) error {
	perm, mapped := MCPMethodPermissions[method]
	if !mapped {
		if _, dispatchable := s.mcpHandlers[method]; !dispatchable {
			return nil
		}
		s.logger.ErrorContext(ctx, "ACME admin MCP method has no permission mapping; denying",
			slog.String("method", method))
		return admin.ErrOperationUnmapped
	}

	return s.gate.Authorize(ctx, perm.Resource, perm.Action, slog.String("method", method))
}
