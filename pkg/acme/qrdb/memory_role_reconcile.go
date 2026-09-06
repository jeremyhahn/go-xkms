// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package qrdb

import (
	"context"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/qrdbrole"
)

// ReconcileBuiltInRoles converges this client's stored built-in roles onto the
// definitions the linked go-qrdb build publishes, adding the permissions it now
// grants and removing the ones it no longer does. Custom roles are untouched
// and a converged tenant performs zero writes.
//
// The convergence itself lives in pkg/qrdbrole so every in-memory RoleClient in
// this repository answers the verb identically.
func (c *memoryRoleClient) ReconcileBuiltInRoles(ctx context.Context, req *db.ReconcileRolesRequest) (*db.ReconcileRolesResponse, error) {
	return qrdbrole.Reconcile(ctx, c, req)
}
