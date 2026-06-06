// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package qrdb

import (
	"context"
	"sort"

	db "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// GetRoleByName retrieves a role by its tenant-scoped name. When the request
// carries a TenantID, only roles in that tenant are considered; otherwise the
// first role matching the name is returned. A nil request, or a name with no
// match, yields errRoleNotFound to mirror the other lookup methods.
func (c *memoryRoleClient) GetRoleByName(_ context.Context, req *db.GetRoleByNameRequest) (*db.Role, error) {
	if req == nil {
		return nil, errRoleNotFound
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, r := range c.roles {
		if r.Name != req.Name {
			continue
		}
		if req.TenantID != "" && r.TenantID != req.TenantID {
			continue
		}
		return r, nil
	}
	return nil, errRoleNotFound
}

// ResolvePermissions returns the sorted, deduplicated union of permissions
// granted by the requested role IDs. Unknown role IDs are skipped so callers
// receive the effective permission set of whatever roles currently exist.
func (c *memoryRoleClient) ResolvePermissions(_ context.Context, req *db.ResolvePermissionsRequest) (*db.ResolvePermissionsResponse, error) {
	seen := make(map[string]struct{})
	if req != nil {
		c.mu.RLock()
		for _, id := range req.RoleIDs {
			role, ok := c.roles[id]
			if !ok {
				continue
			}
			for _, p := range role.Permissions {
				seen[p] = struct{}{}
			}
		}
		c.mu.RUnlock()
	}
	perms := make([]string, 0, len(seen))
	for p := range seen {
		perms = append(perms, p)
	}
	sort.Strings(perms)
	return &db.ResolvePermissionsResponse{Permissions: perms}, nil
}
