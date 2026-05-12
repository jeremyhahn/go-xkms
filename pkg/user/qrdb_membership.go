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

package user

import (
	"context"
	"errors"
	"fmt"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// QRDBMembership is the small set of qrdb-backed identity helpers xkms
// middleware needs for permission decisions. It is the deliberate, narrow
// successor of the deleted UserRBACAdapter:
//
//   - Identity (users, role memberships) lives in qrdb.
//   - Authorization for xkms-domain operations (keys/certs/secrets/...)
//     lives in xkms's keyrbac package.
//   - The middleware composes the two: lookup roles via qrdb, then ask
//     keyrbac whether those roles can perform the requested action on the
//     xkms-domain resource.
//
// QRDBMembership intentionally omits role-CRUD passthroughs that the old
// UserRBACAdapter exported. Role CRUD is qrdb's responsibility; consumers
// call qrdb's RoleClient directly when they need to manage role definitions.
type QRDBMembership struct {
	users qrdbtransport.UserClient
	roles qrdbtransport.RoleClient
}

// ErrQRDBMembershipUnconfigured is returned when QRDBMembership is constructed
// without the required qrdb clients.
var ErrQRDBMembershipUnconfigured = errors.New("user: qrdb membership requires both UserClient and RoleClient")

// NewQRDBMembership wires qrdb's user/role SDK surfaces into a single
// helper. Both clients are required; pass nil for either to deliberately
// disable the helper at construction time and surface the misconfiguration
// before the first request.
func NewQRDBMembership(users qrdbtransport.UserClient, roles qrdbtransport.RoleClient) (*QRDBMembership, error) {
	if users == nil || roles == nil {
		return nil, ErrQRDBMembershipUnconfigured
	}
	return &QRDBMembership{users: users, roles: roles}, nil
}

// LookupUserRoles returns the role names assigned to a (tenantID, username)
// pair. The returned slice is empty when the user has no roles. Errors from
// qrdb (e.g. user not found) are returned wrapped so callers can distinguish
// transient lookup failures from authorization denials.
//
// Each role-name resolution requires one GetRole call. Callers that drive
// authorization on the hot path should cache the result for the request
// scope rather than re-issuing the lookup per check.
func (m *QRDBMembership) LookupUserRoles(ctx context.Context, tenantID, username string) ([]string, error) {
	user, err := m.users.GetUserByUsername(ctx, tenantID, username)
	if err != nil {
		return nil, fmt.Errorf("user: lookup %q in tenant %q: %w", username, tenantID, err)
	}
	if !user.Enabled {
		return nil, nil
	}
	if len(user.RoleIDs) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(user.RoleIDs))
	for _, id := range user.RoleIDs {
		role, err := m.roles.GetRole(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("user: resolve role id %q: %w", id, err)
		}
		names = append(names, role.Name)
	}
	return names, nil
}

// AssignUserRole assigns the given role to the given user via qrdb's
// RoleClient. The IDs are qrdb-issued UUIDs; callers that have only a
// username should resolve the user first (e.g. via GetUserByUsername).
func (m *QRDBMembership) AssignUserRole(ctx context.Context, userID, roleID string) error {
	if userID == "" || roleID == "" {
		return fmt.Errorf("user: AssignUserRole requires both userID and roleID")
	}
	if err := m.roles.AssignRole(ctx, userID, roleID); err != nil {
		return fmt.Errorf("user: assign role %q to user %q: %w", roleID, userID, err)
	}
	return nil
}

// UnassignUserRole removes the given role from the given user. Callers
// that need atomic role-set updates should call qrdb's UpdateUser with
// the desired RoleIDs instead of pairing Assign/Unassign.
func (m *QRDBMembership) UnassignUserRole(ctx context.Context, userID, roleID string) error {
	if userID == "" || roleID == "" {
		return fmt.Errorf("user: UnassignUserRole requires both userID and roleID")
	}
	if err := m.roles.UnassignRole(ctx, userID, roleID); err != nil {
		return fmt.Errorf("user: unassign role %q from user %q: %w", roleID, userID, err)
	}
	return nil
}
