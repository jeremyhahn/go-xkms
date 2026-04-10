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

package custodian

import "context"

// CustodianGroupStore defines the persistence interface for custodian groups.
type CustodianGroupStore interface {
	// Create persists a new custodian group. Returns ErrGroupAlreadyExists
	// if a group with the same ID already exists.
	Create(ctx context.Context, group *CustodianGroup) error

	// Get retrieves a custodian group by ID. Returns ErrGroupNotFound
	// if the group does not exist.
	Get(ctx context.Context, id string) (*CustodianGroup, error)

	// Update replaces an existing custodian group. Returns ErrGroupNotFound
	// if the group does not exist.
	Update(ctx context.Context, group *CustodianGroup) error

	// Delete removes a custodian group by ID. Returns ErrGroupNotFound
	// if the group does not exist.
	Delete(ctx context.Context, id string) error

	// List returns all custodian groups.
	List(ctx context.Context) ([]*CustodianGroup, error)

	// ListByTenant returns custodian groups scoped to a specific tenant.
	// An empty tenantID matches system-level groups.
	ListByTenant(ctx context.Context, tenantID string) ([]*CustodianGroup, error)

	// ListByPurpose returns custodian groups filtered by purpose.
	ListByPurpose(ctx context.Context, purpose string) ([]*CustodianGroup, error)
}
