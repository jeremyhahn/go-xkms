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

package xkms

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// CustodianGroupServicer defines operations for managing custodian groups
// used in Shamir secret sharing and key ceremony workflows. Custodian state
// is owned by the embedded go-qrdb node; xkms presents this API on top of the
// node's CustodianGroupClient and performs no local persistence.
type CustodianGroupServicer interface {
	CreateCustodianGroup(ctx context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error)
	GetCustodianGroup(ctx context.Context, groupID string) (*transport.GetCustodianGroupResponse, error)
	ListCustodianGroups(ctx context.Context) (*transport.ListCustodianGroupsResponse, error)
	DeleteCustodianGroup(ctx context.Context, groupID string) error
	AddCustodianMember(ctx context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error)
	RemoveCustodianMember(ctx context.Context, req *transport.RemoveCustodianMemberRequest) error
	DistributeShares(ctx context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error)
}

// CreateCustodianGroup creates a new custodian group with threshold parameters.
// The transport request/response types are aliases of the qrdb transport types,
// so the call is a direct pass-through to the node's custodian client.
func (s *XKMSService) CreateCustodianGroup(ctx context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	if s.custodians == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return s.custodians.CreateCustodianGroup(ctx, req)
}

// GetCustodianGroup retrieves a custodian group by its ID.
func (s *XKMSService) GetCustodianGroup(ctx context.Context, groupID string) (*transport.GetCustodianGroupResponse, error) {
	if s.custodians == nil {
		return nil, ErrNotConfigured
	}
	return s.custodians.GetCustodianGroup(ctx, groupID)
}

// ListCustodianGroups returns all registered custodian groups.
func (s *XKMSService) ListCustodianGroups(ctx context.Context) (*transport.ListCustodianGroupsResponse, error) {
	if s.custodians == nil {
		return nil, ErrNotConfigured
	}
	return s.custodians.ListCustodianGroups(ctx)
}

// DeleteCustodianGroup deletes a custodian group by its ID.
func (s *XKMSService) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	if s.custodians == nil {
		return ErrNotConfigured
	}
	return s.custodians.DeleteCustodianGroup(ctx, groupID)
}

// AddCustodianMember adds a member to a custodian group.
func (s *XKMSService) AddCustodianMember(ctx context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	if s.custodians == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return s.custodians.AddCustodianMember(ctx, req)
}

// RemoveCustodianMember removes a member from a custodian group.
func (s *XKMSService) RemoveCustodianMember(ctx context.Context, req *transport.RemoveCustodianMemberRequest) error {
	if s.custodians == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return s.custodians.RemoveCustodianMember(ctx, req)
}

// DistributeShares distributes Shamir shares to the members of a custodian group.
func (s *XKMSService) DistributeShares(ctx context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	if s.custodians == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return s.custodians.DistributeShares(ctx, req)
}
