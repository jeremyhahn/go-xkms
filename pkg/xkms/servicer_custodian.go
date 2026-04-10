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
	"github.com/jeremyhahn/go-xkms/pkg/custodian"
)

// CustodianGroupServicer defines operations for managing custodian groups
// used in Shamir secret sharing and key ceremony workflows.
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
func (s *XKMSService) CreateCustodianGroup(ctx context.Context, req *transport.CreateCustodianGroupRequest) (*transport.CreateCustodianGroupResponse, error) {
	if s.custodianService == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	group, err := s.custodianService.CreateGroup(
		ctx, req.ID, req.TenantID, req.Name, req.Purpose, req.Threshold, req.Total,
	)
	if err != nil {
		return nil, err
	}
	return &transport.CreateCustodianGroupResponse{
		Group: custodianGroupToInfo(group),
	}, nil
}

// GetCustodianGroup retrieves a custodian group by its ID.
func (s *XKMSService) GetCustodianGroup(ctx context.Context, groupID string) (*transport.GetCustodianGroupResponse, error) {
	if s.custodianService == nil {
		return nil, ErrNotConfigured
	}
	group, err := s.custodianService.GetGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	return &transport.GetCustodianGroupResponse{
		Group: custodianGroupToInfo(group),
	}, nil
}

// ListCustodianGroups returns all registered custodian groups.
func (s *XKMSService) ListCustodianGroups(ctx context.Context) (*transport.ListCustodianGroupsResponse, error) {
	if s.custodianService == nil {
		return nil, ErrNotConfigured
	}
	groups, err := s.custodianService.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	infos := make([]transport.CustodianGroupInfo, 0, len(groups))
	for _, g := range groups {
		infos = append(infos, custodianGroupToInfo(g))
	}
	return &transport.ListCustodianGroupsResponse{
		Groups: infos,
	}, nil
}

// DeleteCustodianGroup deletes a custodian group by its ID.
func (s *XKMSService) DeleteCustodianGroup(ctx context.Context, groupID string) error {
	if s.custodianService == nil {
		return ErrNotConfigured
	}
	return s.custodianService.DeleteGroup(ctx, groupID)
}

// AddCustodianMember adds a member to a custodian group.
func (s *XKMSService) AddCustodianMember(ctx context.Context, req *transport.AddCustodianMemberRequest) (*transport.AddCustodianMemberResponse, error) {
	if s.custodianService == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	member, err := s.custodianService.AddMember(
		ctx, req.GroupID, req.UserID, req.Username, req.Method,
	)
	if err != nil {
		return nil, err
	}
	return &transport.AddCustodianMemberResponse{
		Member: custodianMemberToInfo(member),
	}, nil
}

// RemoveCustodianMember removes a member from a custodian group.
func (s *XKMSService) RemoveCustodianMember(ctx context.Context, req *transport.RemoveCustodianMemberRequest) error {
	if s.custodianService == nil {
		return ErrNotConfigured
	}
	if req == nil {
		return ErrNilRequest
	}
	return s.custodianService.RemoveMember(ctx, req.GroupID, req.UserID)
}

// DistributeShares distributes Shamir shares to the members of a custodian group.
func (s *XKMSService) DistributeShares(ctx context.Context, req *transport.DistributeSharesRequest) (*transport.DistributeSharesResponse, error) {
	if s.custodianService == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	count, err := s.custodianService.DistributeShares(ctx, req.GroupID)
	if err != nil {
		return nil, err
	}
	return &transport.DistributeSharesResponse{
		Distributed: count,
	}, nil
}

// custodianGroupToInfo converts a custodian.CustodianGroup to a transport.CustodianGroupInfo.
func custodianGroupToInfo(g *custodian.CustodianGroup) transport.CustodianGroupInfo {
	members := make([]transport.CustodianMemberInfo, 0, len(g.Members))
	for i := range g.Members {
		members = append(members, custodianMemberToInfo(&g.Members[i]))
	}
	return transport.CustodianGroupInfo{
		ID:        g.ID,
		TenantID:  g.TenantID,
		Name:      g.Name,
		Purpose:   g.Purpose,
		Threshold: g.Threshold,
		Total:     g.Total,
		Members:   members,
		CreatedAt: g.CreatedAt,
		UpdatedAt: g.UpdatedAt,
	}
}

// custodianMemberToInfo converts a custodian.CustodianMember to a transport.CustodianMemberInfo.
func custodianMemberToInfo(m *custodian.CustodianMember) transport.CustodianMemberInfo {
	return transport.CustodianMemberInfo{
		ShareIndex: m.ShareIndex,
		UserID:     m.UserID,
		Username:   m.Username,
		AssignedAt: m.AssignedAt,
		ReceivedAt: m.ReceivedAt,
		Method:     m.Method,
	}
}
