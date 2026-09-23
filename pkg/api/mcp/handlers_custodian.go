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

package mcp

import (
	"context"
	"encoding/json"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// custodianSuccess is the uniform success envelope for a custodian mutation
// that returns no other payload.
var custodianSuccess = map[string]interface{}{"success": true}

// CustodianGroupIDParams selects a custodian group by ID. Custodian group
// state is owned by the embedded go-qrdb node; a group ID is unique across
// the node, so no tenant or backend qualifier is carried here, matching
// xkms.getShare's ShareCoordinatesParams sibling.
type CustodianGroupIDParams struct {
	GroupID string `json:"group_id"`
}

// groupID decodes and validates a CustodianGroupIDParams from req.
func groupID(req *JSONRPCRequest) (string, error) {
	var params CustodianGroupIDParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return "", &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	}
	if params.GroupID == "" {
		return "", &errs.Message{Msg: "group_id is required"}
	}
	return params.GroupID, nil
}

// handleCreateCustodianGroup handles the xkms.createCustodianGroup method:
// registers a new custodian group with an M-of-N Shamir threshold. Delegates
// entirely to the xkms service layer (XKMSService.CreateCustodianGroup),
// which passes through to the embedded go-qrdb node's custodian client.
func (s *Server) handleCreateCustodianGroup(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.CreateCustodianGroupRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	}

	resp, err := s.xkmsService.CreateCustodianGroup(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return resp, nil
}

// handleGetCustodianGroup handles the xkms.getCustodianGroup method:
// retrieves a single custodian group by ID.
func (s *Server) handleGetCustodianGroup(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	id, err := groupID(req)
	if err != nil {
		return nil, err
	}

	resp, err := s.xkmsService.GetCustodianGroup(ctx, id)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return resp, nil
}

// handleListCustodianGroups handles the xkms.listCustodianGroups method:
// returns every custodian group. Takes no params.
func (s *Server) handleListCustodianGroups(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	resp, err := s.xkmsService.ListCustodianGroups(ctx)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return resp, nil
}

// handleDeleteCustodianGroup handles the xkms.deleteCustodianGroup method:
// removes a custodian group by ID.
func (s *Server) handleDeleteCustodianGroup(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	id, err := groupID(req)
	if err != nil {
		return nil, err
	}

	if err := s.xkmsService.DeleteCustodianGroup(ctx, id); err != nil {
		return nil, mapKeyOpError(err)
	}

	return custodianSuccess, nil
}

// handleAddCustodianMember handles the xkms.addCustodianMember method: adds
// a member to an existing custodian group.
func (s *Server) handleAddCustodianMember(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.AddCustodianMemberRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	}

	resp, err := s.xkmsService.AddCustodianMember(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return resp, nil
}

// handleRemoveCustodianMember handles the xkms.removeCustodianMember
// method: removes a member from a custodian group.
func (s *Server) handleRemoveCustodianMember(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.RemoveCustodianMemberRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	}

	if err := s.xkmsService.RemoveCustodianMember(ctx, &params); err != nil {
		return nil, mapKeyOpError(err)
	}

	return custodianSuccess, nil
}

// handleDistributeShares handles the xkms.distributeShares method: triggers
// distribution of a custodian group's Shamir shares to its enrolled members.
func (s *Server) handleDistributeShares(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.DistributeSharesRequest
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: err}
	}

	resp, err := s.xkmsService.DistributeShares(ctx, &params)
	if err != nil {
		return nil, mapKeyOpError(err)
	}

	return resp, nil
}
