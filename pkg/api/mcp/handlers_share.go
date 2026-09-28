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

package mcp

import (
	"context"
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ShareCoordinatesParams addresses a single stored share. The triple
// (server_url, group_id, share_index) is the share's identity.
type ShareCoordinatesParams struct {
	ServerURL  string `json:"server_url"`
	GroupID    string `json:"group_id"`
	ShareIndex int    `json:"share_index"`
}

// GetShareCollectionStatusParams selects the custodian group whose share
// collection progress to report.
type GetShareCollectionStatusParams struct {
	GroupID string `json:"group_id"`
}

// shareSentinelCodes maps the share domain's errors onto JSON-RPC error
// codes. Share state is owned by the embedded go-qrdb node and reached here
// through XKMSService's ShareServicer (pkg/xkms/servicer_share.go), which
// passes every call through unchanged to the node's share client -- the same
// client pkg/api/grpc/service_custodian_share_tenant.go's shareErrorToGRPC
// classifies. This table carries the identical classification:
// qrdbsdk.ErrCeremonyShareNotFound is Not found, matching gRPC's
// codes.NotFound.
//
// xkms.ErrNotConfigured is only observable on this transport: gRPC's five
// share RPCs never call through the xkms service layer at all -- they use
// the package-level shareClient set by SetShareClient directly -- so
// XKMSService.shares being nil has no gRPC equivalent to mirror. It is
// classified Service unavailable, the same floor this package uses
// everywhere else for an unwired subsystem (errors_cert.go's mapCAError,
// handlers_init_credentials.go's ceremonySentinelCodes and
// credentialSentinelCodes).
var shareSentinelCodes = []struct {
	sentinel error
	code     int
}{
	{qrdbsdk.ErrCeremonyShareNotFound, sdkssh.JSONRPCCodeNotFound},
	{xkms.ErrNotConfigured, ErrCodeServiceUnavailable},
}

// mapShareError converts an error returned by XKMSService's ShareServicer
// into a *KeyOpError carrying the JSON-RPC code shareSentinelCodes names for
// it. Anything not in that table is an internal fault.
func mapShareError(err error, operation string) error {
	if err == nil {
		return nil
	}
	for _, entry := range shareSentinelCodes {
		if errors.Is(err, entry.sentinel) {
			return classified(entry.code, &errs.Wrapped{Msg: operation, Err: err})
		}
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: &errs.Wrapped{Msg: operation, Err: err}}
}

// handleSubmitShare handles the xkms.submitShare method.
func (s *Server) handleSubmitShare(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params transport.SubmitShareRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.GroupID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "group_id is required"}}
	}
	if len(params.ShareData) == 0 {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "share_data is required"}}
	}

	resp, err := s.xkmsService.SubmitShare(ctx, &params)
	if err != nil {
		return nil, mapShareError(err, "failed to submit share")
	}

	return resp, nil
}

// handleListShares handles the xkms.listShares method. Sensitive share
// material is stripped from every entry before it leaves the server.
func (s *Server) handleListShares(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	resp, err := s.xkmsService.ListShares(ctx)
	if err != nil {
		return nil, mapShareError(err, "failed to list shares")
	}

	shares := make([]transport.ShareInfo, len(resp.Shares))
	for i := range resp.Shares {
		shares[i] = withoutShareData(resp.Shares[i])
	}

	return transport.ListSharesResponse{Shares: shares}, nil
}

// handleGetShare handles the xkms.getShare method. Sensitive share material
// is stripped before the result leaves the server.
func (s *Server) handleGetShare(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	params, err := shareCoordinates(req)
	if err != nil {
		return nil, err
	}

	info, err := s.xkmsService.GetShare(ctx, params.ServerURL, params.GroupID, params.ShareIndex)
	if err != nil {
		return nil, mapShareError(err, "failed to get share")
	}

	return withoutShareData(*info), nil
}

// handleDeleteShare handles the xkms.deleteShare method.
func (s *Server) handleDeleteShare(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	params, err := shareCoordinates(req)
	if err != nil {
		return nil, err
	}

	if err := s.xkmsService.DeleteShare(ctx, params.ServerURL, params.GroupID, params.ShareIndex); err != nil {
		return nil, mapShareError(err, "failed to delete share")
	}

	return struct{}{}, nil
}

// handleGetShareCollectionStatus handles the xkms.getShareCollectionStatus
// method.
func (s *Server) handleGetShareCollectionStatus(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	var params GetShareCollectionStatusParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.GroupID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "group_id is required"}}
	}

	status, err := s.xkmsService.GetShareCollectionStatus(ctx, params.GroupID)
	if err != nil {
		return nil, mapShareError(err, "failed to get share collection status")
	}

	return status, nil
}

// shareCoordinates decodes and validates the triple that addresses a single
// share.
func shareCoordinates(req *JSONRPCRequest) (*ShareCoordinatesParams, error) {
	var params ShareCoordinatesParams
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}

	if params.ServerURL == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "server_url is required"}}
	}
	if params.GroupID == "" {
		return nil, &KeyOpError{Code: ErrCodeInvalidParams, Err: &errs.Message{Msg: "group_id is required"}}
	}

	return &params, nil
}

// withoutShareData returns a copy of info with the sensitive share material
// cleared. Share bytes are write-only over the API: they go in through
// submit and are only ever read by the barrier's unseal quorum.
func withoutShareData(info transport.ShareInfo) transport.ShareInfo {
	info.ShareData = nil
	return info
}
