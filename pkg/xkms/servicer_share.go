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

// ShareServicer defines operations for submitting and managing Shamir shares.
// Share state is owned by the embedded go-qrdb node; the servicer passes calls
// through to the node's share client.
type ShareServicer interface {
	SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error)
	ListShares(ctx context.Context) (*transport.ListSharesResponse, error)
	GetShare(ctx context.Context, serverURL, groupID string, shareIndex int) (*transport.ShareInfo, error)
	DeleteShare(ctx context.Context, serverURL, groupID string, shareIndex int) error
	GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error)
}

// SubmitShare submits a Shamir share for collection. It passes the request
// through to the embedded go-qrdb node's share client.
func (s *XKMSService) SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	shares := s.shares.load()
	if shares == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	return shares.SubmitShare(ctx, req)
}

// ListShares returns all shares available to the authenticated caller. It
// passes the request through to the embedded go-qrdb node's share client.
func (s *XKMSService) ListShares(ctx context.Context) (*transport.ListSharesResponse, error) {
	shares := s.shares.load()
	if shares == nil {
		return nil, ErrNotConfigured
	}
	return shares.ListShares(ctx)
}

// GetShare retrieves a single submitted share identified by its server URL,
// group ID, and share index. It passes the request through to the embedded
// go-qrdb node's share client.
func (s *XKMSService) GetShare(ctx context.Context, serverURL, groupID string, shareIndex int) (*transport.ShareInfo, error) {
	shares := s.shares.load()
	if shares == nil {
		return nil, ErrNotConfigured
	}
	return shares.GetShare(ctx, serverURL, groupID, shareIndex)
}

// DeleteShare removes a single submitted share identified by its server URL,
// group ID, and share index. It passes the request through to the embedded
// go-qrdb node's share client.
func (s *XKMSService) DeleteShare(ctx context.Context, serverURL, groupID string, shareIndex int) error {
	shares := s.shares.load()
	if shares == nil {
		return ErrNotConfigured
	}
	return shares.DeleteShare(ctx, serverURL, groupID, shareIndex)
}

// GetShareCollectionStatus returns the share collection status for a custodian
// group. It passes the request through to the embedded go-qrdb node's share
// client, which reports threshold progress for the group.
func (s *XKMSService) GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error) {
	shares := s.shares.load()
	if shares == nil {
		return nil, ErrNotConfigured
	}
	return shares.GetShareCollectionStatus(ctx, groupID)
}
