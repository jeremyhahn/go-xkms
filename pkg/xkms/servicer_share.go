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
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
)

// ShareServicer defines operations for submitting and managing Shamir shares.
type ShareServicer interface {
	SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error)
	ListShares(ctx context.Context) (*transport.ListSharesResponse, error)
	GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error)
}

// SubmitShare submits a Shamir share for collection.
func (s *XKMSService) SubmitShare(ctx context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	if s.shareStore == nil {
		return nil, ErrNotConfigured
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	entry := &sharestore.ShareEntry{
		ServerURL:  req.ServerURL,
		GroupID:    req.GroupID,
		GroupName:  req.GroupName,
		ShareIndex: req.ShareIndex,
		ShareData:  req.ShareData,
		Purpose:    req.Purpose,
		ReceivedAt: time.Now().UTC(),
		TenantID:   req.TenantID,
	}
	if err := s.shareStore.Save(ctx, entry); err != nil {
		return nil, err
	}
	return &transport.SubmitShareResponse{
		Accepted: true,
	}, nil
}

// ListShares returns all locally stored shares.
func (s *XKMSService) ListShares(ctx context.Context) (*transport.ListSharesResponse, error) {
	if s.shareStore == nil {
		return nil, ErrNotConfigured
	}
	entries, err := s.shareStore.List(ctx)
	if err != nil {
		return nil, err
	}
	shares := make([]transport.ShareInfo, 0, len(entries))
	for _, e := range entries {
		shares = append(shares, shareEntryToInfo(e))
	}
	return &transport.ListSharesResponse{
		Shares: shares,
	}, nil
}

// GetShareCollectionStatus returns the share collection status for a custodian group.
// It counts shares matching the given group ID and reports threshold progress
// using the custodian service when available.
func (s *XKMSService) GetShareCollectionStatus(ctx context.Context, groupID string) (*transport.ShareCollectionStatus, error) {
	if s.shareStore == nil {
		return nil, ErrNotConfigured
	}
	entries, err := s.shareStore.List(ctx)
	if err != nil {
		return nil, err
	}

	// Count shares belonging to this group.
	collected := 0
	for _, e := range entries {
		if e.GroupID == groupID {
			collected++
		}
	}

	// Retrieve threshold from the custodian group if the service is available.
	threshold := 0
	total := 0
	if s.custodianService != nil {
		group, groupErr := s.custodianService.GetGroup(ctx, groupID)
		if groupErr == nil {
			threshold = group.Threshold
			total = group.Total
		}
	}

	return &transport.ShareCollectionStatus{
		GroupID:   groupID,
		Threshold: threshold,
		Total:     total,
		Collected: collected,
		Ready:     threshold > 0 && collected >= threshold,
	}, nil
}

// shareEntryToInfo converts a sharestore.ShareEntry to a transport.ShareInfo.
func shareEntryToInfo(e *sharestore.ShareEntry) transport.ShareInfo {
	return transport.ShareInfo{
		ServerURL:  e.ServerURL,
		GroupID:    e.GroupID,
		GroupName:  e.GroupName,
		ShareIndex: e.ShareIndex,
		ShareData:  e.ShareData,
		Purpose:    e.Purpose,
		ReceivedAt: e.ReceivedAt,
		TenantID:   e.TenantID,
	}
}
