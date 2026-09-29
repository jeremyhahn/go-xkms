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

package services

import (
	"context"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unreachableShareServer is a loopback address nothing listens on. Dialing
// it fails immediately with "connection refused" so these tests exercise
// the SDK-client error paths without any real network dependency.
const unreachableShareServer = "https://127.0.0.1:1"

// ---------------------------------------------------------------------------
// ReceiveShares
// ---------------------------------------------------------------------------

func TestShareService_ReceiveShares_EmptyServerURL(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(xkms.NewMemoryShareStore())

	shares, err := svc.ReceiveShares("", "")
	require.ErrorIs(t, err, ErrEmptyServerURL)
	assert.Nil(t, shares)
}

func TestShareService_ReceiveShares_NilStore(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())

	shares, err := svc.ReceiveShares("https://xkms.example.com", "")
	require.ErrorIs(t, err, ErrShareStoreNil)
	assert.Nil(t, shares)
}

func TestShareService_ReceiveShares_ConnectFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spkiPin string
	}{
		{name: "no SPKI pin"},
		{name: "with SPKI pin", spkiPin: "deadbeef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewShareService()
			svc.SetContext(context.Background())
			svc.SetShareStore(xkms.NewMemoryShareStore())

			shares, err := svc.ReceiveShares(unreachableShareServer, tc.spkiPin)
			require.ErrorIs(t, err, ErrShareReceiveFailed)
			assert.Nil(t, shares)
		})
	}
}

// ---------------------------------------------------------------------------
// SubmitShare
// ---------------------------------------------------------------------------

func TestShareService_SubmitShare_EmptyServerURL(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(xkms.NewMemoryShareStore())

	err := svc.SubmitShare("", "group-1", 0, "")
	require.ErrorIs(t, err, ErrEmptyServerURL)
}

func TestShareService_SubmitShare_EmptyGroupID(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(xkms.NewMemoryShareStore())

	err := svc.SubmitShare("https://xkms.example.com", "", 0, "")
	require.ErrorIs(t, err, ErrEmptyGroupID)
}

func TestShareService_SubmitShare_NilStore(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())

	err := svc.SubmitShare("https://xkms.example.com", "group-1", 0, "")
	require.ErrorIs(t, err, ErrShareStoreNil)
}

func TestShareService_SubmitShare_ShareNotFound(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(xkms.NewMemoryShareStore())

	err := svc.SubmitShare("https://xkms.example.com", "missing-group", 0, "")
	require.ErrorIs(t, err, ErrShareNotFound)
}

func TestShareService_SubmitShare_ConnectFailure(t *testing.T) {
	store := xkms.NewMemoryShareStore()
	entry := &xkms.ShareEntry{
		ServerURL:  unreachableShareServer,
		GroupID:    "group-1",
		ShareIndex: 0,
		ShareData:  []byte("secret-share-data"),
		ReceivedAt: time.Now().UTC(),
	}
	require.NoError(t, store.Save(context.Background(), entry))

	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(store)

	err := svc.SubmitShare(unreachableShareServer, "group-1", 0, "spki-pin-value")
	require.ErrorIs(t, err, ErrShareSubmitFailed)
}

// ---------------------------------------------------------------------------
// GetShareStatus
// ---------------------------------------------------------------------------

func TestShareService_GetShareStatus_EmptyServerURL(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())

	status, err := svc.GetShareStatus("", "group-1", "")
	require.ErrorIs(t, err, ErrEmptyServerURL)
	assert.Nil(t, status)
}

func TestShareService_GetShareStatus_EmptyGroupID(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())

	status, err := svc.GetShareStatus("https://xkms.example.com", "", "")
	require.ErrorIs(t, err, ErrEmptyGroupID)
	assert.Nil(t, status)
}

func TestShareService_GetShareStatus_ConnectFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spkiPin string
	}{
		{name: "no SPKI pin"},
		{name: "with SPKI pin", spkiPin: "deadbeef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewShareService()
			svc.SetContext(context.Background())

			status, err := svc.GetShareStatus(unreachableShareServer, "group-1", tc.spkiPin)
			require.Error(t, err)
			assert.Nil(t, status)
		})
	}
}
