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

// handlers_share_test.go covers the MCP Shamir share methods: dispatch
// registration, parameter validation, and the not-configured path taken when
// no go-qrdb node backs the service.
package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// testShareServerURL is the server URL used to address a share.
const testShareServerURL = "https://xkms.example.com:8443"

// newShareServer returns an MCP server backed by the standard test XKMS
// service. That service carries no go-qrdb node, so share calls exercise the
// not-configured path — the parameter validation in front of it runs first
// and is what these tests pin.
func newShareServer(t *testing.T) *Server {
	t.Helper()

	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)

	server, err := NewServer(&Config{
		Addr:          "localhost:0",
		XKMSService:   svc,
		Authenticator: auth.NewNoOpAuthenticator(),
	})
	require.NoError(t, err)
	return server
}

// shareRequest builds a JSON-RPC request with the given params object.
func shareRequest(t *testing.T, method string, params interface{}) *JSONRPCRequest {
	t.Helper()

	raw, err := json.Marshal(params)
	require.NoError(t, err)

	return &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: raw, ID: 1}
}

// TestShareMethods_Dispatchable proves every share method is reachable
// through the dispatch table. The MCP server registered none of them while
// the transport client already called them, so a missing registration is the
// exact regression to catch.
func TestShareMethods_Dispatchable(t *testing.T) {
	for _, method := range []string{
		"xkms.submitShare",
		"xkms.listShares",
		"xkms.getShare",
		"xkms.deleteShare",
		"xkms.getShareCollectionStatus",
	} {
		_, ok := rpcMethodHandlers[method]
		assert.True(t, ok, "method %q must be dispatchable", method)
	}
}

func TestHandleSubmitShare_RequiresGroupID(t *testing.T) {
	server := newShareServer(t)

	_, err := server.handleSubmitShare(context.Background(),
		shareRequest(t, "xkms.submitShare", transport.SubmitShareRequest{ShareData: []byte("s")}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "group_id")
}

func TestHandleSubmitShare_RequiresShareData(t *testing.T) {
	server := newShareServer(t)

	_, err := server.handleSubmitShare(context.Background(),
		shareRequest(t, "xkms.submitShare", transport.SubmitShareRequest{GroupID: "g1"}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "share_data")
}

func TestHandleSubmitShare_InvalidParams(t *testing.T) {
	server := newShareServer(t)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.submitShare", Params: json.RawMessage(`{`), ID: 1}
	_, err := server.handleSubmitShare(context.Background(), req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid params")
}

func TestHandleSubmitShare_NotConfigured(t *testing.T) {
	server := newShareServer(t)

	_, err := server.handleSubmitShare(context.Background(),
		shareRequest(t, "xkms.submitShare", transport.SubmitShareRequest{GroupID: "g1", ShareData: []byte("s")}))

	require.Error(t, err, "a service with no go-qrdb node must report failure, not panic")
}

func TestHandleListShares_NotConfigured(t *testing.T) {
	server := newShareServer(t)

	_, err := server.handleListShares(context.Background(), shareRequest(t, "xkms.listShares", struct{}{}))

	require.Error(t, err)
}

func TestHandleGetShare_RequiresCoordinates(t *testing.T) {
	server := newShareServer(t)

	tests := []struct {
		name   string
		params ShareCoordinatesParams
		want   string
	}{
		{"missing server_url", ShareCoordinatesParams{GroupID: "g1", ShareIndex: 1}, "server_url"},
		{"missing group_id", ShareCoordinatesParams{ServerURL: testShareServerURL, ShareIndex: 1}, "group_id"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := server.handleGetShare(context.Background(),
				shareRequest(t, "xkms.getShare", tc.params))

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestHandleGetShare_NotConfigured(t *testing.T) {
	server := newShareServer(t)

	_, err := server.handleGetShare(context.Background(), shareRequest(t, "xkms.getShare",
		ShareCoordinatesParams{ServerURL: testShareServerURL, GroupID: "g1", ShareIndex: 2}))

	require.Error(t, err)
}

func TestHandleDeleteShare_RequiresCoordinates(t *testing.T) {
	server := newShareServer(t)

	_, err := server.handleDeleteShare(context.Background(), shareRequest(t, "xkms.deleteShare",
		ShareCoordinatesParams{GroupID: "g1", ShareIndex: 1}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "server_url")
}

func TestHandleDeleteShare_NotConfigured(t *testing.T) {
	server := newShareServer(t)

	_, err := server.handleDeleteShare(context.Background(), shareRequest(t, "xkms.deleteShare",
		ShareCoordinatesParams{ServerURL: testShareServerURL, GroupID: "g1", ShareIndex: 2}))

	require.Error(t, err)
}

func TestHandleGetShareCollectionStatus_RequiresGroupID(t *testing.T) {
	server := newShareServer(t)

	_, err := server.handleGetShareCollectionStatus(context.Background(),
		shareRequest(t, "xkms.getShareCollectionStatus", GetShareCollectionStatusParams{}))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "group_id")
}

func TestHandleGetShareCollectionStatus_NotConfigured(t *testing.T) {
	server := newShareServer(t)

	_, err := server.handleGetShareCollectionStatus(context.Background(),
		shareRequest(t, "xkms.getShareCollectionStatus", GetShareCollectionStatusParams{GroupID: "g1"}))

	require.Error(t, err)
}

// TestShareCoordinates_InvalidParams covers the decode failure path shared by
// getShare and deleteShare.
func TestShareCoordinates_InvalidParams(t *testing.T) {
	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.getShare", Params: json.RawMessage(`[`), ID: 1}

	_, err := shareCoordinates(req)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid params")
}

// TestWithoutShareData proves the response scrubber clears share material
// while preserving every metadata field. Share bytes are write-only over the
// API: leaking them here would hand a reader quorum material directly.
func TestWithoutShareData(t *testing.T) {
	received := time.Now().UTC()
	info := transport.ShareInfo{
		ServerURL:  testShareServerURL,
		GroupID:    "g1",
		GroupName:  "ops",
		ShareIndex: 4,
		ShareData:  []byte("secret-share-material"),
		Purpose:    "barrier",
		ReceivedAt: received,
		TenantID:   "t1",
	}

	got := withoutShareData(info)

	assert.Nil(t, got.ShareData, "share material must be cleared")
	assert.Equal(t, testShareServerURL, got.ServerURL)
	assert.Equal(t, "g1", got.GroupID)
	assert.Equal(t, "ops", got.GroupName)
	assert.Equal(t, 4, got.ShareIndex)
	assert.Equal(t, "barrier", got.Purpose)
	assert.Equal(t, received, got.ReceivedAt)
	assert.Equal(t, "t1", got.TenantID)

	assert.Equal(t, []byte("secret-share-material"), info.ShareData,
		"the caller's own value must not be mutated")
}
