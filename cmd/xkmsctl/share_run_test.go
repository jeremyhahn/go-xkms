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

// share_run_test.go exercises the "xkmsctl share" command tree against a mock
// ShareService, covering happy paths, flag validation, and error handling.
package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errShareRunBoom = errors.New("boom")

type mockShareClient struct {
	mockBackendsClient

	submitResp *transport.SubmitShareResponse
	submitErr  error
	listResp   *transport.ListSharesResponse
	listErr    error
	statusResp *transport.ShareCollectionStatus
	statusErr  error
	getResp    *transport.ShareInfo
	getErr     error
	deleteErr  error

	gotSubmitReq *transport.SubmitShareRequest
	gotStatusID  string

	// gotCoords records the (serverURL, groupID, shareIndex) triple the
	// last per-share call addressed.
	gotCoords shareCoords
}

// shareCoords is the triple identifying a single share.
type shareCoords struct {
	serverURL  string
	groupID    string
	shareIndex int
}

func (m *mockShareClient) SubmitShare(_ context.Context, req *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	m.gotSubmitReq = req
	return m.submitResp, m.submitErr
}

func (m *mockShareClient) ListShares(_ context.Context) (*transport.ListSharesResponse, error) {
	return m.listResp, m.listErr
}

func (m *mockShareClient) GetShareCollectionStatus(_ context.Context, groupID string) (*transport.ShareCollectionStatus, error) {
	m.gotStatusID = groupID
	return m.statusResp, m.statusErr
}

func (m *mockShareClient) GetShare(_ context.Context, serverURL, groupID string, shareIndex int) (*transport.ShareInfo, error) {
	m.gotCoords = shareCoords{serverURL: serverURL, groupID: groupID, shareIndex: shareIndex}
	return m.getResp, m.getErr
}

func (m *mockShareClient) DeleteShare(_ context.Context, serverURL, groupID string, shareIndex int) error {
	m.gotCoords = shareCoords{serverURL: serverURL, groupID: groupID, shareIndex: shareIndex}
	return m.deleteErr
}

func newShareConfig(mock *mockShareClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func TestShareSubmitCmd_Success(t *testing.T) {
	resetCmdFlags(t, shareSubmitCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareSubmitCmd) })
	mock := &mockShareClient{submitResp: &transport.SubmitShareResponse{Accepted: true}}
	withGlobalConfig(t, newShareConfig(mock))
	_ = shareSubmitCmd.Flags().Set("group-id", "g1")
	_ = shareSubmitCmd.Flags().Set("share-index", "2")
	_ = shareSubmitCmd.Flags().Set("data", "c2hhcmU=") // "share"

	out := captureStdout(t, func() {
		shareSubmitCmd.Run(shareSubmitCmd, nil)
	})
	if mock.gotSubmitReq == nil || mock.gotSubmitReq.GroupID != "g1" ||
		mock.gotSubmitReq.ShareIndex != 2 || string(mock.gotSubmitReq.ShareData) != "share" {
		t.Fatalf("SubmitShare request mismatch: %+v", mock.gotSubmitReq)
	}
	if !strings.Contains(out, "accepted") {
		t.Errorf("expected acceptance message, got %q", out)
	}
}

func TestShareSubmitCmd_RequiresGroupID(t *testing.T) {
	resetCmdFlags(t, shareSubmitCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareSubmitCmd) })
	withGlobalConfig(t, newShareConfig(&mockShareClient{}))
	_ = shareSubmitCmd.Flags().Set("data", "c2hhcmU=")

	code := captureExit(t, func() {
		shareSubmitCmd.Run(shareSubmitCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1 without --group-id, got %d", code)
	}
}

func TestShareSubmitCmd_RequiresData(t *testing.T) {
	resetCmdFlags(t, shareSubmitCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareSubmitCmd) })
	withGlobalConfig(t, newShareConfig(&mockShareClient{}))
	_ = shareSubmitCmd.Flags().Set("group-id", "g1")

	code := captureExit(t, func() {
		shareSubmitCmd.Run(shareSubmitCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1 without share data, got %d", code)
	}
}

func TestShareSubmitCmd_DataFileConflict(t *testing.T) {
	resetCmdFlags(t, shareSubmitCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareSubmitCmd) })
	withGlobalConfig(t, newShareConfig(&mockShareClient{}))
	_ = shareSubmitCmd.Flags().Set("group-id", "g1")
	_ = shareSubmitCmd.Flags().Set("data", "c2hhcmU=")
	_ = shareSubmitCmd.Flags().Set("file", "/tmp/x")

	code := captureExit(t, func() {
		shareSubmitCmd.Run(shareSubmitCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1 on data/file conflict, got %d", code)
	}
}

func TestShareSubmitCmd_Error(t *testing.T) {
	resetCmdFlags(t, shareSubmitCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareSubmitCmd) })
	withGlobalConfig(t, newShareConfig(&mockShareClient{submitErr: errShareRunBoom}))
	_ = shareSubmitCmd.Flags().Set("group-id", "g1")
	_ = shareSubmitCmd.Flags().Set("data", "c2hhcmU=")

	code := captureExit(t, func() {
		shareSubmitCmd.Run(shareSubmitCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
}

func TestShareListCmd_SuccessAndError(t *testing.T) {
	withGlobalConfig(t, newShareConfig(&mockShareClient{listResp: &transport.ListSharesResponse{
		Shares: []transport.ShareInfo{{GroupID: "g1", ShareIndex: 1, ServerURL: "https://x", ReceivedAt: time.Now()}},
	}}))
	out := captureStdout(t, func() {
		shareListCmd.Run(shareListCmd, nil)
	})
	if !strings.Contains(out, "g1") {
		t.Errorf("expected share in list output, got %q", out)
	}

	withGlobalConfig(t, newShareConfig(&mockShareClient{listErr: errShareRunBoom}))
	code := captureExit(t, func() {
		shareListCmd.Run(shareListCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
}

func TestShareStatusCmd_SuccessAndError(t *testing.T) {
	resetCmdFlags(t, shareStatusCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareStatusCmd) })
	mock := &mockShareClient{statusResp: &transport.ShareCollectionStatus{
		GroupID: "g1", Collected: 2, Threshold: 3, Total: 5,
	}}
	withGlobalConfig(t, newShareConfig(mock))
	_ = shareStatusCmd.Flags().Set("group-id", "g1")
	out := captureStdout(t, func() {
		shareStatusCmd.Run(shareStatusCmd, nil)
	})
	if mock.gotStatusID != "g1" {
		t.Errorf("status group id = %q, want g1", mock.gotStatusID)
	}
	if !strings.Contains(out, "Collected") {
		t.Errorf("expected status output, got %q", out)
	}

	resetCmdFlags(t, shareStatusCmd)
	withGlobalConfig(t, newShareConfig(&mockShareClient{statusErr: errShareRunBoom}))
	_ = shareStatusCmd.Flags().Set("group-id", "g1")
	code := captureExit(t, func() {
		shareStatusCmd.Run(shareStatusCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
}

func TestShareStatusCmd_RequiresGroupID(t *testing.T) {
	resetCmdFlags(t, shareStatusCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareStatusCmd) })
	withGlobalConfig(t, newShareConfig(&mockShareClient{}))

	code := captureExit(t, func() {
		shareStatusCmd.Run(shareStatusCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1 without --group-id, got %d", code)
	}
}

func TestShareGetCmd_Success(t *testing.T) {
	resetCmdFlags(t, shareGetCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareGetCmd) })
	mock := &mockShareClient{getResp: &transport.ShareInfo{
		ServerURL: "https://xkms:8443", GroupID: "g1", GroupName: "ops",
		ShareIndex: 2, Purpose: "barrier", ReceivedAt: time.Now(),
	}}
	withGlobalConfig(t, newShareConfig(mock))
	_ = shareGetCmd.Flags().Set("server-url", "https://xkms:8443")
	_ = shareGetCmd.Flags().Set("group-id", "g1")
	_ = shareGetCmd.Flags().Set("share-index", "2")

	out := captureStdout(t, func() {
		shareGetCmd.Run(shareGetCmd, nil)
	})

	want := shareCoords{serverURL: "https://xkms:8443", groupID: "g1", shareIndex: 2}
	if mock.gotCoords != want {
		t.Errorf("GetShare addressed %+v, want %+v", mock.gotCoords, want)
	}
	if !strings.Contains(out, "g1") || !strings.Contains(out, "barrier") {
		t.Errorf("expected share metadata in output, got %q", out)
	}
}

// TestShareGetCmd_NeverPrintsShareData pins the security property: share
// bytes are write-only over the API, so even a server that wrongly returned
// them must not have the CLI echo them to a terminal.
func TestShareGetCmd_NeverPrintsShareData(t *testing.T) {
	resetCmdFlags(t, shareGetCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareGetCmd) })
	withGlobalConfig(t, newShareConfig(&mockShareClient{getResp: &transport.ShareInfo{
		ServerURL: "https://xkms:8443", GroupID: "g1", ShareIndex: 1,
		ShareData: []byte("TOP-SECRET-SHARE-BYTES"), ReceivedAt: time.Now(),
	}}))
	_ = shareGetCmd.Flags().Set("server-url", "https://xkms:8443")
	_ = shareGetCmd.Flags().Set("group-id", "g1")

	out := captureStdout(t, func() {
		shareGetCmd.Run(shareGetCmd, nil)
	})
	if strings.Contains(out, "TOP-SECRET-SHARE-BYTES") {
		t.Error("share material must never be printed by the CLI")
	}
}

func TestShareGetCmd_RequiresServerURL(t *testing.T) {
	resetCmdFlags(t, shareGetCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareGetCmd) })
	withGlobalConfig(t, newShareConfig(&mockShareClient{}))
	_ = shareGetCmd.Flags().Set("group-id", "g1")

	code := captureExit(t, func() {
		shareGetCmd.Run(shareGetCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1 without --server-url, got %d", code)
	}
}

func TestShareGetCmd_RequiresGroupID(t *testing.T) {
	resetCmdFlags(t, shareGetCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareGetCmd) })
	withGlobalConfig(t, newShareConfig(&mockShareClient{}))
	_ = shareGetCmd.Flags().Set("server-url", "https://xkms:8443")

	code := captureExit(t, func() {
		shareGetCmd.Run(shareGetCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1 without --group-id, got %d", code)
	}
}

func TestShareGetCmd_Error(t *testing.T) {
	resetCmdFlags(t, shareGetCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareGetCmd) })
	withGlobalConfig(t, newShareConfig(&mockShareClient{getErr: errShareRunBoom}))
	_ = shareGetCmd.Flags().Set("server-url", "https://xkms:8443")
	_ = shareGetCmd.Flags().Set("group-id", "g1")

	code := captureExit(t, func() {
		shareGetCmd.Run(shareGetCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
}

func TestShareDeleteCmd_Success(t *testing.T) {
	resetCmdFlags(t, shareDeleteCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareDeleteCmd) })
	mock := &mockShareClient{}
	withGlobalConfig(t, newShareConfig(mock))
	_ = shareDeleteCmd.Flags().Set("server-url", "https://xkms:8443")
	_ = shareDeleteCmd.Flags().Set("group-id", "g1")
	_ = shareDeleteCmd.Flags().Set("share-index", "3")

	out := captureStdout(t, func() {
		shareDeleteCmd.Run(shareDeleteCmd, nil)
	})

	want := shareCoords{serverURL: "https://xkms:8443", groupID: "g1", shareIndex: 3}
	if mock.gotCoords != want {
		t.Errorf("DeleteShare addressed %+v, want %+v", mock.gotCoords, want)
	}
	if !strings.Contains(out, "Deleted share") {
		t.Errorf("expected deletion message, got %q", out)
	}
}

func TestShareDeleteCmd_RequiresServerURL(t *testing.T) {
	resetCmdFlags(t, shareDeleteCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareDeleteCmd) })
	withGlobalConfig(t, newShareConfig(&mockShareClient{}))
	_ = shareDeleteCmd.Flags().Set("group-id", "g1")

	code := captureExit(t, func() {
		shareDeleteCmd.Run(shareDeleteCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1 without --server-url, got %d", code)
	}
}

func TestShareDeleteCmd_Error(t *testing.T) {
	resetCmdFlags(t, shareDeleteCmd)
	t.Cleanup(func() { resetCmdFlags(t, shareDeleteCmd) })
	withGlobalConfig(t, newShareConfig(&mockShareClient{deleteErr: errShareRunBoom}))
	_ = shareDeleteCmd.Flags().Set("server-url", "https://xkms:8443")
	_ = shareDeleteCmd.Flags().Set("group-id", "g1")

	code := captureExit(t, func() {
		shareDeleteCmd.Run(shareDeleteCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit 1, got %d", code)
	}
}

func TestShareCmd_Registration(t *testing.T) {
	found := map[string]bool{}
	for _, c := range shareCmd.Commands() {
		found[c.Name()] = true
	}
	for _, name := range []string{"submit", "list", "get", "delete", "status"} {
		if !found[name] {
			t.Errorf("expected share subcommand %q to be registered", name)
		}
	}
}
