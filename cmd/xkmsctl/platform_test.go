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

// platform_test.go defines mockPlatformClient and exercises the
// "xkmsctl platform" flag/argument validation paths.
package main

import (
	"context"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockPlatformClient is a mock client for testing platform store operations.
type mockPlatformClient struct {
	mockBackendsClient
	putErr     error
	getResp    *transport.SealStoreGetResponse
	getErr     error
	deleteErr  error
	listResp   *transport.SealStoreListResponse
	listErr    error
	resealErr  error
	statusResp *transport.SealStoreStatusResponse
	statusErr  error

	// Captured requests for assertion.
	gotPutReq    *transport.SealStorePutRequest
	gotGetReq    *transport.SealStoreGetRequest
	gotDeleteReq *transport.SealStoreDeleteRequest
	gotResealReq *transport.SealStoreResealRequest
}

func (m *mockPlatformClient) SealStorePut(_ context.Context, req *transport.SealStorePutRequest) error {
	m.gotPutReq = req
	return m.putErr
}

func (m *mockPlatformClient) SealStoreGet(_ context.Context, req *transport.SealStoreGetRequest) (*transport.SealStoreGetResponse, error) {
	m.gotGetReq = req
	return m.getResp, m.getErr
}

func (m *mockPlatformClient) SealStoreDelete(_ context.Context, req *transport.SealStoreDeleteRequest) error {
	m.gotDeleteReq = req
	return m.deleteErr
}

func (m *mockPlatformClient) SealStoreList(_ context.Context) (*transport.SealStoreListResponse, error) {
	return m.listResp, m.listErr
}

func (m *mockPlatformClient) SealStoreReseal(_ context.Context, req *transport.SealStoreResealRequest) error {
	m.gotResealReq = req
	return m.resealErr
}

func (m *mockPlatformClient) SealStoreStatus(_ context.Context) (*transport.SealStoreStatusResponse, error) {
	return m.statusResp, m.statusErr
}

func (m *mockPlatformClient) EscrowKey(_ context.Context, _ *transport.EscrowRequest) ([]*transport.EscrowReceipt, error) {
	return nil, nil
}

func (m *mockPlatformClient) RecoverKey(_ context.Context, _ *transport.RecoverRequest) (*transport.RecoverResponse, error) {
	return nil, nil
}

func (m *mockPlatformClient) ListEscrowed(_ context.Context) ([]transport.EscrowRecord, error) {
	return nil, nil
}

func (m *mockPlatformClient) RevokeEscrow(_ context.Context, _ string) error {
	return nil
}

func newPlatformConfig(mock *mockPlatformClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func TestPlatformPutCmd_ValueFileConflict(t *testing.T) {
	resetCmdFlags(t, platformPutCmd)
	t.Cleanup(func() { resetCmdFlags(t, platformPutCmd) })
	withGlobalConfig(t, newPlatformConfig(&mockPlatformClient{}))
	_ = platformPutCmd.Flags().Set("value", "s3cret")
	_ = platformPutCmd.Flags().Set("file", "/tmp/secret")

	code := captureExit(t, func() {
		platformPutCmd.Run(platformPutCmd, []string{"db-password"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for --value/--file conflict, got %d", code)
	}
}

func TestPlatformPutCmd_EmptySecret(t *testing.T) {
	resetCmdFlags(t, platformPutCmd)
	t.Cleanup(func() { resetCmdFlags(t, platformPutCmd) })
	withGlobalConfig(t, newPlatformConfig(&mockPlatformClient{}))
	withPromptInput(t, "\n")

	code := captureExit(t, func() {
		platformPutCmd.Run(platformPutCmd, []string{"db-password"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for empty secret, got %d", code)
	}
}

func TestPlatformPutCmd_MissingFile(t *testing.T) {
	resetCmdFlags(t, platformPutCmd)
	t.Cleanup(func() { resetCmdFlags(t, platformPutCmd) })
	withGlobalConfig(t, newPlatformConfig(&mockPlatformClient{}))
	_ = platformPutCmd.Flags().Set("file", "/nonexistent/secret-file")

	code := captureExit(t, func() {
		platformPutCmd.Run(platformPutCmd, []string{"db-password"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for missing secret file, got %d", code)
	}
}

func TestPlatformCmd_Registered(t *testing.T) {
	for _, verb := range []string{"put", "get", "delete", "list", "reseal", "status"} {
		if _, _, err := rootCmd.Find([]string{"platform", verb}); err != nil {
			t.Errorf("platform %s missing: %v", verb, err)
		}
	}
}
