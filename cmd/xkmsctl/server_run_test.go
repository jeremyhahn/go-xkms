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

// server_run_test.go exercises the top-level "xkmsctl status" command against
// a mock health surface.
package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

var errServerRunBoom = errors.New("boom")

// mockHealthClient reports a configurable health response and connect error;
// all other methods come from the embedded base.
type mockHealthClient struct {
	mockBackendsClient
	healthResp *client.HealthResponse
	healthErr  error
}

func (m *mockHealthClient) Health(_ context.Context) (*client.HealthResponse, error) {
	if m.healthResp != nil || m.healthErr != nil {
		return m.healthResp, m.healthErr
	}
	return &client.HealthResponse{Status: "ok"}, nil
}

func newServerConfig(mock client.Client) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func TestServerStatusCmd_Success(t *testing.T) {
	withGlobalConfig(t, newServerConfig(&mockHealthClient{
		healthResp: &client.HealthResponse{Status: "ok", Version: "1.2.3"},
	}))

	out := captureStdout(t, func() {
		serverStatusCmd.Run(serverStatusCmd, nil)
	})
	if !strings.Contains(out, "ok") {
		t.Errorf("expected status in output, got %q", out)
	}
	if !strings.Contains(out, "1.2.3") {
		t.Errorf("expected version in output, got %q", out)
	}
}

func TestServerStatusCmd_ConnectError(t *testing.T) {
	withGlobalConfig(t, newServerConfig(&mockHealthClient{
		mockBackendsClient: mockBackendsClient{connectErr: errServerRunBoom},
	}))

	code := captureExit(t, func() {
		serverStatusCmd.Run(serverStatusCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 on connect failure, got %d", code)
	}
}

func TestServerStatusCmd_HealthError(t *testing.T) {
	withGlobalConfig(t, newServerConfig(&mockHealthClient{healthErr: errServerRunBoom}))

	code := captureExit(t, func() {
		serverStatusCmd.Run(serverStatusCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 on health failure, got %d", code)
	}
}

func TestServerStatusCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return nil, errServerRunBoom
		},
	})

	code := captureExit(t, func() {
		serverStatusCmd.Run(serverStatusCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 on client creation failure, got %d", code)
	}
}
