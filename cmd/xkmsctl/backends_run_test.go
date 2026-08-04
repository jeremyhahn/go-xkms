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

// backends_run_test.go exercises the "xkmsctl backends list/info" Run
// closures, which delegate to the already-tested listBackends/backendInfo
// named functions.
package main

import (
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

func TestBackendsListCmd_Run(t *testing.T) {
	mock := &mockBackendsClient{listBackendsResp: &client.ListBackendsResponse{
		Backends: []client.BackendInfo{{ID: "software", Type: "software"}},
	}}
	withGlobalConfig(t, &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	})

	captureStdout(t, func() {
		backendsListCmd.Run(backendsListCmd, nil)
	})
}

func TestBackendsInfoCmd_Run(t *testing.T) {
	mock := &mockBackendsClient{getBackendResp: &client.BackendInfo{
		ID: "software", Type: "software",
		Capabilities: transport.BackendCapabilities{Keys: true, Signing: true},
	}}
	withGlobalConfig(t, &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	})

	captureStdout(t, func() {
		backendsInfoCmd.Run(backendsInfoCmd, []string{"software"})
	})
}
