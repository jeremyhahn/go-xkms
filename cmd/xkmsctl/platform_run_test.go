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

// platform_run_test.go exercises the "xkmsctl platform" command tree against
// mockPlatformClient (defined in platform_test.go), covering the SDK happy
// path and error handling for each subcommand.
package main

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errPlatformRunBoom = errors.New("boom")

func TestPlatformPutCmd_Success(t *testing.T) {
	resetCmdFlags(t, platformPutCmd)
	t.Cleanup(func() { resetCmdFlags(t, platformPutCmd) })
	mock := &mockPlatformClient{}
	withGlobalConfig(t, newPlatformConfig(mock))
	_ = platformPutCmd.Flags().Set("value", "s3cret")

	captureStdout(t, func() {
		platformPutCmd.Run(platformPutCmd, []string{"db-password"})
	})
	if mock.gotPutReq == nil || mock.gotPutReq.Name != "db-password" ||
		string(mock.gotPutReq.Secret) != "s3cret" {
		t.Errorf("SealStorePut request mismatch: %+v", mock.gotPutReq)
	}
}

func TestPlatformPutCmd_Error(t *testing.T) {
	resetCmdFlags(t, platformPutCmd)
	t.Cleanup(func() { resetCmdFlags(t, platformPutCmd) })
	withGlobalConfig(t, newPlatformConfig(&mockPlatformClient{putErr: errPlatformRunBoom}))
	_ = platformPutCmd.Flags().Set("value", "s3cret")

	code := captureExit(t, func() {
		platformPutCmd.Run(platformPutCmd, []string{"db-password"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPlatformGetCmd_SuccessAndError(t *testing.T) {
	mock := &mockPlatformClient{getResp: &transport.SealStoreGetResponse{
		Name: "db-password", Secret: []byte("s3cret"),
	}}
	withGlobalConfig(t, newPlatformConfig(mock))
	out := captureStdout(t, func() {
		platformGetCmd.Run(platformGetCmd, []string{"db-password"})
	})
	if mock.gotGetReq == nil || mock.gotGetReq.Name != "db-password" {
		t.Errorf("SealStoreGet request mismatch: %+v", mock.gotGetReq)
	}
	// Text output base64-encodes the secret bytes (czNjcmV0 == "s3cret").
	if !strings.Contains(out, base64.StdEncoding.EncodeToString([]byte("s3cret"))) {
		t.Errorf("expected base64 secret in output, got %q", out)
	}

	withGlobalConfig(t, newPlatformConfig(&mockPlatformClient{getErr: errPlatformRunBoom}))
	code := captureExit(t, func() {
		platformGetCmd.Run(platformGetCmd, []string{"db-password"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPlatformDeleteCmd_SuccessAndError(t *testing.T) {
	mock := &mockPlatformClient{}
	withGlobalConfig(t, newPlatformConfig(mock))
	captureStdout(t, func() {
		platformDeleteCmd.Run(platformDeleteCmd, []string{"db-password"})
	})
	if mock.gotDeleteReq == nil || mock.gotDeleteReq.Name != "db-password" {
		t.Errorf("SealStoreDelete request mismatch: %+v", mock.gotDeleteReq)
	}

	withGlobalConfig(t, newPlatformConfig(&mockPlatformClient{deleteErr: errPlatformRunBoom}))
	code := captureExit(t, func() {
		platformDeleteCmd.Run(platformDeleteCmd, []string{"db-password"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPlatformListCmd_SuccessAndError(t *testing.T) {
	withGlobalConfig(t, newPlatformConfig(&mockPlatformClient{listResp: &transport.SealStoreListResponse{
		Names: []string{"db-password", "tls-key"},
	}}))
	out := captureStdout(t, func() {
		platformListCmd.Run(platformListCmd, nil)
	})
	if !strings.Contains(out, "db-password") {
		t.Errorf("expected secret name in list, got %q", out)
	}

	withGlobalConfig(t, newPlatformConfig(&mockPlatformClient{listErr: errPlatformRunBoom}))
	code := captureExit(t, func() {
		platformListCmd.Run(platformListCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPlatformResealCmd_SuccessAndError(t *testing.T) {
	mock := &mockPlatformClient{}
	withGlobalConfig(t, newPlatformConfig(mock))
	captureStdout(t, func() {
		platformResealCmd.Run(platformResealCmd, []string{"db-password"})
	})
	if mock.gotResealReq == nil || mock.gotResealReq.Name != "db-password" {
		t.Errorf("SealStoreReseal request mismatch: %+v", mock.gotResealReq)
	}

	withGlobalConfig(t, newPlatformConfig(&mockPlatformClient{resealErr: errPlatformRunBoom}))
	code := captureExit(t, func() {
		platformResealCmd.Run(platformResealCmd, []string{"db-password"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestPlatformStatusCmd_SuccessAndError(t *testing.T) {
	withGlobalConfig(t, newPlatformConfig(&mockPlatformClient{statusResp: &transport.SealStoreStatusResponse{
		Available: true, SecretCount: 2,
	}}))
	out := captureStdout(t, func() {
		platformStatusCmd.Run(platformStatusCmd, nil)
	})
	if !strings.Contains(strings.ToLower(out), "available") {
		t.Errorf("expected status output, got %q", out)
	}

	withGlobalConfig(t, newPlatformConfig(&mockPlatformClient{statusErr: errPlatformRunBoom}))
	code := captureExit(t, func() {
		platformStatusCmd.Run(platformStatusCmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}
