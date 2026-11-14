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
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

var errPlatformRunBoom = errors.New("boom")

// TestPlatformPutCmd_WipesSecret checks the secret buffer handed to the
// client is zeroed after put, on success and on the error path (#623).
func TestPlatformPutCmd_WipesSecret(t *testing.T) {
	for _, tc := range []struct {
		name   string
		putErr error
	}{
		{name: "success"},
		{name: "error", putErr: errPlatformRunBoom},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetCmdFlags(t, platformPutCmd)
			t.Cleanup(func() { resetCmdFlags(t, platformPutCmd) })
			mock := &mockPlatformClient{putErr: tc.putErr}
			withGlobalConfig(t, newPlatformConfig(mock))
			_ = platformPutCmd.Flags().Set("value", "s3cret")

			captureStdout(t, func() {
				captureExit(t, func() {
					platformPutCmd.Run(platformPutCmd, []string{"db-password"})
				})
			})
			if len(mock.gotPutSecretRef) == 0 {
				t.Fatal("SealStorePut was not called with a secret")
			}
			if !bytes.Equal(mock.gotPutSecretRef, make([]byte, len(mock.gotPutSecretRef))) {
				t.Errorf("secret buffer not wiped after put: %q", mock.gotPutSecretRef)
			}
		})
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

// TestPlatformGet_WipesSecretOnEveryOutputPath checks the secret is zero on
// return and, on a failing output, already zero when the process exits:
// os.Exit skips deferred calls, so a deferred wipe never runs there.
func TestPlatformGet_WipesSecretOnEveryOutputPath(t *testing.T) {
	badFile := filepath.Join(t.TempDir(), "missing-dir", "secret")
	for _, tc := range []struct {
		name       string
		format     string
		outputFile string
		failWrites bool
	}{
		{name: "text", format: "text"},
		{name: "table", format: "table"},
		{name: "json", format: "json"},
		{name: "file", format: "text", outputFile: filepath.Join(t.TempDir(), "secret")},
		{name: "text write error", format: "text", failWrites: true},
		{name: "json write error", format: "json", failWrites: true},
		{name: "file write error", format: "text", outputFile: badFile},
		{name: "file success message error", format: "text", outputFile: filepath.Join(t.TempDir(), "secret"), failWrites: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := []byte("s3cret")
			mock := &mockPlatformClient{getResp: &transport.SealStoreGetResponse{Name: "db-password", Secret: secret}}
			cfg := newPlatformConfig(mock)
			cfg.OutputFormat = tc.format

			out := io.Discard
			if tc.failWrites {
				out = &erroringWriter{err: errPlatformRunBoom}
			}

			oldExit := exitFunc
			t.Cleanup(func() { exitFunc = oldExit })
			exited, wipedAtExit := false, false
			exitFunc = func(int) {
				exited = true
				wipedAtExit = bytes.Equal(secret, make([]byte, len(secret)))
			}

			platformGet(cfg, NewPrinter(cfg.OutputFormat, out), "db-password", tc.outputFile)

			wantExit := tc.failWrites || tc.outputFile == badFile
			if exited != wantExit {
				t.Fatalf("exited = %v, want %v", exited, wantExit)
			}
			if exited && !wipedAtExit {
				t.Error("secret not wiped before exit")
			}
			if !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Errorf("secret not wiped on return: %q", secret)
			}
		})
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
