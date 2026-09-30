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

// user_invite_test.go exercises "xkmsctl user invite redeem": reference
// parsing (full invitation link vs. bare token + --tenant-id), method
// validation, and the PIV and FIDO2 redemption paths against a mock client.
// The FIDO2 ceremony itself is driven through a nonexistent --device path
// (the same technique user_test.go uses for register/login), so device
// lookup fails fast and deterministically without touching real hardware;
// the test still covers everything exercised before the device is opened
// (GetInvite, origin/PIN resolution, BeginInviteRegistration is NOT reached
// because adapter construction fails first).
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestParseInviteReference(t *testing.T) {
	tests := []struct {
		name       string
		arg        string
		tenantFlag string
		wantTenant string
		wantToken  string
		wantErr    bool
	}{
		{
			name:       "full link",
			arg:        "https://kms.example.com/ui/#/invite/acme/b64url-secret",
			wantTenant: "acme",
			wantToken:  "b64url-secret",
		},
		{
			name:       "full link with escaped segments",
			arg:        "https://kms.example.com/ui/#/invite/acme%2Fsub/b64url%2Bsecret",
			wantTenant: "acme/sub",
			wantToken:  "b64url+secret",
		},
		{
			name:       "bare token with tenant flag",
			arg:        "b64url-secret",
			tenantFlag: "acme",
			wantTenant: "acme",
			wantToken:  "b64url-secret",
		},
		{
			name:    "bare token without tenant flag",
			arg:     "b64url-secret",
			wantErr: true,
		},
		{
			name:    "link missing token segment",
			arg:     "https://kms.example.com/ui/#/invite/acme",
			wantErr: true,
		},
		{
			name:    "empty argument and no tenant",
			arg:     "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenantID, token, err := parseInviteReference(tt.arg, tt.tenantFlag)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got tenant=%q token=%q", tenantID, token)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tenantID != tt.wantTenant || token != tt.wantToken {
				t.Errorf("got tenant=%q token=%q, want tenant=%q token=%q", tenantID, token, tt.wantTenant, tt.wantToken)
			}
		})
	}
}

// mockUserInviteClient adds the invite-redemption methods on top of
// mockUserClient (whose embedded mockBackendsClient answers them with
// client.ErrNotSupported by default).
type mockUserInviteClient struct {
	mockUserClient

	getInviteResp *client.GetInviteResponse
	getInviteErr  error

	activatePIVResp *client.ActivateInvitePIVResponse
	activatePIVErr  error

	gotActivatePIV *client.ActivateInvitePIVRequest
}

func (m *mockUserInviteClient) GetInvite(_ context.Context, _ *client.GetInviteRequest) (*client.GetInviteResponse, error) {
	return m.getInviteResp, m.getInviteErr
}

func (m *mockUserInviteClient) ActivateInvitePIV(_ context.Context, req *client.ActivateInvitePIVRequest) (*client.ActivateInvitePIVResponse, error) {
	m.gotActivatePIV = req
	return m.activatePIVResp, m.activatePIVErr
}

// newUserInviteTestConfig wires globalConfig's ClientFactory to return mock.
func newUserInviteTestConfig(format string, mock *mockUserInviteClient) *Config {
	return &Config{
		OutputFormat: format,
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func writeTempPEM(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "piv-cert.pem")
	// A structurally valid PEM block is enough here: this mock's
	// ActivateInvitePIV never parses it, only the CLI's file-read path is
	// under test (the real certificate verification is
	// pkg/xkms/servicer_invite_test.go's job).
	pem := "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(path, []byte(pem), 0o600); err != nil {
		t.Fatalf("write temp PEM: %v", err)
	}
	return path
}

func TestUserInviteRedeemCmd_PIVSuccess(t *testing.T) {
	resetCmdFlags(t, userInviteRedeemCmd)
	t.Cleanup(func() { resetCmdFlags(t, userInviteRedeemCmd) })

	mock := &mockUserInviteClient{
		getInviteResp:   &client.GetInviteResponse{Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour)},
		activatePIVResp: &client.ActivateInvitePIVResponse{UserID: 42},
	}
	withGlobalConfig(t, newUserInviteTestConfig("text", mock))

	certFile := writeTempPEM(t)
	if err := userInviteRedeemCmd.Flags().Set("method", "piv"); err != nil {
		t.Fatalf("set method: %v", err)
	}
	if err := userInviteRedeemCmd.Flags().Set("piv-cert-file", certFile); err != nil {
		t.Fatalf("set piv-cert-file: %v", err)
	}
	if err := userInviteRedeemCmd.Flags().Set("tenant-id", "acme"); err != nil {
		t.Fatalf("set tenant-id: %v", err)
	}

	out := captureStdout(t, func() {
		userInviteRedeemCmd.Run(userInviteRedeemCmd, []string{"b64url-secret"})
	})
	if mock.gotActivatePIV == nil {
		t.Fatal("ActivateInvitePIV was not called")
	}
	if mock.gotActivatePIV.TenantID != "acme" || mock.gotActivatePIV.Token != "b64url-secret" {
		t.Errorf("unexpected request: %+v", mock.gotActivatePIV)
	}
	if !containsAll(out, "Account activated.", "42") {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestUserInviteRedeemCmd_PIVMissingCertFile(t *testing.T) {
	resetCmdFlags(t, userInviteRedeemCmd)
	t.Cleanup(func() { resetCmdFlags(t, userInviteRedeemCmd) })

	mock := &mockUserInviteClient{
		getInviteResp: &client.GetInviteResponse{Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour)},
	}
	withGlobalConfig(t, newUserInviteTestConfig("text", mock))

	if err := userInviteRedeemCmd.Flags().Set("method", "piv"); err != nil {
		t.Fatalf("set method: %v", err)
	}
	if err := userInviteRedeemCmd.Flags().Set("tenant-id", "acme"); err != nil {
		t.Fatalf("set tenant-id: %v", err)
	}

	code := captureExit(t, func() {
		userInviteRedeemCmd.Run(userInviteRedeemCmd, []string{"b64url-secret"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 with --method piv and no --piv-cert-file, got %d", code)
	}
	if mock.gotActivatePIV != nil {
		t.Error("ActivateInvitePIV must not be called without --piv-cert-file")
	}
}

func TestUserInviteRedeemCmd_InvalidMethod(t *testing.T) {
	resetCmdFlags(t, userInviteRedeemCmd)
	t.Cleanup(func() { resetCmdFlags(t, userInviteRedeemCmd) })
	withGlobalConfig(t, newUserInviteTestConfig("text", &mockUserInviteClient{}))

	if err := userInviteRedeemCmd.Flags().Set("method", "bogus"); err != nil {
		t.Fatalf("set method: %v", err)
	}
	if err := userInviteRedeemCmd.Flags().Set("tenant-id", "acme"); err != nil {
		t.Fatalf("set tenant-id: %v", err)
	}

	code := captureExit(t, func() {
		userInviteRedeemCmd.Run(userInviteRedeemCmd, []string{"b64url-secret"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for an invalid --method, got %d", code)
	}
}

func TestUserInviteRedeemCmd_InvalidReference(t *testing.T) {
	resetCmdFlags(t, userInviteRedeemCmd)
	t.Cleanup(func() { resetCmdFlags(t, userInviteRedeemCmd) })
	withGlobalConfig(t, newUserInviteTestConfig("text", &mockUserInviteClient{}))

	// No --tenant-id and a bare token: parseInviteReference must refuse
	// before any client call is made.
	code := captureExit(t, func() {
		userInviteRedeemCmd.Run(userInviteRedeemCmd, []string{"b64url-secret"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for a bare token with no --tenant-id, got %d", code)
	}
}

var errUserInviteBoom = errors.New("boom")

func TestUserInviteRedeemCmd_GetInviteError(t *testing.T) {
	resetCmdFlags(t, userInviteRedeemCmd)
	t.Cleanup(func() { resetCmdFlags(t, userInviteRedeemCmd) })

	mock := &mockUserInviteClient{getInviteErr: errUserInviteBoom}
	withGlobalConfig(t, newUserInviteTestConfig("text", mock))
	if err := userInviteRedeemCmd.Flags().Set("tenant-id", "acme"); err != nil {
		t.Fatalf("set tenant-id: %v", err)
	}

	code := captureExit(t, func() {
		userInviteRedeemCmd.Run(userInviteRedeemCmd, []string{"b64url-secret"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 when GetInvite fails, got %d", code)
	}
}

// TestUserInviteRedeemCmd_FIDO2DeviceUnavailable exercises the default
// (--method fido2) path up to hardware-adapter construction, which fails
// fast against a nonexistent device path — see the file doc comment.
func TestUserInviteRedeemCmd_FIDO2DeviceUnavailable(t *testing.T) {
	resetCmdFlags(t, userInviteRedeemCmd)
	t.Cleanup(func() { resetCmdFlags(t, userInviteRedeemCmd) })

	mock := &mockUserInviteClient{
		getInviteResp: &client.GetInviteResponse{Email: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour)},
	}
	withGlobalConfig(t, newUserInviteTestConfig("text", mock))

	if err := userInviteRedeemCmd.Flags().Set("tenant-id", "acme"); err != nil {
		t.Fatalf("set tenant-id: %v", err)
	}
	if err := userInviteRedeemCmd.Flags().Set("device", "/nonexistent/fido2-device"); err != nil {
		t.Fatalf("set device: %v", err)
	}
	if err := userInviteRedeemCmd.Flags().Set(originFlag, "https://kms.example.com"); err != nil {
		t.Fatalf("set origin: %v", err)
	}

	code := captureExit(t, func() {
		userInviteRedeemCmd.Run(userInviteRedeemCmd, []string{"b64url-secret"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 against a nonexistent FIDO2 device, got %d", code)
	}
	if mock.getInviteResp == nil {
		t.Fatal("test setup error: getInviteResp must be set")
	}
}

// containsAll reports whether s contains every substring in want.
func containsAll(s string, want ...string) bool {
	for _, w := range want {
		if !strings.Contains(s, w) {
			return false
		}
	}
	return true
}
