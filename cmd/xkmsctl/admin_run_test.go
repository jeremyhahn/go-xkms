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

// admin_run_test.go exercises the "xkmsctl admin" command tree's Run/RunE
// closures (list, get, delete, disable, enable, status, create dispatch),
// which are anonymous cobra closures not otherwise reached by the
// admin_test.go metadata tests. As with user_test.go, FIDO2 enrollment is
// driven through a nonexistent --device path so the local authenticator
// lookup fails fast and deterministically without touching real hardware.
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	webauthnclient "github.com/jeremyhahn/go-xkms/sdk/go/webauthnclient"
	"github.com/spf13/cobra"
)

// mockAdminCRUDClient implements client.Client for the adminList/Get/Delete/
// Disable/Enable/Status command tree.
type mockAdminCRUDClient struct {
	mockBackendsClient

	connectErr error

	listUsersResp *transport.ListUsersResponse
	listUsersErr  error

	getUserResp *transport.GetUserResponse
	getUserErr  error

	listCredsResp *transport.ListUserCredentialsResponse
	listCredsErr  error

	deleteUserErr  error
	enableUserErr  error
	disableUserErr error
}

func (m *mockAdminCRUDClient) Connect(context.Context) error { return m.connectErr }

func (m *mockAdminCRUDClient) ListUsers(context.Context, ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return m.listUsersResp, m.listUsersErr
}

func (m *mockAdminCRUDClient) GetUser(context.Context, string) (*transport.GetUserResponse, error) {
	return m.getUserResp, m.getUserErr
}

func (m *mockAdminCRUDClient) ListUserCredentials(context.Context, string) (*transport.ListUserCredentialsResponse, error) {
	return m.listCredsResp, m.listCredsErr
}

func (m *mockAdminCRUDClient) DeleteUser(context.Context, string) error  { return m.deleteUserErr }
func (m *mockAdminCRUDClient) EnableUser(context.Context, string) error  { return m.enableUserErr }
func (m *mockAdminCRUDClient) DisableUser(context.Context, string) error { return m.disableUserErr }

func newAdminCRUDConfig(format string, mock *mockAdminCRUDClient) *Config {
	return &Config{
		OutputFormat: format,
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

// ---------------------------------------------------------------------------
// adminListCmd
// ---------------------------------------------------------------------------

func TestAdminListCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		adminListCmd.Run(&cobra.Command{}, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestAdminListCmd_ListError(t *testing.T) {
	mock := &mockAdminCRUDClient{listUsersErr: errors.New("boom")}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	code := captureExit(t, func() {
		adminListCmd.Run(&cobra.Command{}, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestAdminListCmd_NoAdmins(t *testing.T) {
	mock := &mockAdminCRUDClient{listUsersResp: &transport.ListUsersResponse{
		Users: []transport.UserInfo{{Username: "bob", Role: "user"}},
	}}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	out := captureStdout(t, func() {
		adminListCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "No administrator accounts configured") {
		t.Errorf("expected no-admins message, got: %q", out)
	}
}

func TestAdminListCmd_TextWithAdmins(t *testing.T) {
	last := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mock := &mockAdminCRUDClient{listUsersResp: &transport.ListUsersResponse{
		Users: []transport.UserInfo{
			{Username: "root", DisplayName: "Root", Role: "admin", Enabled: true, CreatedAt: last, LastLogin: &last},
			{Username: "bob", Role: "user"},
		},
	}}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	out := captureStdout(t, func() {
		adminListCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "root") || strings.Contains(out, "\nbob") {
		t.Errorf("expected only admin accounts listed, got: %q", out)
	}
	if !strings.Contains(out, "Total: 1 administrator(s)") {
		t.Errorf("expected total count, got: %q", out)
	}
}

func TestAdminListCmd_JSONWithAdmins(t *testing.T) {
	last := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mock := &mockAdminCRUDClient{listUsersResp: &transport.ListUsersResponse{
		Users: []transport.UserInfo{{Username: "root", Role: "admin", CreatedAt: last, LastLogin: &last}},
	}}
	withGlobalConfig(t, newAdminCRUDConfig("json", mock))
	out := captureStdout(t, func() {
		adminListCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "root") {
		t.Errorf("expected root in JSON output, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// adminGetCmd
// ---------------------------------------------------------------------------

func TestAdminGetCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		adminGetCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestAdminGetCmd_ConnectError(t *testing.T) {
	mock := &mockAdminCRUDClient{connectErr: errors.New("refused")}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	code := captureExit(t, func() {
		adminGetCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestAdminGetCmd_GetError(t *testing.T) {
	mock := &mockAdminCRUDClient{getUserErr: errors.New("not found")}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	code := captureExit(t, func() {
		adminGetCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestAdminGetCmd_TextWithCredentials(t *testing.T) {
	last := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mock := &mockAdminCRUDClient{
		getUserResp: &transport.GetUserResponse{User: transport.UserInfo{
			Username: "root", DisplayName: "Root", Role: "admin", Enabled: true, CreatedAt: last, LastLogin: &last,
		}},
		listCredsResp: &transport.ListUserCredentialsResponse{
			Credentials: []transport.CredentialInfo{{ID: "cred-1"}},
		},
	}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	out := captureStdout(t, func() {
		adminGetCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if !strings.Contains(out, "root") || !strings.Contains(out, "cred-1") {
		t.Errorf("expected admin + credential info, got: %q", out)
	}
}

func TestAdminGetCmd_JSONCredentialListError(t *testing.T) {
	last := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mock := &mockAdminCRUDClient{
		getUserResp:  &transport.GetUserResponse{User: transport.UserInfo{Username: "root", CreatedAt: last}},
		listCredsErr: errors.New("unavailable"),
	}
	withGlobalConfig(t, newAdminCRUDConfig("json", mock))
	out := captureStdout(t, func() {
		adminGetCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if !strings.Contains(out, "root") {
		t.Errorf("expected root in output despite credential-list error, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// adminDeleteCmd / adminDisableCmd / adminEnableCmd
// ---------------------------------------------------------------------------

func TestAdminDeleteCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		adminDeleteCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestAdminDeleteCmd_DeleteError(t *testing.T) {
	mock := &mockAdminCRUDClient{deleteUserErr: errors.New("cannot delete last admin")}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	code := captureExit(t, func() {
		adminDeleteCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestAdminDeleteCmd_SuccessText(t *testing.T) {
	mock := &mockAdminCRUDClient{}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	out := captureStdout(t, func() {
		adminDeleteCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if !strings.Contains(out, "deleted successfully") {
		t.Errorf("expected success message, got: %q", out)
	}
}

func TestAdminDeleteCmd_SuccessJSON(t *testing.T) {
	mock := &mockAdminCRUDClient{}
	withGlobalConfig(t, newAdminCRUDConfig("json", mock))
	out := captureStdout(t, func() {
		adminDeleteCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if !strings.Contains(out, "\"success\"") {
		t.Errorf("expected success field, got: %q", out)
	}
}

func TestAdminDisableCmd_DisableError(t *testing.T) {
	mock := &mockAdminCRUDClient{disableUserErr: errors.New("boom")}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	code := captureExit(t, func() {
		adminDisableCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestAdminDisableCmd_SuccessText(t *testing.T) {
	mock := &mockAdminCRUDClient{}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	out := captureStdout(t, func() {
		adminDisableCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if !strings.Contains(out, "disabled") {
		t.Errorf("expected disabled message, got: %q", out)
	}
}

func TestAdminDisableCmd_SuccessJSON(t *testing.T) {
	mock := &mockAdminCRUDClient{}
	withGlobalConfig(t, newAdminCRUDConfig("json", mock))
	out := captureStdout(t, func() {
		adminDisableCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if !strings.Contains(out, "\"enabled\"") {
		t.Errorf("expected enabled field, got: %q", out)
	}
}

func TestAdminEnableCmd_EnableError(t *testing.T) {
	mock := &mockAdminCRUDClient{enableUserErr: errors.New("boom")}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	code := captureExit(t, func() {
		adminEnableCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestAdminEnableCmd_SuccessText(t *testing.T) {
	mock := &mockAdminCRUDClient{}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	out := captureStdout(t, func() {
		adminEnableCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if !strings.Contains(out, "enabled") {
		t.Errorf("expected enabled message, got: %q", out)
	}
}

func TestAdminEnableCmd_SuccessJSON(t *testing.T) {
	mock := &mockAdminCRUDClient{}
	withGlobalConfig(t, newAdminCRUDConfig("json", mock))
	out := captureStdout(t, func() {
		adminEnableCmd.Run(&cobra.Command{}, []string{"root"})
	})
	if !strings.Contains(out, "\"enabled\"") {
		t.Errorf("expected enabled field, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// adminStatusCmd
// ---------------------------------------------------------------------------

func TestAdminStatusCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		adminStatusCmd.Run(&cobra.Command{}, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestAdminStatusCmd_ListError(t *testing.T) {
	mock := &mockAdminCRUDClient{listUsersErr: errors.New("boom")}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	code := captureExit(t, func() {
		adminStatusCmd.Run(&cobra.Command{}, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestAdminStatusCmd_NotConfiguredText(t *testing.T) {
	mock := &mockAdminCRUDClient{listUsersResp: &transport.ListUsersResponse{}}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	out := captureStdout(t, func() {
		adminStatusCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "NOT CONFIGURED") {
		t.Errorf("expected NOT CONFIGURED, got: %q", out)
	}
}

func TestAdminStatusCmd_ConfiguredText(t *testing.T) {
	mock := &mockAdminCRUDClient{listUsersResp: &transport.ListUsersResponse{
		Users: []transport.UserInfo{{Username: "root", Role: "admin"}},
	}}
	withGlobalConfig(t, newAdminCRUDConfig("text", mock))
	out := captureStdout(t, func() {
		adminStatusCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "CONFIGURED") {
		t.Errorf("expected CONFIGURED, got: %q", out)
	}
}

func TestAdminStatusCmd_JSONNotConfigured(t *testing.T) {
	mock := &mockAdminCRUDClient{listUsersResp: &transport.ListUsersResponse{}}
	withGlobalConfig(t, newAdminCRUDConfig("json", mock))
	out := captureStdout(t, func() {
		adminStatusCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "requires_setup") {
		t.Errorf("expected requires_setup, got: %q", out)
	}
}

func TestAdminStatusCmd_JSONConfigured(t *testing.T) {
	mock := &mockAdminCRUDClient{listUsersResp: &transport.ListUsersResponse{
		Users: []transport.UserInfo{{Username: "root", Role: "admin"}},
	}}
	withGlobalConfig(t, newAdminCRUDConfig("json", mock))
	out := captureStdout(t, func() {
		adminStatusCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "System is configured and ready") {
		t.Errorf("expected configured message, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// adminCreateCmd.RunE dispatch + enrollFIDO2Admin depth
// ---------------------------------------------------------------------------

func newAdminCreateCmdCopy() *cobra.Command {
	cmd := &cobra.Command{Use: "create"}
	cmd.Flags().String("storage-path", "", "")
	// The fido2 method requires the canonical login key; these tests exercise
	// the paths beyond that guard. TestEnrollFIDO2Admin_EmailRequired covers it.
	cmd.Flags().String("email", "root@example.com", "")
	cmd.Flags().String("display-name", "", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "/nonexistent/fido2-device", "")
	cmd.Flags().Bool("user-verification", false, "")
	cmd.Flags().String("method", "fido2", "")
	cmd.Flags().String("cert-file", "", "")
	// These tests run over no http(s) --server, so the origin is supplied;
	// TestResolveWebAuthnOrigin covers its derivation and absence.
	cmd.Flags().String(originFlag, "https://kms.example.com", "")
	addPINFlags(cmd)
	return cmd
}

func TestAdminCreateCmd_UnsupportedMethod_RunE(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	cmd := newAdminCreateCmdCopy()
	_ = cmd.Flags().Set("method", "bluetooth")

	err := adminCreateCmd.RunE(cmd, []string{"root"})
	if !errors.Is(err, ErrUnsupportedAuthMethod) {
		t.Fatalf("want ErrUnsupportedAuthMethod, got %v", err)
	}
}

func TestAdminCreateCmd_FIDO2DispatchError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	cmd := newAdminCreateCmdCopy()

	code := captureExit(t, func() {
		_ = adminCreateCmd.RunE(cmd, []string{"root"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestAdminCreateCmd_MTLSDispatchSuccess(t *testing.T) {
	certPEM := makeSelfSignedCert(t, "root-admin")
	p := t.TempDir() + "/root.pem"
	if err := os.WriteFile(p, certPEM, 0600); err != nil {
		t.Fatal(err)
	}

	mock := &mockAdminClient{}
	withGlobalConfig(t, &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	})

	cmd := newAdminCreateCmdCopy()
	_ = cmd.Flags().Set("method", "mtls")
	_ = cmd.Flags().Set("cert-file", p)

	if err := adminCreateCmd.RunE(cmd, []string{"root"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// mockAdminClient (defined in coverage_gaps_test.go) does not override
// BeginRegistration, so give it a real one here for the FIDO2 depth test.
func (m *mockAdminClient) BeginRegistration(_ context.Context, _ *client.BeginRegistrationRequest) (*client.BeginRegistrationResponse, error) {
	return &client.BeginRegistrationResponse{SessionID: "sess-1", OptionsJSON: validRegistrationOptionsJSON()}, nil
}

func TestEnrollFIDO2Admin_ConnectError(t *testing.T) {
	mock := &mockAdminClient{connectErr: errors.New("refused")}
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
	cmd := newAdminCreateCmdCopy()
	printer := NewPrinter("text", io.Discard)

	err := enrollFIDO2Admin(cmd, "root", cfg, printer, "")
	if err == nil {
		t.Fatal("expected error when Connect fails")
	}
	if !strings.Contains(err.Error(), "failed to connect") {
		t.Errorf("error %q does not mention connect", err.Error())
	}
}

// TestEnrollFIDO2Admin_ReachesDevice drives enrollment through the mock
// client to the authenticator step, with an injected enumerator that finds no
// authenticator, so the outcome never depends on the FIDO2 devices attached
// to the host running the test. The hardware CTAP2 adapter is opened lazily,
// after CreateUser and BeginRegistration have already succeeded against the
// mock client, and fails closed at discovery.
func TestEnrollFIDO2Admin_ReachesDevice(t *testing.T) {
	mock := &mockAdminClient{}
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
		HIDEnumerator: noHIDEnumerator{},
	}
	cmd := newAdminCreateCmdCopy()
	printer := NewPrinter("text", io.Discard)

	captureStdout(t, func() {
		err := enrollFIDO2Admin(cmd, "root", cfg, printer, "")
		if !errors.Is(err, ErrCreateFIDO2HandlerFailed) {
			t.Fatalf("error = %v, want %v", err, ErrCreateFIDO2HandlerFailed)
		}
		if !errors.Is(err, webauthnclient.ErrAuthenticatorNotFound) {
			t.Errorf("error = %v, want it to wrap %v", err, webauthnclient.ErrAuthenticatorNotFound)
		}
	})
}

// FIDO2 admin enrollment must refuse to run without the canonical login key.
//
// WebAuthn resolves the account by email, so an admin enrolled without one is
// created and cannot be authenticated by anybody. The mTLS method is exempt and
// declares the absence explicitly instead — see enrollMTLSAdmin.
func TestEnrollFIDO2Admin_EmailRequired(t *testing.T) {
	mock := &mockAdminClient{}
	cfg := &Config{
		OutputFormat:  "text",
		ClientFactory: func(*Config) (client.Client, error) { return mock, nil },
	}
	cmd := newAdminCreateCmdCopy()
	if sErr := cmd.Flags().Set("email", ""); sErr != nil {
		t.Fatalf("set email: %v", sErr)
	}

	err := enrollFIDO2Admin(cmd, "root", cfg, NewPrinter("text", io.Discard), "")
	if err == nil {
		t.Fatal("fido2 admin enrollment without an email must not succeed")
	}
	if !errors.Is(err, ErrEmailRequired) {
		t.Fatalf("want ErrEmailRequired, got %v", err)
	}
}
