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

// user_test.go exercises the "xkmsctl user" command tree (register, login,
// list, get, delete, disable, enable, status, credentials). The FIDO2
// hardware ceremony itself (register/login) is driven through a
// nonexistent --device path so the local authenticator lookup fails fast
// and deterministically without touching any real hardware; the tests
// still cover the client-creation, connect, and server-ceremony branches
// that are exercised before the local device is ever opened.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

// mockUserClient implements client.Client for the user.go command tree by
// embedding the full-surface mockBackendsClient and overriding only the
// methods exercised by user.go.
type mockUserClient struct {
	mockBackendsClient

	connectErr error

	createUserResp *client.GetUserResponse
	createUserErr  error

	listUsersResp *transport.ListUsersResponse
	listUsersErr  error

	getUserResp *transport.GetUserResponse
	getUserErr  error

	deleteUserErr  error
	enableUserErr  error
	disableUserErr error

	listCredsResp *transport.ListUserCredentialsResponse
	listCredsErr  error

	beginRegResp *client.BeginRegistrationResponse
	beginRegErr  error

	beginAuthResp *client.BeginAuthenticationResponse
	beginAuthErr  error
}

func (m *mockUserClient) Connect(context.Context) error { return m.connectErr }

func (m *mockUserClient) CreateUser(context.Context, *client.CreateUserRequest) (*client.GetUserResponse, error) {
	return m.createUserResp, m.createUserErr
}

func (m *mockUserClient) ListUsers(context.Context, ...transport.ListOption) (*transport.ListUsersResponse, error) {
	return m.listUsersResp, m.listUsersErr
}

func (m *mockUserClient) GetUser(context.Context, string) (*transport.GetUserResponse, error) {
	return m.getUserResp, m.getUserErr
}

func (m *mockUserClient) DeleteUser(context.Context, string) error  { return m.deleteUserErr }
func (m *mockUserClient) EnableUser(context.Context, string) error  { return m.enableUserErr }
func (m *mockUserClient) DisableUser(context.Context, string) error { return m.disableUserErr }

func (m *mockUserClient) ListUserCredentials(context.Context, string) (*transport.ListUserCredentialsResponse, error) {
	return m.listCredsResp, m.listCredsErr
}

func (m *mockUserClient) BeginRegistration(context.Context, *client.BeginRegistrationRequest) (*client.BeginRegistrationResponse, error) {
	return m.beginRegResp, m.beginRegErr
}

func (m *mockUserClient) BeginAuthentication(context.Context, *client.BeginAuthenticationRequest) (*client.BeginAuthenticationResponse, error) {
	return m.beginAuthResp, m.beginAuthErr
}

// newUserTestConfig wires globalConfig's ClientFactory to return mock.
func newUserTestConfig(format string, mock *mockUserClient) *Config {
	return &Config{
		OutputFormat: format,
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	}
}

// newUserErrorConfig wires globalConfig's ClientFactory to always fail.
func newUserErrorConfig(format string) *Config {
	return &Config{
		OutputFormat: format,
		ClientFactory: func(*Config) (client.Client, error) {
			return nil, errors.New("client factory failed")
		},
	}
}

// b64url is a small helper for constructing WebAuthn JSON option payloads.
func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// validRegistrationOptionsJSON returns a minimal, valid JSON encoding of a
// protocol.CredentialCreation so json.Unmarshal in webAuthnRegistration
// succeeds and execution proceeds to the local FIDO2 device lookup.
func validRegistrationOptionsJSON() string {
	return `{"publicKey":{"rp":{"id":"xkms.example.com","name":"xkms"},` +
		`"user":{"id":"` + b64url("user-1") + `","name":"alice","displayName":"Alice"},` +
		`"challenge":"` + b64url("challenge-data") + `",` +
		`"pubKeyCredParams":[{"type":"public-key","alg":-7}]}}`
}

// validAuthenticationOptionsJSON returns a minimal, valid JSON encoding of a
// protocol.CredentialAssertion.
func validAuthenticationOptionsJSON() string {
	return `{"publicKey":{"challenge":"` + b64url("challenge-data") + `",` +
		`"rpId":"xkms.example.com",` +
		`"allowCredentials":[{"type":"public-key","id":"` + b64url("cred-1") + `"}]}}`
}

// newUserRegisterCmd builds a standalone copy of userRegisterCmd's flag
// surface so each test has an isolated FlagSet, while still exercising the
// real Run closure.
func newUserRegisterCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "register"}
	cmd.Flags().String("display-name", "", "")
	cmd.Flags().String("role", "", "")
	cmd.Flags().String("rp-id", "go-xkms", "")
	cmd.Flags().String("rp-name", "Go xKMS", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "/nonexistent/fido2-device", "")
	cmd.Flags().Bool("user-verification", false, "")
	return cmd
}

func newUserLoginCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "login"}
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "/nonexistent/fido2-device", "")
	cmd.Flags().Bool("user-verification", false, "")
	return cmd
}

// ---------------------------------------------------------------------------
// userRegisterCmd
// ---------------------------------------------------------------------------

func TestUserRegisterCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))

	code := captureExit(t, func() {
		userRegisterCmd.Run(newUserRegisterCmd(), []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserRegisterCmd_ConnectError(t *testing.T) {
	mock := &mockUserClient{connectErr: errors.New("connect refused")}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	code := captureExit(t, func() {
		userRegisterCmd.Run(newUserRegisterCmd(), []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserRegisterCmd_InvalidRole(t *testing.T) {
	mock := &mockUserClient{}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	cmd := newUserRegisterCmd()
	_ = cmd.Flags().Set("role", "not-a-real-role")

	code := captureExit(t, func() {
		userRegisterCmd.Run(cmd, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for invalid role, got %d", code)
	}
}

func TestUserRegisterCmd_ListUsersError(t *testing.T) {
	mock := &mockUserClient{listUsersErr: errors.New("list failed")}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	code := captureExit(t, func() {
		userRegisterCmd.Run(newUserRegisterCmd(), []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserRegisterCmd_FirstUserReachesFIDO2Device(t *testing.T) {
	mock := &mockUserClient{
		listUsersResp: &transport.ListUsersResponse{Users: nil},
		beginRegResp: &client.BeginRegistrationResponse{
			SessionID:   "sess-1",
			OptionsJSON: validRegistrationOptionsJSON(),
		},
	}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	// The nonexistent --device path forces a fast, deterministic failure
	// inside webAuthnRegistration's call to handler.RegisterWebAuthn,
	// well after CreateUser/BeginRegistration/JSON-parse have all run.
	code := captureExit(t, func() {
		userRegisterCmd.Run(newUserRegisterCmd(), []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (no real FIDO2 device present), got %d", code)
	}
}

func TestUserRegisterCmd_CreateUserError(t *testing.T) {
	mock := &mockUserClient{
		listUsersResp: &transport.ListUsersResponse{Users: []transport.UserInfo{{Username: "existing", Role: "admin"}}},
		createUserErr: errors.New("username exists"),
	}
	withGlobalConfig(t, newUserTestConfig("json", mock))

	code := captureExit(t, func() {
		userRegisterCmd.Run(newUserRegisterCmd(), []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// userLoginCmd
// ---------------------------------------------------------------------------

func TestUserLoginCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))

	code := captureExit(t, func() {
		userLoginCmd.Run(newUserLoginCmd(), []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserLoginCmd_BeginAuthenticationError(t *testing.T) {
	mock := &mockUserClient{beginAuthErr: errors.New("no such user")}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	code := captureExit(t, func() {
		userLoginCmd.Run(newUserLoginCmd(), []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserLoginCmd_BadOptionsJSON(t *testing.T) {
	mock := &mockUserClient{
		beginAuthResp: &client.BeginAuthenticationResponse{SessionID: "s", OptionsJSON: "not-json"},
	}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	code := captureExit(t, func() {
		userLoginCmd.Run(newUserLoginCmd(), []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserLoginCmd_ReachesFIDO2Device(t *testing.T) {
	mock := &mockUserClient{
		beginAuthResp: &client.BeginAuthenticationResponse{
			SessionID:   "sess-1",
			OptionsJSON: validAuthenticationOptionsJSON(),
		},
	}
	withGlobalConfig(t, newUserTestConfig("json", mock))

	code := captureExit(t, func() {
		userLoginCmd.Run(newUserLoginCmd(), []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 (no real FIDO2 device present), got %d", code)
	}
}

// ---------------------------------------------------------------------------
// userListCmd
// ---------------------------------------------------------------------------

func TestUserListCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		userListCmd.Run(&cobra.Command{}, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserListCmd_ListError(t *testing.T) {
	mock := &mockUserClient{listUsersErr: errors.New("boom")}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	code := captureExit(t, func() {
		userListCmd.Run(&cobra.Command{}, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserListCmd_Empty(t *testing.T) {
	mock := &mockUserClient{listUsersResp: &transport.ListUsersResponse{}}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	out := captureStdout(t, func() {
		userListCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "No users configured") {
		t.Errorf("expected empty-list message, got: %q", out)
	}
}

func TestUserListCmd_TextWithUsers(t *testing.T) {
	last := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mock := &mockUserClient{listUsersResp: &transport.ListUsersResponse{
		Users: []transport.UserInfo{
			{Username: "alice", DisplayName: "Alice", Role: "admin", Enabled: true, CreatedAt: last, LastLogin: &last},
			{Username: "bob", DisplayName: "Bob", Role: "user", Enabled: false, CreatedAt: last},
		},
	}}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	out := captureStdout(t, func() {
		userListCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "alice") || !strings.Contains(out, "bob") {
		t.Errorf("expected both users in output, got: %q", out)
	}
	if !strings.Contains(out, "Total: 2 user(s)") {
		t.Errorf("expected total count, got: %q", out)
	}
}

func TestUserListCmd_JSONWithUsers(t *testing.T) {
	last := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mock := &mockUserClient{listUsersResp: &transport.ListUsersResponse{
		Users: []transport.UserInfo{
			{Username: "alice", DisplayName: "Alice", Role: "admin", Enabled: true, CreatedAt: last, LastLogin: &last},
		},
	}}
	withGlobalConfig(t, newUserTestConfig("json", mock))

	out := captureStdout(t, func() {
		userListCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "alice") {
		t.Errorf("expected alice in JSON output, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// userGetCmd
// ---------------------------------------------------------------------------

func TestUserGetCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		userGetCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserGetCmd_GetError(t *testing.T) {
	mock := &mockUserClient{getUserErr: errors.New("not found")}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	code := captureExit(t, func() {
		userGetCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserGetCmd_TextWithCredentials(t *testing.T) {
	last := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mock := &mockUserClient{
		getUserResp: &transport.GetUserResponse{User: transport.UserInfo{
			Username: "alice", DisplayName: "Alice", Role: "admin", Enabled: true, CreatedAt: last, LastLogin: &last,
		}},
		listCredsResp: &transport.ListUserCredentialsResponse{
			Credentials: []transport.CredentialInfo{{ID: "cred-1", DisplayName: "YubiKey"}},
		},
	}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	out := captureStdout(t, func() {
		userGetCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if !strings.Contains(out, "alice") || !strings.Contains(out, "YubiKey") {
		t.Errorf("expected user + credential info, got: %q", out)
	}
}

func TestUserGetCmd_JSONCredentialListError(t *testing.T) {
	last := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mock := &mockUserClient{
		getUserResp: &transport.GetUserResponse{User: transport.UserInfo{
			Username: "alice", CreatedAt: last,
		}},
		listCredsErr: errors.New("creds unavailable"),
	}
	withGlobalConfig(t, newUserTestConfig("json", mock))

	// ListUserCredentials failing is tolerated (best-effort); the command
	// should still succeed and print the user with an empty credential list.
	out := captureStdout(t, func() {
		userGetCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if !strings.Contains(out, "alice") {
		t.Errorf("expected alice in output despite credential-list error, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// userDeleteCmd / userDisableCmd / userEnableCmd
// ---------------------------------------------------------------------------

func TestUserDeleteCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		userDeleteCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserDeleteCmd_DeleteError(t *testing.T) {
	mock := &mockUserClient{deleteUserErr: errors.New("cannot delete last admin")}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	code := captureExit(t, func() {
		userDeleteCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserDeleteCmd_SuccessText(t *testing.T) {
	mock := &mockUserClient{}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	out := captureStdout(t, func() {
		userDeleteCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if !strings.Contains(out, "deleted successfully") {
		t.Errorf("expected success message, got: %q", out)
	}
}

func TestUserDeleteCmd_SuccessJSON(t *testing.T) {
	mock := &mockUserClient{}
	withGlobalConfig(t, newUserTestConfig("json", mock))
	out := captureStdout(t, func() {
		userDeleteCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if !strings.Contains(out, "\"success\"") {
		t.Errorf("expected JSON success field, got: %q", out)
	}
}

func TestUserDisableCmd_DisableError(t *testing.T) {
	mock := &mockUserClient{disableUserErr: errors.New("boom")}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	code := captureExit(t, func() {
		userDisableCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserDisableCmd_SuccessJSON(t *testing.T) {
	mock := &mockUserClient{}
	withGlobalConfig(t, newUserTestConfig("json", mock))
	out := captureStdout(t, func() {
		userDisableCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if !strings.Contains(out, "\"enabled\": false") && !strings.Contains(out, "\"enabled\":false") {
		t.Errorf("expected enabled:false in JSON output, got: %q", out)
	}
}

func TestUserDisableCmd_SuccessText(t *testing.T) {
	mock := &mockUserClient{}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	out := captureStdout(t, func() {
		userDisableCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if !strings.Contains(out, "disabled") {
		t.Errorf("expected disabled message, got: %q", out)
	}
}

func TestUserEnableCmd_EnableError(t *testing.T) {
	mock := &mockUserClient{enableUserErr: errors.New("boom")}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	code := captureExit(t, func() {
		userEnableCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserEnableCmd_SuccessJSON(t *testing.T) {
	mock := &mockUserClient{}
	withGlobalConfig(t, newUserTestConfig("json", mock))
	out := captureStdout(t, func() {
		userEnableCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if !strings.Contains(out, "\"enabled\": true") && !strings.Contains(out, "\"enabled\":true") {
		t.Errorf("expected enabled:true in JSON output, got: %q", out)
	}
}

func TestUserEnableCmd_SuccessText(t *testing.T) {
	mock := &mockUserClient{}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	out := captureStdout(t, func() {
		userEnableCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if !strings.Contains(out, "enabled") {
		t.Errorf("expected enabled message, got: %q", out)
	}
}

func TestUserDeleteCmd_ConnectError(t *testing.T) {
	mock := &mockUserClient{connectErr: errors.New("refused")}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	code := captureExit(t, func() {
		userDeleteCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

// ---------------------------------------------------------------------------
// userStatusCmd
// ---------------------------------------------------------------------------

func TestUserStatusCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		userStatusCmd.Run(&cobra.Command{}, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserStatusCmd_ListError(t *testing.T) {
	mock := &mockUserClient{listUsersErr: errors.New("boom")}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	code := captureExit(t, func() {
		userStatusCmd.Run(&cobra.Command{}, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserStatusCmd_NotConfiguredText(t *testing.T) {
	mock := &mockUserClient{listUsersResp: &transport.ListUsersResponse{}}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	out := captureStdout(t, func() {
		userStatusCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "NOT CONFIGURED") {
		t.Errorf("expected NOT CONFIGURED, got: %q", out)
	}
}

func TestUserStatusCmd_ConfiguredText(t *testing.T) {
	mock := &mockUserClient{listUsersResp: &transport.ListUsersResponse{
		Users: []transport.UserInfo{{Username: "alice", Role: "admin"}, {Username: "bob", Role: "user"}},
	}}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	out := captureStdout(t, func() {
		userStatusCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "CONFIGURED") {
		t.Errorf("expected CONFIGURED, got: %q", out)
	}
	if !strings.Contains(out, "Admin accounts: 1") {
		t.Errorf("expected admin count, got: %q", out)
	}
}

func TestUserStatusCmd_JSONNotConfigured(t *testing.T) {
	mock := &mockUserClient{listUsersResp: &transport.ListUsersResponse{}}
	withGlobalConfig(t, newUserTestConfig("json", mock))
	out := captureStdout(t, func() {
		userStatusCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "requires_setup") {
		t.Errorf("expected requires_setup field, got: %q", out)
	}
}

func TestUserStatusCmd_JSONConfigured(t *testing.T) {
	mock := &mockUserClient{listUsersResp: &transport.ListUsersResponse{
		Users: []transport.UserInfo{{Username: "alice", Role: "admin"}},
	}}
	withGlobalConfig(t, newUserTestConfig("json", mock))
	out := captureStdout(t, func() {
		userStatusCmd.Run(&cobra.Command{}, nil)
	})
	if !strings.Contains(out, "System is configured and ready") {
		t.Errorf("expected configured message, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// userCredentialConfigCmd
// ---------------------------------------------------------------------------

func TestUserCredentialConfigCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	code := captureExit(t, func() {
		userCredentialConfigCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserCredentialConfigCmd_ListError(t *testing.T) {
	mock := &mockUserClient{listCredsErr: errors.New("boom")}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	code := captureExit(t, func() {
		userCredentialConfigCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestUserCredentialConfigCmd_Empty(t *testing.T) {
	mock := &mockUserClient{listCredsResp: &transport.ListUserCredentialsResponse{}}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	code := captureExit(t, func() {
		userCredentialConfigCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for no credentials, got %d", code)
	}
}

func TestUserCredentialConfigCmd_TextWithCreds(t *testing.T) {
	mock := &mockUserClient{listCredsResp: &transport.ListUserCredentialsResponse{
		Credentials: []transport.CredentialInfo{
			{ID: "cred-1", DisplayName: "YubiKey 5"},
			{ID: "cred-2"},
		},
	}}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	out := captureStdout(t, func() {
		userCredentialConfigCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if !strings.Contains(out, "YubiKey 5") || !strings.Contains(out, "cred-2") {
		t.Errorf("expected both credentials in output, got: %q", out)
	}
}

func TestUserCredentialConfigCmd_JSONWithCreds(t *testing.T) {
	mock := &mockUserClient{listCredsResp: &transport.ListUserCredentialsResponse{
		Credentials: []transport.CredentialInfo{{ID: "cred-1", DisplayName: "YubiKey 5"}},
	}}
	withGlobalConfig(t, newUserTestConfig("json", mock))
	out := captureStdout(t, func() {
		userCredentialConfigCmd.Run(&cobra.Command{}, []string{"alice"})
	})
	if !strings.Contains(out, "cred-1") {
		t.Errorf("expected credential id in JSON output, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// Registration / metadata
// ---------------------------------------------------------------------------

func TestUserCmd_SubcommandsRegistered(t *testing.T) {
	found := map[string]bool{}
	for _, c := range userCmd.Commands() {
		found[c.Name()] = true
	}
	for _, name := range []string{"register", "login", "list", "get", "delete", "disable", "enable", "status", "credentials"} {
		if !found[name] {
			t.Errorf("expected user subcommand %q to be registered", name)
		}
	}
}
