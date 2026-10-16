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
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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

	// Captured requests. The mocks used to discard them, so NO test could
	// observe which identifier a ceremony was driven with — which is how
	// BeginRegistration came to be called with the username while the service
	// resolves by email (go-xkms #190). A double that throws the request away
	// cannot fail for the reason that matters.
	gotCreateUser *client.CreateUserRequest
	gotBeginReg   *client.BeginRegistrationRequest

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

func (m *mockUserClient) CreateUser(_ context.Context, req *client.CreateUserRequest) (*client.GetUserResponse, error) {
	m.gotCreateUser = req
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

func (m *mockUserClient) BeginRegistration(_ context.Context, req *client.BeginRegistrationRequest) (*client.BeginRegistrationResponse, error) {
	m.gotBeginReg = req
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
// protocol.CredentialCreation, usable anywhere a test needs registration
// options an authenticator adapter can parse.
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
	// The canonical login key is required; these tests exercise the paths BEYOND
	// that guard, so they supply one. TestUserRegisterCmd_EmailRequired covers
	// its absence.
	cmd.Flags().String("email", "alice@example.com", "")
	cmd.Flags().String("display-name", "", "")
	cmd.Flags().String("role", "", "")
	cmd.Flags().String("rp-id", "go-xkms", "")
	cmd.Flags().String("rp-name", "Go xKMS", "")
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "/nonexistent/fido2-device", "")
	cmd.Flags().Bool("user-verification", false, "")
	// These tests run over no http(s) --server, so the origin is supplied;
	// TestResolveWebAuthnOrigin covers its derivation and absence.
	cmd.Flags().String(originFlag, "https://kms.example.com", "")
	addPINFlags(cmd)
	return cmd
}

func newUserLoginCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "login"}
	cmd.Flags().Duration("timeout", 30*time.Second, "")
	cmd.Flags().String("device", "/nonexistent/fido2-device", "")
	cmd.Flags().Bool("user-verification", false, "")
	// These tests run over no http(s) --server, so the origin is supplied;
	// TestResolveWebAuthnOrigin covers its derivation and absence.
	cmd.Flags().String(originFlag, "https://kms.example.com", "")
	addPINFlags(cmd)
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

func TestUserRegisterCmd_CustomRolePassesThrough(t *testing.T) {
	mock := &mockUserClient{
		listUsersResp: &transport.ListUsersResponse{Users: []transport.UserInfo{{Username: "existing", Roles: []string{qrdbsdk.RoleNameAdmin}}}},
	}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	cmd := newUserRegisterCmd()
	if err := cmd.Flags().Set("role", "release-signer"); err != nil {
		t.Fatalf("set role: %v", err)
	}
	code := captureExit(t, func() {
		userRegisterCmd.Run(cmd, []string{"alice"})
	})
	if code != -1 {
		t.Fatalf("expected success (no exit) for a custom role, got exit code %d", code)
	}
	if mock.gotCreateUser == nil || mock.gotCreateUser.Role != "release-signer" {
		t.Fatalf("CreateUser role = %+v, want %q", mock.gotCreateUser, "release-signer")
	}
}

func TestUserRegisterCmd_RoleRefusedByServer(t *testing.T) {
	mock := &mockUserClient{
		listUsersResp: &transport.ListUsersResponse{Users: []transport.UserInfo{{Username: "existing", Roles: []string{qrdbsdk.RoleNameAdmin}}}},
		createUserErr: errors.New("unknown role"),
	}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	cmd := newUserRegisterCmd()
	if err := cmd.Flags().Set("role", "not-a-real-role"); err != nil {
		t.Fatalf("set role: %v", err)
	}
	code := captureExit(t, func() {
		userRegisterCmd.Run(cmd, []string{"alice"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1 when the server refuses the role, got %d", code)
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

// TestUserRegisterCmd_FirstUserCreatesInvitedAccount is the go-xkms#1294
// part B regression guard: userRegisterCmd creates the account and stops —
// it no longer drives a local FIDO2 ceremony inline (enrolling the first
// user's own passkey is authorized by the invitation CreateUser mints, not
// by having just created the account), so it succeeds off CreateUser alone,
// with no FIDO2 device involved.
func TestUserRegisterCmd_FirstUserCreatesInvitedAccount(t *testing.T) {
	mock := &mockUserClient{
		listUsersResp: &transport.ListUsersResponse{Users: nil},
	}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	code := captureExit(t, func() {
		userRegisterCmd.Run(newUserRegisterCmd(), []string{"alice"})
	})
	if code != -1 {
		t.Errorf("expected success (no exit), got exit code %d", code)
	}
	if mock.gotCreateUser == nil {
		t.Fatal("expected CreateUser to be called")
	}
	if mock.gotCreateUser.Role != qrdbsdk.RoleNameAdmin {
		t.Errorf("the first user must be created admin, got role %q", mock.gotCreateUser.Role)
	}
}

func TestUserRegisterCmd_CreateUserError(t *testing.T) {
	mock := &mockUserClient{
		listUsersResp: &transport.ListUsersResponse{Users: []transport.UserInfo{{Username: "existing", Roles: []string{"admin"}}}},
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

// TestUserRegisterCmd_RequestedRoleJSON pins that a later user gets the role
// asked for, and that JSON output reports the pending account.
func TestUserRegisterCmd_RequestedRoleJSON(t *testing.T) {
	mock := &mockUserClient{
		listUsersResp: &transport.ListUsersResponse{Users: []transport.UserInfo{{Username: "existing", Roles: []string{"admin"}}}},
	}
	withGlobalConfig(t, newUserTestConfig("json", mock))

	cmd := newUserRegisterCmd()
	if err := cmd.Flags().Set("role", qrdbsdk.RoleNameOperator); err != nil {
		t.Fatalf("set role: %v", err)
	}
	code := -1
	out := captureStdout(t, func() {
		code = captureExit(t, func() { userRegisterCmd.Run(cmd, []string{"alice"}) })
	})
	if code != -1 {
		t.Fatalf("expected success (no exit), got exit code %d", code)
	}
	if mock.gotCreateUser == nil || mock.gotCreateUser.Role != qrdbsdk.RoleNameOperator {
		t.Fatalf("CreateUser role = %+v, want %q", mock.gotCreateUser, qrdbsdk.RoleNameOperator)
	}
	got := lastJSONObject(t, out)
	if got["role"] != qrdbsdk.RoleNameOperator || got["first_user"] != false || got["pending"] != true || got["display_name"] != "alice" {
		t.Errorf("JSON result = %v", got)
	}
}

// ---------------------------------------------------------------------------
// userLoginCmd
// ---------------------------------------------------------------------------

// The login tests below pass an email: the argument is the login key, and a
// username is refused before any of the paths they exercise.

func TestUserLoginCmd_CreateClientError(t *testing.T) {
	withGlobalConfig(t, newUserErrorConfig("text"))
	runUserLoginExpectingFailure(t, ErrCreateClientFailed)
}

func TestUserLoginCmd_ConnectError(t *testing.T) {
	mock := &mockUserClient{connectErr: errors.New("connect refused")}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	runUserLoginExpectingFailure(t, ErrConnectFailed)
}

func TestUserLoginCmd_BeginAuthenticationError(t *testing.T) {
	mock := &mockUserClient{beginAuthErr: errors.New("no such user")}
	withGlobalConfig(t, newUserTestConfig("text", mock))
	runUserLoginExpectingFailure(t, ErrBeginAuthenticationFailed)
}

// runUserLoginExpectingFailure logs in as alice@example.com and requires
// the command to exit 1 reporting sentinel.
func runUserLoginExpectingFailure(t *testing.T, sentinel error) string {
	t.Helper()
	code, stderr := runKeyExt(t, func() {
		userLoginCmd.Run(newUserLoginCmd(), []string{"alice@example.com"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if sentinel != nil && !strings.Contains(stderr, sentinel.Error()) {
		t.Errorf("stderr %q does not report %q", stderr, sentinel)
	}
	return stderr
}

// newUserLoginConfig serves mock and attaches no authenticator, so the
// ceremony never reaches the host's HID devices.
func newUserLoginConfig(mock *mockUserClient) *Config {
	cfg := newUserTestConfig("json", mock)
	cfg.HIDEnumerator = noHIDEnumerator{}
	return cfg
}

func TestUserLoginCmd_BadOptionsJSON(t *testing.T) {
	mock := &mockUserClient{
		beginAuthResp: &client.BeginAuthenticationResponse{SessionID: "s", OptionsJSON: "not-json"},
	}
	withGlobalConfig(t, newUserLoginConfig(mock))
	runUserLoginExpectingFailure(t, nil)
}

func TestUserLoginCmd_ReachesFIDO2Device(t *testing.T) {
	mock := &mockUserClient{
		beginAuthResp: &client.BeginAuthenticationResponse{
			SessionID:   "sess-1",
			OptionsJSON: validAuthenticationOptionsJSON(),
		},
	}
	withGlobalConfig(t, newUserLoginConfig(mock))

	// No authenticator is attached, so the ceremony fails past the server.
	stderr := runUserLoginExpectingFailure(t, nil)
	if strings.Contains(stderr, ErrBeginAuthenticationFailed.Error()) {
		t.Errorf("the ceremony must get past the server, got %q", stderr)
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
			{Username: "alice", DisplayName: "Alice", Roles: []string{"admin"}, Enabled: true, CreatedAt: last, LastLogin: &last},
			{Username: "bob", DisplayName: "Bob", Roles: []string{"user"}, Enabled: false, CreatedAt: last},
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
			{Username: "alice", DisplayName: "Alice", Roles: []string{"admin"}, Enabled: true, CreatedAt: last, LastLogin: &last},
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
			Username: "alice", DisplayName: "Alice", Roles: []string{"admin"}, Enabled: true, CreatedAt: last, LastLogin: &last,
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
		Users: []transport.UserInfo{{Username: "alice", Roles: []string{"admin"}}, {Username: "bob", Roles: []string{"user"}}},
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
		Users: []transport.UserInfo{{Username: "alice", Roles: []string{"admin"}}},
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

// Registration must refuse to run without the canonical login key rather than
// creating an account nobody can enrol against.
func TestUserRegisterCmd_EmailRequired(t *testing.T) {
	mock := &mockUserClient{}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	cmd := newUserRegisterCmd()
	if err := cmd.Flags().Set("email", ""); err != nil {
		t.Fatalf("set email: %v", err)
	}
	code := captureExit(t, func() {
		userRegisterCmd.Run(cmd, []string{"alice"})
	})
	// Assert the EXACT code. captureExit returns -1 when the command never
	// exits at all, so "code != 0" passed while the command was printing an
	// error and returning normally — every script saw a rejected registration
	// as success. This is the second time in this PR that asserting "not the
	// good value" hid the actual behaviour (Codex, go-xkms #190).
	if code != 1 {
		t.Errorf("registration without --email must exit 1, got %d", code)
	}
}

// The ceremony must be driven by the EMAIL, not the username, when they differ.
//
// TestUserRegisterCmd_CreateUserSendsUsernameAndEmail pins the two
// identifiers CreateUser sends: the username the operator named and the
// canonical email login key, as distinct fields (Codex, go-xkms #190 —
// conflating them, or sending only one, left the account unreachable by
// WebAuthn). go-xkms#1294 part B removed the inline BeginRegistration call
// this test used to also cover; that ceremony is now reached only through
// invite redemption (BeginInviteRegistration), tested in pkg/xkms.
func TestUserRegisterCmd_CreateUserSendsUsernameAndEmail(t *testing.T) {
	mock := &mockUserClient{
		listUsersResp: &transport.ListUsersResponse{Users: nil},
	}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	cmd := newUserRegisterCmd()
	if err := cmd.Flags().Set("email", "alice@example.com"); err != nil {
		t.Fatalf("set email: %v", err)
	}

	captureExit(t, func() {
		userRegisterCmd.Run(cmd, []string{"alice"})
	})

	if mock.gotCreateUser == nil {
		t.Fatal("CreateUser was never called")
	}
	if mock.gotCreateUser.Username != "alice" {
		t.Errorf("CreateUser username = %q, want %q", mock.gotCreateUser.Username, "alice")
	}
	if mock.gotCreateUser.Email != "alice@example.com" {
		t.Errorf("CreateUser email = %q, want %q", mock.gotCreateUser.Email, "alice@example.com")
	}
}

// JSON output must carry the canonical login key.
//
// The CLI builds its JSON by hand rather than marshalling UserInfo, so it does
// NOT inherit the struct tag — I claimed in a commit message that it did,
// without checking, and it was false. Machine-readable output was therefore
// missing the one field a scripted WebAuthn login needs, while the table beside
// it showed the value (Codex, go-xkms #190).
func TestUserListCmd_JSONCarriesEmail(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mock := &mockUserClient{listUsersResp: &transport.ListUsersResponse{
		Users: []transport.UserInfo{
			{Username: "alice", Email: "alice@example.com", DisplayName: "Alice", Roles: []string{"admin"}, Enabled: true, CreatedAt: created},
			// A certificate-authenticated principal legitimately has none; a
			// script must be able to tell the two apart.
			{Username: "root", Email: "", DisplayName: "Root", Roles: []string{"admin"}, Enabled: true, CreatedAt: created},
		},
	}}
	withGlobalConfig(t, newUserTestConfig("json", mock))

	out := captureStdout(t, func() {
		userListCmd.Run(&cobra.Command{}, nil)
	})

	var payload struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(payload.Users) != 2 {
		t.Fatalf("got %d users, want 2", len(payload.Users))
	}
	got, ok := payload.Users[0]["email"]
	if !ok {
		t.Fatalf("JSON output omits the canonical login key entirely: %v", payload.Users[0])
	}
	if got != "alice@example.com" {
		t.Errorf("email = %v, want alice@example.com", got)
	}
	if _, ok := payload.Users[1]["email"]; !ok {
		t.Error("the email key must be present even when empty, so a script can distinguish " +
			"a cert-authenticated admin from a missing field")
	}
}
