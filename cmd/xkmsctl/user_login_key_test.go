// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestValidateLoginKey pins what the CLI accepts as a login key: a bare
// address, trimmed; not a username, not a display-name form.
func TestValidateLoginKey(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want string
		err  error
	}{
		"bare address":      {in: "alice@example.com", want: "alice@example.com"},
		"surrounding space": {in: "  alice@example.com\n", want: "alice@example.com"},
		"username":          {in: "alice", err: ErrLoginKeyNotEmail},
		"display-name form": {in: "Alice <alice@example.com>", err: ErrLoginKeyNotEmail},
		"empty":             {in: "", err: ErrLoginKeyNotEmail},
		"two addresses":     {in: "a@x.com, b@x.com", err: ErrLoginKeyNotEmail},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := validateLoginKey(tc.in)
			if !errors.Is(err, tc.err) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if got != tc.want {
				t.Errorf("value = %q, want %q", got, tc.want)
			}
		})
	}
}

// recordingLoginClient records the login key the ceremony was begun with.
type recordingLoginClient struct {
	mockUserClient
	beginAuthCalled bool
	beginAuthEmail  string
}

func (c *recordingLoginClient) BeginAuthentication(ctx context.Context, req *client.BeginAuthenticationRequest) (*client.BeginAuthenticationResponse, error) {
	c.beginAuthCalled = true
	c.beginAuthEmail = req.Email
	return c.mockUserClient.BeginAuthentication(ctx, req)
}

func withRecordingLoginClient(t *testing.T) *recordingLoginClient {
	t.Helper()
	// The ceremony stops at the server's first answer: what is under test is
	// whether the login key reaches it, not the authenticator steps after.
	mock := &recordingLoginClient{mockUserClient: mockUserClient{beginAuthErr: errors.New("ceremony stopped by the test")}}
	withGlobalConfig(t, &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	})
	return mock
}

// TestUserLoginCmd_RejectsANonEmailBeforeTheNetwork proves a username is
// refused locally: the server resolves the account by its email, so the
// ceremony would run against nothing, and the operator's typo should not cost
// a round trip or read as a remote authentication failure.
func TestUserLoginCmd_RejectsANonEmailBeforeTheNetwork(t *testing.T) {
	mock := withRecordingLoginClient(t)

	code := captureExit(t, func() {
		userLoginCmd.Run(newUserLoginCmd(), []string{"alice"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if mock.beginAuthCalled {
		t.Error("no ceremony may be begun for a login key that is not an email")
	}
}

// TestUserLoginCmd_BeginsTheCeremonyWithAValidEmail proves a valid address
// passes the local check and reaches the server trimmed.
func TestUserLoginCmd_BeginsTheCeremonyWithAValidEmail(t *testing.T) {
	mock := withRecordingLoginClient(t)

	captureExit(t, func() {
		userLoginCmd.Run(newUserLoginCmd(), []string{"  alice@example.com "})
	})
	if !mock.beginAuthCalled {
		t.Fatal("a valid email must begin the ceremony")
	}
	if mock.beginAuthEmail != "alice@example.com" {
		t.Errorf("ceremony begun with %q, want the trimmed address", mock.beginAuthEmail)
	}
}

// TestUserRegisterCmd_RejectsANonEmailBeforeTheNetwork is the register half:
// --email is the key the account is created and enrolled under, so a
// username there is refused before anything is created server-side.
func TestUserRegisterCmd_RejectsANonEmailBeforeTheNetwork(t *testing.T) {
	mock := withRecordingLoginClient(t)

	cmd := newUserRegisterCmd()
	if err := cmd.Flags().Set("email", "alice"); err != nil {
		t.Fatal(err)
	}
	code := captureExit(t, func() {
		userRegisterCmd.Run(cmd, []string{"alice"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if mock.beginAuthCalled {
		t.Error("nothing may reach the server for a login key that is not an email")
	}
}
