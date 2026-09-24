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

// user_registration_key_test.go pins the identifier the WebAuthn registration
// ceremony resolves by. The account is created with two identifiers — a
// username and the canonical email login key — and only the email addresses
// the principal on the server: pkg/webauthn/service.go BeginRegistration takes
// (ctx, email, displayName) and resolves with GetByEmail. Sending the username
// instead worked only for as long as the two were the same string, and the
// --email flag made them differ.
package main

import (
	"context"
	"errors"
	"io"
	"testing"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	webauthnclient "github.com/jeremyhahn/go-xkms/sdk/go/webauthnclient"
)

// fakeDirectoryClient is a stateful stand-in for the server's user directory.
// It reproduces the two identity decisions the registration ceremony makes, so
// a test can observe WHICH principal the credential would be attached to:
//
//   - CreateUser stores the account under its canonical email login key,
//     alongside the separate username.
//   - BeginRegistration resolves the account by the email in the request and,
//     when the relying party allows public registration, creates one if the
//     lookup misses — mirroring pkg/webauthn/service.go lines 138-150.
//
// The second rule is why sending the wrong identifier is not merely a failed
// lookup: on an open relying party it silently mints a second principal and
// enrolls the credential there.
type fakeDirectoryClient struct {
	mockBackendsClient

	// accounts maps the canonical email login key to the username of the
	// account filed under it.
	accounts map[string]string

	// publicRegistration mirrors the relying party's open sign-up setting.
	publicRegistration bool

	// beginRegErr, when set, is the server's refusal of the ceremony. The
	// request is still recorded, so a test can assert what was rejected.
	beginRegErr error

	createUserReqs []*client.CreateUserRequest
	beginRegReqs   []*client.BeginRegistrationRequest
}

func newFakeDirectoryClient(publicRegistration bool) *fakeDirectoryClient {
	return &fakeDirectoryClient{
		accounts:           make(map[string]string),
		publicRegistration: publicRegistration,
	}
}

func (f *fakeDirectoryClient) CreateUser(_ context.Context, req *client.CreateUserRequest) (*client.GetUserResponse, error) {
	f.createUserReqs = append(f.createUserReqs, req)
	f.accounts[req.Email] = req.Username
	return &client.GetUserResponse{}, nil
}

func (f *fakeDirectoryClient) ListUsers(context.Context, ...transport.ListOption) (*transport.ListUsersResponse, error) {
	users := make([]transport.UserInfo, 0, len(f.accounts))
	for email, username := range f.accounts {
		users = append(users, transport.UserInfo{Username: username, Email: email})
	}
	return &transport.ListUsersResponse{Users: users}, nil
}

func (f *fakeDirectoryClient) BeginRegistration(_ context.Context, req *client.BeginRegistrationRequest) (*client.BeginRegistrationResponse, error) {
	f.beginRegReqs = append(f.beginRegReqs, req)

	if f.beginRegErr != nil {
		return nil, f.beginRegErr
	}

	if _, found := f.accounts[req.Email]; !found {
		if !f.publicRegistration {
			return nil, errors.New("user not found and public registration is disabled")
		}
		f.accounts[req.Email] = req.Email
	}

	return &client.BeginRegistrationResponse{
		SessionID:   "sess-1",
		OptionsJSON: validRegistrationOptionsJSON(),
	}, nil
}

// unresponsiveHIDDevice is a HID device double that enumerates as attached
// but fails every I/O call, so a ceremony driven against it fails
// deterministically at the authenticator without needing real hardware.
type unresponsiveHIDDevice struct{ path string }

func (d *unresponsiveHIDDevice) Write([]byte) (int, error) {
	return 0, errors.New("no real authenticator attached")
}
func (d *unresponsiveHIDDevice) Read([]byte) (int, error) {
	return 0, errors.New("no real authenticator attached")
}
func (d *unresponsiveHIDDevice) Close() error         { return nil }
func (d *unresponsiveHIDDevice) Path() string         { return d.path }
func (d *unresponsiveHIDDevice) ProductID() uint16    { return 0x0001 }
func (d *unresponsiveHIDDevice) VendorID() uint16     { return 0xF1D0 }
func (d *unresponsiveHIDDevice) Product() string      { return "Test Authenticator" }
func (d *unresponsiveHIDDevice) Manufacturer() string { return "xkmsctl tests" }
func (d *unresponsiveHIDDevice) SerialNumber() string { return "TEST-0001" }

// unresponsiveHIDEnumerator reports one attached, unresponsive device so
// webauthnclient.NewHardwareAdapter's discovery probe succeeds, letting the
// ceremony fail at the authenticator I/O step instead of at discovery.
type unresponsiveHIDEnumerator struct{}

func (unresponsiveHIDEnumerator) Enumerate(_, _ uint16) ([]fido2.HIDDevice, error) {
	return []fido2.HIDDevice{&unresponsiveHIDDevice{path: "/nonexistent/fido2-device"}}, nil
}

func (unresponsiveHIDEnumerator) Open(path string) (fido2.HIDDevice, error) {
	return &unresponsiveHIDDevice{path: path}, nil
}

// newDeviceLessAdapter builds the same hardware authenticator adapter the
// commands build, aimed at a device that enumerates but never responds.
// Construction succeeds and the ceremony fails deterministically at the
// authenticator, which is well after the two server calls under test have
// already been made.
func newDeviceLessAdapter(t *testing.T) webauthnclient.AuthenticatorAdapter {
	t.Helper()

	cfg := fido2.DefaultConfig
	cfg.DevicePath = "/nonexistent/fido2-device"

	adapter, err := webauthnclient.NewHardwareAdapter(&cfg, unresponsiveHIDEnumerator{})
	if err != nil {
		t.Fatalf("build hardware adapter: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })

	return adapter
}

// The ceremony must be begun against the email, not the username, whether or
// not the relying party allows public registration. Closed registration must
// find the account that was just created; open registration must enroll the
// credential on that same account rather than forking a second principal.
func TestWebAuthnRegistration_BeginsCeremonyByEmailNotUsername(t *testing.T) {
	const (
		username = "admin"
		email    = "admin@example.com"
	)

	for _, tc := range []struct {
		name               string
		publicRegistration bool
	}{
		{name: "closed registration", publicRegistration: false},
		{name: "public registration", publicRegistration: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl := newFakeDirectoryClient(tc.publicRegistration)

			_, err := webAuthnRegistration(
				context.Background(),
				cl,
				func() (webauthnclient.AuthenticatorAdapter, error) { return newDeviceLessAdapter(t), nil },
				NewPrinter("text", io.Discard),
				username, email, "Admin", string(RoleAdmin), "",
				nil,
			)

			// The ceremony can only fail at the local authenticator: reaching it
			// proves the server-side lookup resolved the account.
			if !errors.Is(err, ErrRegisterCredentialFailed) {
				t.Fatalf("want the ceremony to reach the authenticator and fail there, got %v", err)
			}

			if len(cl.beginRegReqs) != 1 {
				t.Fatalf("want exactly one BeginRegistration call, got %d", len(cl.beginRegReqs))
			}
			if got := cl.beginRegReqs[0].Email; got != email {
				t.Errorf("BeginRegistration resolved by %q, want the canonical login key %q", got, email)
			}

			// One account, filed under the email, still owned by the username
			// the operator asked for. A second entry here is the open-relying-
			// party half of the defect: the credential lands on a principal
			// nobody created.
			if len(cl.accounts) != 1 {
				t.Fatalf("want exactly one account, got %d: %v", len(cl.accounts), cl.accounts)
			}
			if got, found := cl.accounts[email]; !found || got != username {
				t.Errorf("account under %q is %q (found=%v), want %q", email, got, found, username)
			}

			if len(cl.createUserReqs) != 1 {
				t.Fatalf("want exactly one CreateUser call, got %d", len(cl.createUserReqs))
			}
			if got := cl.createUserReqs[0].Username; got != username {
				t.Errorf("CreateUser username is %q, want %q", got, username)
			}
			if got := cl.createUserReqs[0].Email; got != email {
				t.Errorf("CreateUser email is %q, want %q", got, email)
			}
		})
	}
}

// A rejected ceremony is reported as such, and the request that was rejected
// still carried the email — a failure must not be mistaken for the identifier
// having been right.
func TestWebAuthnRegistration_BeginRegistrationFailureIsWrapped(t *testing.T) {
	const email = "admin@example.com"

	// A closed relying party refusing an identifier it cannot resolve is
	// exactly how the reported defect surfaced in the field.
	cl := newFakeDirectoryClient(false)
	cl.beginRegErr = errors.New("user not found and public registration is disabled")

	_, err := webAuthnRegistration(
		context.Background(),
		cl,
		func() (webauthnclient.AuthenticatorAdapter, error) { return newDeviceLessAdapter(t), nil },
		NewPrinter("text", io.Discard),
		"admin", email, "Admin", string(RoleAdmin), "",
		nil,
	)

	if !errors.Is(err, ErrBeginRegistrationFailed) {
		t.Fatalf("want ErrBeginRegistrationFailed, got %v", err)
	}
	if len(cl.beginRegReqs) != 1 {
		t.Fatalf("want exactly one BeginRegistration call, got %d", len(cl.beginRegReqs))
	}
	if got := cl.beginRegReqs[0].Email; got != email {
		t.Errorf("BeginRegistration resolved by %q, want the canonical login key %q", got, email)
	}
}

// The register command must hand the ceremony the --email value, not the
// positional username argument. This is the wiring the reported defect broke:
// `user register admin --email admin@example.com` looked "admin" up as an
// email.
func TestUserRegisterCmd_SendsTheEmailFlagToBeginRegistration(t *testing.T) {
	const email = "admin@example.com"

	cl := newFakeDirectoryClient(false)
	withGlobalConfig(t, &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return cl, nil
		},
	})

	cmd := newUserRegisterCmd()
	if err := cmd.Flags().Set("email", email); err != nil {
		t.Fatalf("set email: %v", err)
	}

	code := captureExit(t, func() {
		userRegisterCmd.Run(cmd, []string{"admin"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1 (no real FIDO2 device present), got %d", code)
	}

	if len(cl.beginRegReqs) != 1 {
		t.Fatalf("want exactly one BeginRegistration call, got %d", len(cl.beginRegReqs))
	}
	if got := cl.beginRegReqs[0].Email; got != email {
		t.Errorf("BeginRegistration resolved by %q, want the --email value %q", got, email)
	}
	if len(cl.accounts) != 1 {
		t.Fatalf("want exactly one account, got %d: %v", len(cl.accounts), cl.accounts)
	}
}
