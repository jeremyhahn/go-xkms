// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package fido2

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// testSecret seals a test PIN string into protected memory. An empty s
// returns nil, mirroring what an authenticator with no PIN configured
// receives.
func testSecret(t *testing.T, s string) *secure.Secret {
	t.Helper()

	if s == "" {
		return nil
	}
	secret, err := secure.NewSecret(t.Context(), []byte(s))
	if err != nil {
		t.Fatalf("seal test PIN: %v", err)
	}
	return secret
}

type fakeDevices struct {
	devices []pkgfido2.Device
	err     error
}

func (f *fakeDevices) ListDevices() ([]pkgfido2.Device, error) { return f.devices, f.err }

type fakeCeremony struct {
	opts   pkgfido2.WebAuthnRegistrationOptions
	called bool
	err    error

	// attestation, when set, is returned verbatim instead of the default
	// placeholder — used to drive Enroll's post-parse success path with a
	// real, server-parseable document (see ctap2_success_test.go).
	attestation *pkgfido2.WebAuthnAttestation
}

func (f *fakeCeremony) RegisterWebAuthn(opts pkgfido2.WebAuthnRegistrationOptions) (*pkgfido2.WebAuthnAttestation, error) {
	f.called = true
	f.opts = opts
	if f.err != nil {
		return nil, f.err
	}
	if f.attestation != nil {
		return f.attestation, nil
	}
	return &pkgfido2.WebAuthnAttestation{CredentialID: []byte("cred")}, nil
}

func yubi(serial string) pkgfido2.Device {
	return pkgfido2.Device{
		Path:         "/dev/hidraw" + serial,
		Manufacturer: "Yubico",
		Product:      "YubiKey 5 NFC",
		SerialNumber: serial,
	}
}

func localRequest() LocalEnrollRequest {
	return LocalEnrollRequest{
		Challenge: []byte("challenge"),
		UserID:    []byte("user-handle"),
		Username:  "admin",
		RPID:      "xkms.example.com",
	}
}

// assertStubParseFailure accepts the one failure a stubbed authenticator can
// legitimately produce — a placeholder attestation that real parsing rejects —
// and fails on anything else, so a genuine regression before that point is
// never mistaken for the fixture's limitation.
func assertStubParseFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var ceremonyErr *LocalCeremonyError
	if !errors.As(err, &ceremonyErr) || ceremonyErr.Stage != "parse" {
		t.Fatalf("Enroll = %v, want nil or a parse-stage stub failure", err)
	}
}

// zeroDeviceEnumerator implements pkgfido2.HIDDeviceEnumerator, reporting no
// attached HID devices — the deterministic, hardware-free case a build
// without an attached authenticator (e.g. this test host) always hits.
type zeroDeviceEnumerator struct{}

func (zeroDeviceEnumerator) Enumerate(uint16, uint16) ([]pkgfido2.HIDDevice, error) {
	return nil, nil
}

func (zeroDeviceEnumerator) Open(string) (pkgfido2.HIDDevice, error) {
	return nil, errors.New("no device at path")
}

// TestNewLocalCeremony_WiresARealHandler pins the production constructor:
// given a real *pkgfido2.FIDO2Handler (not the test seam), it must build a
// LocalCeremony whose Available() reflects the handler's device list, and a
// non-positive timeout must fall back to the 60s default.
func TestNewLocalCeremony_WiresARealHandler(t *testing.T) {
	handler, err := pkgfido2.NewHandler(nil, zeroDeviceEnumerator{})
	if err != nil {
		t.Fatalf("pkgfido2.NewHandler: %v", err)
	}

	c := NewLocalCeremony(handler, 0)
	if c.timeout != 60*time.Second {
		t.Fatalf("timeout = %v, want the 60s default", c.timeout)
	}
	if ok, reason := c.Available(context.Background()); ok {
		t.Fatalf("Available() = true (%s), want false with zero attached devices", reason)
	}
}

// TestNewLocalCeremony_NilHandlerRefuses pins issue #1446: a nil handler must
// not be stored as a typed-nil interface, which compares non-nil and panics on
// first use. The ceremony reports NoHandlerReason and refuses to enroll.
func TestNewLocalCeremony_NilHandlerRefuses(t *testing.T) {
	c := NewLocalCeremony(nil, 0)
	if ok, reason := c.Available(context.Background()); ok || reason != NoHandlerReason {
		t.Fatalf("Available() = (%v, %q), want (false, %q)", ok, reason, NoHandlerReason)
	}
	if _, err := c.Enroll(context.Background(), localRequest()); !errors.Is(err, ErrLocalCeremonyUnavailable) {
		t.Fatalf("Enroll = %v, want ErrLocalCeremonyUnavailable", err)
	}
}

func TestLocalCeremony_AvailableRequiresAuthenticator(t *testing.T) {
	c := newLocalCeremony(&fakeDevices{}, &fakeCeremony{}, 0)
	ok, reason := c.Available(context.Background())
	if ok {
		t.Fatal("Available() = true with no authenticator attached")
	}
	if reason == "" {
		t.Error("Available() must explain why it is unavailable")
	}
}

func TestLocalCeremony_AvailableWithAuthenticator(t *testing.T) {
	c := newLocalCeremony(&fakeDevices{devices: []pkgfido2.Device{yubi("1")}}, &fakeCeremony{}, 0)
	if ok, reason := c.Available(context.Background()); !ok {
		t.Fatalf("Available() = false (%s), want true", reason)
	}
}

func TestLocalCeremony_SatisfiesTheCeremonyAvailabilityProbe(t *testing.T) {
	// Compile-time proof the driver plugs into the shared preflight without a
	// parallel registry or enroller interface.
	var _ qrdbsdk.AdminFactorAvailability = newLocalCeremony(&fakeDevices{}, &fakeCeremony{}, 0)
}

func TestLocalCeremony_RequiresRelyingPartyIDAndChallenge(t *testing.T) {
	c := newLocalCeremony(&fakeDevices{devices: []pkgfido2.Device{yubi("1")}}, &fakeCeremony{}, 0)

	req := localRequest()
	req.RPID = ""
	if _, err := c.Enroll(context.Background(), req); !errors.Is(err, ErrLocalRPIDRequired) {
		t.Fatalf("Enroll without RP ID = %v, want ErrLocalRPIDRequired", err)
	}

	req = localRequest()
	req.Challenge = nil
	if _, err := c.Enroll(context.Background(), req); !errors.Is(err, ErrLocalChallengeRequired) {
		t.Fatalf("Enroll without challenge = %v, want ErrLocalChallengeRequired", err)
	}
}

func TestLocalCeremony_RefusesToGuessBetweenAuthenticators(t *testing.T) {
	// Enrolling onto the wrong token is undiscoverable until first login, so
	// several attached keys with no selector is an error, not a pick.
	ceremony := &fakeCeremony{}
	c := newLocalCeremony(&fakeDevices{devices: []pkgfido2.Device{yubi("1"), yubi("2")}}, ceremony, 0)

	_, err := c.Enroll(context.Background(), localRequest())
	var ambiguous *AmbiguousAuthenticatorError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("Enroll = %v, want *AmbiguousAuthenticatorError", err)
	}
	if len(ambiguous.Candidates) != 2 {
		t.Errorf("Candidates = %v, want both devices listed", ambiguous.Candidates)
	}
	if ceremony.called {
		t.Error("the authenticator must not be touched when the selection is ambiguous")
	}
}

func TestLocalCeremony_SelectsByHint(t *testing.T) {
	ceremony := &fakeCeremony{}
	c := newLocalCeremony(&fakeDevices{devices: []pkgfido2.Device{yubi("111"), yubi("222")}}, ceremony, 0)

	req := localRequest()
	req.DeviceHint = "222"
	_, err := c.Enroll(context.Background(), req)

	if !ceremony.called {
		t.Fatalf("the selected authenticator was never driven (err=%v)", err)
	}
	assertStubParseFailure(t, err)
}

func TestLocalCeremony_ReportsUnmatchedHint(t *testing.T) {
	c := newLocalCeremony(&fakeDevices{devices: []pkgfido2.Device{yubi("111")}}, &fakeCeremony{}, 0)

	req := localRequest()
	req.DeviceHint = "nonexistent"
	_, err := c.Enroll(context.Background(), req)

	var notFound *AuthenticatorNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("Enroll = %v, want *AuthenticatorNotFoundError", err)
	}
	if len(notFound.Candidates) != 1 {
		t.Errorf("Candidates = %v, want the attached device listed", notFound.Candidates)
	}
}

func TestLocalCeremony_OriginMatchesRelyingParty(t *testing.T) {
	// The origin sent to the authenticator must equal what a browser sends at
	// login. A mismatch enrolls a credential that never works.
	ceremony := &fakeCeremony{}
	c := newLocalCeremony(&fakeDevices{devices: []pkgfido2.Device{yubi("1")}}, ceremony, 0)

	assertStubParseFailure(t, mustErr(c.Enroll(context.Background(), localRequest())))

	if ceremony.opts.Origin != "https://xkms.example.com" {
		t.Errorf("Origin = %q, want https://xkms.example.com", ceremony.opts.Origin)
	}
	if ceremony.opts.RPID != "xkms.example.com" {
		t.Errorf("RPID = %q, want xkms.example.com", ceremony.opts.RPID)
	}
	if !ceremony.opts.RequireUserVerification {
		t.Error("user verification must be required for an admin credential")
	}
}

func TestLocalCeremony_ForwardsThePIN(t *testing.T) {
	// A PIN-protected key refuses credential creation outright, and at init
	// there is no browser to prompt — so a PIN that is collected but not
	// forwarded fails the ceremony with an error about the authenticator.
	ceremony := &fakeCeremony{}
	c := newLocalCeremony(&fakeDevices{devices: []pkgfido2.Device{yubi("1")}}, ceremony, 0)

	req := localRequest()
	req.PIN = testSecret(t, "123456")
	assertStubParseFailure(t, mustErr(c.Enroll(context.Background(), req)))

	if ceremony.opts.PIN == nil {
		t.Fatal("want a PIN forwarded to the authenticator ceremony")
	}
	buf, err := ceremony.opts.PIN.Open(t.Context())
	if err != nil {
		t.Fatalf("open forwarded PIN: %v", err)
	}
	defer buf.Destroy()
	if string(buf.Bytes()) != "123456" {
		t.Errorf("PIN = %q, want it forwarded to the authenticator ceremony", buf.Bytes())
	}
}

func TestLocalCeremony_OmitsAnAbsentPIN(t *testing.T) {
	// A key with no PIN configured must not be sent an empty one: that would
	// turn a working enrollment into a getPINToken failure.
	ceremony := &fakeCeremony{}
	c := newLocalCeremony(&fakeDevices{devices: []pkgfido2.Device{yubi("1")}}, ceremony, 0)

	assertStubParseFailure(t, mustErr(c.Enroll(context.Background(), localRequest())))

	if ceremony.opts.PIN != nil {
		t.Errorf("PIN = %v, want nil when none was supplied", ceremony.opts.PIN)
	}
}

func TestLocalCeremony_SurfacesAuthenticatorFailure(t *testing.T) {
	ceremony := &fakeCeremony{err: errors.New("user presence timed out")}
	c := newLocalCeremony(&fakeDevices{devices: []pkgfido2.Device{yubi("1")}}, ceremony, 0)

	_, err := c.Enroll(context.Background(), localRequest())
	var ceremonyErr *LocalCeremonyError
	if !errors.As(err, &ceremonyErr) {
		t.Fatalf("Enroll = %v, want *LocalCeremonyError", err)
	}
	if ceremonyErr.Stage != "authenticator" {
		t.Errorf("Stage = %q, want authenticator", ceremonyErr.Stage)
	}
}

// mustErr discards a result and returns only the error, for assertions that
// care about the call's side effects rather than its value.
func mustErr[T any](_ T, err error) error { return err }
