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

package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fido2 "github.com/jeremyhahn/go-xkms/sdk/go/fido2"
)

// --- parseCreationOptions ---

// TestParseCreationOptions_WrappedDocument verifies the browser-shaped
// registration options a relying party serves are decoded into the CTAP2
// registration parameters.
func TestParseCreationOptions_WrappedDocument(t *testing.T) {
	challenge := []byte("registration-challenge")
	userID := []byte("user-handle-1")

	optionsJSON := []byte(`{"publicKey":{` +
		`"challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) + `",` +
		`"rp":{"id":"xkms.example.com","name":"xKMS"},` +
		`"user":{"id":"` + base64.RawURLEncoding.EncodeToString(userID) + `","name":"alice","displayName":"Alice Example"},` +
		`"authenticatorSelection":{"userVerification":"required"},` +
		`"timeout":90000}}`)

	opts, err := parseCreationOptions(optionsJSON, "https://xkms.example.com:8443")
	require.NoError(t, err)

	assert.Equal(t, challenge, opts.Challenge)
	assert.Equal(t, "xkms.example.com", opts.RPID)
	assert.Equal(t, "xKMS", opts.RPName)
	assert.Equal(t, userID, opts.UserID)
	assert.Equal(t, "alice", opts.UserName)
	assert.Equal(t, "Alice Example", opts.UserDisplayName)
	assert.True(t, opts.RequireUserVerification)
	assert.Equal(t, 90*time.Second, opts.Timeout)
	assert.Equal(t, "https://xkms.example.com:8443", opts.Origin)
}

// TestParseCreationOptions_BareDocument verifies the unwrapped
// PublicKeyCredentialCreationOptions shape is accepted too.
func TestParseCreationOptions_BareDocument(t *testing.T) {
	optionsJSON := []byte(`{"challenge":"Y2hhbGxlbmdl","rp":{"id":"xkms.example.com"},"user":{"name":"bob"}}`)

	opts, err := parseCreationOptions(optionsJSON, "")
	require.NoError(t, err)

	assert.Equal(t, []byte("challenge"), opts.Challenge)
	assert.Equal(t, "xkms.example.com", opts.RPID)
	assert.Equal(t, "bob", opts.UserName)
	assert.False(t, opts.RequireUserVerification)
}

// TestParseCreationOptions_DefaultsOrigin verifies the WebAuthn same-origin
// default is applied when the caller supplies no origin.
func TestParseCreationOptions_DefaultsOrigin(t *testing.T) {
	optionsJSON := []byte(`{"publicKey":{"challenge":"Y2hhbGxlbmdl","rp":{"id":"xkms.example.com"}}}`)

	opts, err := parseCreationOptions(optionsJSON, "")
	require.NoError(t, err)
	assert.Equal(t, "https://xkms.example.com", opts.Origin)
}

// TestParseCreationOptions_PaddedBase64 verifies padded base64url fields are
// tolerated, since relying parties have been observed emitting them.
func TestParseCreationOptions_PaddedBase64(t *testing.T) {
	optionsJSON := []byte(`{"publicKey":{"challenge":"Y2hhbGxlbmdlLTE=","rp":{"id":"rp.example"}}}`)

	opts, err := parseCreationOptions(optionsJSON, "")
	require.NoError(t, err)
	assert.Equal(t, []byte("challenge-1"), opts.Challenge)
}

// TestParseCreationOptions_Errors verifies every malformed options document
// is rejected with the matching typed error.
func TestParseCreationOptions_Errors(t *testing.T) {
	tests := []struct {
		name        string
		optionsJSON string
		wantErr     error
	}{
		{"empty", "", ErrWebAuthnOptionsInvalid},
		{"not json", "{not json", ErrWebAuthnOptionsInvalid},
		{"no challenge", `{"publicKey":{"rp":{"id":"rp.example"}}}`, ErrWebAuthnChallengeMissing},
		{"no rp id", `{"publicKey":{"challenge":"Y2hhbGxlbmdl","rp":{"name":"rp"}}}`, ErrWebAuthnRPIDMissing},
		{"bad challenge encoding", `{"publicKey":{"challenge":"!!!!","rp":{"id":"rp.example"}}}`, ErrWebAuthnOptionsInvalid},
		{"bad user id encoding", `{"publicKey":{"challenge":"Y2hhbGxlbmdl","rp":{"id":"rp.example"},"user":{"id":"!!!!"}}}`, ErrWebAuthnOptionsInvalid},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCreationOptions([]byte(tc.optionsJSON), "")
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

// --- fido2Ceremony guard paths ---

// TestFIDO2Ceremony_RegisterRejectsBadOptions verifies malformed options are
// rejected before any authenticator is touched.
func TestFIDO2Ceremony_RegisterRejectsBadOptions(t *testing.T) {
	ceremony := &fido2Ceremony{}

	_, err := ceremony.Register(context.Background(), []byte("{not json"), "https://rp.example")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrWebAuthnOptionsInvalid)
}

// TestFIDO2Ceremony_RegisterHonorsContext verifies a cancelled context stops
// the ceremony before the authenticator prompt.
func TestFIDO2Ceremony_RegisterHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ceremony := &fido2Ceremony{}
	_, err := ceremony.Register(ctx, []byte(`{"publicKey":{}}`), "https://rp.example")
	assert.ErrorIs(t, err, context.Canceled)
}

// --- decodeWebAuthnBase64 ---

func TestDecodeWebAuthnBase64(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []byte
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"unpadded", "Y2hhbGxlbmdl", []byte("challenge"), false},
		{"padded", "Y2hhbGxlbmdlLTE=", []byte("challenge-1"), false},
		{"url safe alphabet", base64.RawURLEncoding.EncodeToString([]byte{0xfb, 0xff, 0x00}), []byte{0xfb, 0xff, 0x00}, false},
		{"invalid", "!!!!", nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeWebAuthnBase64(tc.value)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// --- webauthnOrigin ---

func TestWebAuthnOrigin(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		want      string
	}{
		{"https with port", "https://xkms.example.com:8443", "https://xkms.example.com:8443"},
		{"https without port", "https://xkms.example.com", "https://xkms.example.com"},
		{"trailing path is dropped", "https://xkms.example.com:8443/api/v1", "https://xkms.example.com:8443"},
		{"surrounding whitespace", "  https://xkms.example.com  ", "https://xkms.example.com"},
		{"http", "http://localhost:8080", "http://localhost:8080"},
		{"no scheme", "xkms.example.com:8443", ""},
		{"empty", "", ""},
		{"unparsable", "://nope", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, webauthnOrigin(tc.serverURL))
		})
	}
}

// --- authenticator discovery ---

// fakeHIDDevice is a HID device double. Only the descriptive accessors the
// enumeration path reads are exercised; the transport methods are never
// reached because no ceremony is driven against it.
type fakeHIDDevice struct {
	path   string
	closed bool
}

func (d *fakeHIDDevice) Write(p []byte) (int, error) { return len(p), nil }
func (d *fakeHIDDevice) Read(p []byte) (int, error)  { return 0, nil }
func (d *fakeHIDDevice) Close() error {
	d.closed = true
	return nil
}
func (d *fakeHIDDevice) Path() string         { return d.path }
func (d *fakeHIDDevice) ProductID() uint16    { return 0x0001 }
func (d *fakeHIDDevice) VendorID() uint16     { return 0xF1D0 }
func (d *fakeHIDDevice) Product() string      { return "Test Authenticator" }
func (d *fakeHIDDevice) Manufacturer() string { return "xKey Tests" }
func (d *fakeHIDDevice) SerialNumber() string { return "TEST-0001" }

// fakeEnumerator is a HID enumerator double that reports a scripted device
// list, so authenticator discovery can be exercised without hardware.
type fakeEnumerator struct {
	devices []fido2.HIDDevice
	err     error
}

func (e *fakeEnumerator) Enumerate(_, _ uint16) ([]fido2.HIDDevice, error) {
	return e.devices, e.err
}

func (e *fakeEnumerator) Open(path string) (fido2.HIDDevice, error) {
	if e.err != nil {
		return nil, e.err
	}
	return &fakeHIDDevice{path: path}, nil
}

// installEnumerator points authenticator discovery at the supplied double.
func installEnumerator(t *testing.T, enumerator fido2.HIDDeviceEnumerator) {
	t.Helper()

	original := webauthnEnumeratorFactory
	webauthnEnumeratorFactory = func() fido2.HIDDeviceEnumerator { return enumerator }
	t.Cleanup(func() { webauthnEnumeratorFactory = original })
}

// TestNewFIDO2Ceremony_NoAuthenticator verifies discovery fails closed when
// no CTAP2 device is attached, so a ceremony is never reported as completed
// without an authenticator.
func TestNewFIDO2Ceremony_NoAuthenticator(t *testing.T) {
	installEnumerator(t, &fakeEnumerator{})

	ceremony, err := newFIDO2Ceremony()
	assert.Nil(t, ceremony)
	assert.ErrorIs(t, err, ErrWebAuthnAuthenticatorUnavailable)
}

// TestNewFIDO2Ceremony_EnumerationFails verifies an enumeration error also
// fails closed.
func TestNewFIDO2Ceremony_EnumerationFails(t *testing.T) {
	installEnumerator(t, &fakeEnumerator{err: errors.New("hidraw permission denied")})

	ceremony, err := newFIDO2Ceremony()
	assert.Nil(t, ceremony)
	require.ErrorIs(t, err, ErrWebAuthnAuthenticatorUnavailable)
	assert.Contains(t, err.Error(), "permission denied")
}

// TestNewFIDO2Ceremony_DeviceAttached verifies a ceremony driver is built and
// released when an authenticator is present.
func TestNewFIDO2Ceremony_DeviceAttached(t *testing.T) {
	device := &fakeHIDDevice{path: "/dev/hidraw-test"}
	installEnumerator(t, &fakeEnumerator{devices: []fido2.HIDDevice{device}})

	ceremony, err := newFIDO2Ceremony()
	require.NoError(t, err)
	require.NotNil(t, ceremony)
	assert.True(t, device.closed, "enumeration must release the probed device")
	assert.NoError(t, ceremony.Close())
}
