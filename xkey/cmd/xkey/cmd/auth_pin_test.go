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
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fido2 "github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// pinString reads back a *secure.Secret ceremony.pin recorded for a fixture
// assertion. A nil secret (no PIN supplied) reads as "".
func pinString(t *testing.T, secret *secure.Secret) string {
	t.Helper()

	if secret == nil {
		return ""
	}
	return openSecretString(t, secret)
}

// mustSealPIN seals a test PIN string the way sealCeremonyPIN does, failing
// the test on a sealing error. An empty pin returns nil.
func mustSealPIN(t *testing.T, pin string) *secure.Secret {
	t.Helper()

	secret, err := sealCeremonyPIN(pin)
	require.NoError(t, err)
	return secret
}

// These tests cover go-xkms#299: "xkey auth register" and "xkey auth login"
// could not supply a CTAP2 PIN, so neither completed against a PIN-protected
// authenticator — which is every key the xKey setup wizard configures.

// newPINRegisterClient builds a server double that answers a full registration
// ceremony, so a test can assert on what the authenticator was given.
func newPINRegisterClient() *fakeAuthClient {
	return &fakeAuthClient{
		beginRegistrationResp: &transport.BeginRegistrationResponse{
			SessionID:   "session-pin",
			OptionsJSON: `{"publicKey":{"challenge":"Y2hhbGxlbmdl","rp":{"id":"xkms.example.com"}}}`,
		},
		finishRegistrationResp: &transport.FinishRegistrationResponse{
			Success:      true,
			CredentialID: "cred-pin",
		},
	}
}

// newPINLoginClient builds a server double that answers a full assertion
// ceremony with a token.
func newPINLoginClient() *fakeAuthClient {
	// HS256 JWT with iss/sub/exp claims; only the claims are read.
	const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJpc3MiOiJ4a21zLmV4YW1wbGUuY29tIiwic3ViIjoiYWxpY2UiLCJleHAiOjQ4NzE1MTIwMDB9." +
		"c2lnbmF0dXJl"

	return &fakeAuthClient{
		beginAuthenticationResp: &transport.BeginAuthenticationResponse{
			SessionID:   "login-session-pin",
			OptionsJSON: `{"publicKey":{"challenge":"Y2hhbGxlbmdl","rpId":"xkms.example.com"}}`,
		},
		finishAuthenticationResp: &transport.FinishAuthenticationResponse{
			Success:  true,
			Token:    jwtToken,
			Username: "alice",
		},
	}
}

// TestRunAuthRegister_CarriesPINToTheAuthenticator is the register half of the
// fix: the resolved PIN must reach the ceremony, because a PIN-protected key
// refuses MakeCredential outright without one.
func TestRunAuthRegister_CarriesPINToTheAuthenticator(t *testing.T) {
	t.Run("from stdin", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv(pinEnvVar, "")
		stubStdin(t, []byte("123456\n"), nil)

		ceremony := &fakeCeremony{registerJSON: []byte(`{"id":"cred-pin"}`)}
		installAuthDoubles(t, newPINRegisterClient(), ceremony, nil)

		cmd := newAuthRegisterCmd(t, &bytes.Buffer{})
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "https://xkms.example.com:8443"))
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "email", "alice@example.com"))
		require.NoError(t, setFlagForTest(t, cmd.Flags(), pinFlagStdin, "true"))

		require.NoError(t, runAuthRegister(cmd, nil))
		assert.Equal(t, "123456", pinString(t, ceremony.pin), "the PIN must reach the authenticator")
	})

	t.Run("from the environment", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv(pinEnvVar, "654321")

		ceremony := &fakeCeremony{registerJSON: []byte(`{"id":"cred-pin"}`)}
		installAuthDoubles(t, newPINRegisterClient(), ceremony, nil)

		cmd := newAuthRegisterCmd(t, &bytes.Buffer{})
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "https://xkms.example.com:8443"))
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "email", "alice@example.com"))

		require.NoError(t, runAuthRegister(cmd, nil))
		assert.Equal(t, "654321", pinString(t, ceremony.pin))
	})

	t.Run("no PIN supplied stays no PIN", func(t *testing.T) {
		// An authenticator with no PIN configured must keep working, so the
		// command must not invent one.
		t.Setenv("HOME", t.TempDir())
		t.Setenv(pinEnvVar, "")

		ceremony := &fakeCeremony{registerJSON: []byte(`{"id":"cred-pin"}`)}
		installAuthDoubles(t, newPINRegisterClient(), ceremony, nil)

		cmd := newAuthRegisterCmd(t, &bytes.Buffer{})
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "https://xkms.example.com:8443"))
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "email", "alice@example.com"))

		require.NoError(t, runAuthRegister(cmd, nil))
		assert.Nil(t, ceremony.pin)
	})
}

// TestRunAuthRegister_RejectsEmptyStdinPINBeforeTheNetwork proves bad PIN input
// is caught before anything is registered server-side: correcting it should not
// first cost a round trip or a half-finished enrollment.
func TestRunAuthRegister_RejectsEmptyStdinPINBeforeTheNetwork(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(pinEnvVar, "")
	stubStdin(t, []byte(""), nil)

	client := newPINRegisterClient()
	ceremony := &fakeCeremony{registerJSON: []byte(`{"id":"cred-pin"}`)}
	installAuthDoubles(t, client, ceremony, nil)

	cmd := newAuthRegisterCmd(t, &bytes.Buffer{})
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "https://xkms.example.com:8443"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "email", "alice@example.com"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), pinFlagStdin, "true"))

	err := runAuthRegister(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPINInputStdinEmpty)
	assert.Nil(t, client.beginRegistrationReq, "no ceremony may be begun on unusable PIN input")
	assert.Empty(t, ceremony.registerOpts, "the authenticator must not be touched")
}

// TestRunAuthLogin_CarriesPINToTheAuthenticator is the login half: the gap the
// issue calls a real API gap, since the assertion entry point had no PIN at all.
func TestRunAuthLogin_CarriesPINToTheAuthenticator(t *testing.T) {
	const serverURL = "https://xkms.example.com:8443"

	t.Run("from stdin", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv(pinEnvVar, "")
		registerLoginServer(t, serverURL)
		stubStdin(t, []byte("123456\n"), nil)

		ceremony := &fakeCeremony{assertJSON: []byte(`{"id":"cred-pin"}`)}
		installAuthDoubles(t, newPINLoginClient(), ceremony, nil)

		cmd := newAuthLoginCmd(t, &bytes.Buffer{})
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", serverURL))
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "email", "alice@example.com"))
		require.NoError(t, setFlagForTest(t, cmd.Flags(), pinFlagStdin, "true"))

		require.NoError(t, runAuthLogin(cmd, nil))
		assert.Equal(t, "123456", pinString(t, ceremony.pin), "the PIN must reach the authenticator")
	})

	t.Run("no PIN supplied stays no PIN", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv(pinEnvVar, "")
		registerLoginServer(t, serverURL)

		ceremony := &fakeCeremony{assertJSON: []byte(`{"id":"cred-pin"}`)}
		installAuthDoubles(t, newPINLoginClient(), ceremony, nil)

		cmd := newAuthLoginCmd(t, &bytes.Buffer{})
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", serverURL))
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "email", "alice@example.com"))

		require.NoError(t, runAuthLogin(cmd, nil))
		assert.Nil(t, ceremony.pin)
	})
}

// TestRunAuthLogin_RejectsEmptyStdinPINBeforeTheNetwork mirrors the register
// guard on the login path.
func TestRunAuthLogin_RejectsEmptyStdinPINBeforeTheNetwork(t *testing.T) {
	const serverURL = "https://xkms.example.com:8443"

	t.Setenv("HOME", t.TempDir())
	t.Setenv(pinEnvVar, "")
	registerLoginServer(t, serverURL)
	// A bare line ending trims to nothing: the operator piped no PIN.
	stubStdin(t, []byte("\r\n"), nil)

	client := newPINLoginClient()
	ceremony := &fakeCeremony{assertJSON: []byte(`{"id":"cred-pin"}`)}
	installAuthDoubles(t, client, ceremony, nil)

	cmd := newAuthLoginCmd(t, &bytes.Buffer{})
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", serverURL))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "email", "alice@example.com"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), pinFlagStdin, "true"))

	err := runAuthLogin(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPINInputStdinEmpty)
	assert.Nil(t, client.beginAuthenticationReq, "no ceremony may be begun on unusable PIN input")
	assert.Empty(t, ceremony.assertOpts, "the authenticator must not be touched")
}

// --- the missing-PIN diagnosis (issue #299 fix item 4) ---

// TestCeremonyFailure_NamesTheMissingPIN is the whole point of the mapping: the
// raw CTAP2_ERR_PIN_REQUIRED is what sent the original investigation down the
// wrong path, because it reads as a device fault rather than missing input.
func TestCeremonyFailure_NamesTheMissingPIN(t *testing.T) {
	for _, sentinel := range []error{ErrWebAuthnRegistrationFailed, ErrWebAuthnAssertionFailed} {
		err := ceremonyFailure(sentinel, nil, fido2.ErrPINRequired)

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrWebAuthnPINRequired)
		assert.ErrorIs(t, err, fido2.ErrPINRequired, "the CTAP cause must survive for diagnosis")

		message := err.Error()
		assert.Contains(t, message, "requires a PIN")
		assert.Contains(t, message, "--pin-stdin", "the message must name the flag that supplies it")
		assert.Contains(t, strings.ToLower(message), "xkey_pin")
	}
}

func TestCeremonyFailureClassification(t *testing.T) {
	t.Run("a PIN that was supplied is not reported as a missing one", func(t *testing.T) {
		// PIN_REQUIRED with a PIN in hand means the authenticator rejected an
		// authorization that WAS attempted. Telling the operator to supply the
		// PIN they just supplied sends them in a circle.
		err := ceremonyFailure(ErrWebAuthnAssertionFailed, mustSealPIN(t, "123456"), fido2.ErrPINRequired)

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrWebAuthnAssertionFailed)
		assert.NotErrorIs(t, err, ErrWebAuthnPINRequired)
	})

	t.Run("an unrelated failure keeps its own sentinel", func(t *testing.T) {
		cause := errors.New("hid: device disconnected")
		err := ceremonyFailure(ErrWebAuthnRegistrationFailed, nil, cause)

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrWebAuthnRegistrationFailed)
		assert.ErrorIs(t, err, cause)
		assert.NotErrorIs(t, err, ErrWebAuthnPINRequired)
	})

	t.Run("a wrong PIN is reported as a PIN failure, not a missing PIN", func(t *testing.T) {
		// A lockout must never read as anything else, so the attempt counter
		// the authenticator reported has to survive to the operator.
		cause := &fido2.PINAttemptsError{Err: fido2.ErrInvalidPIN, Retries: 2}
		err := ceremonyFailure(ErrWebAuthnAssertionFailed, mustSealPIN(t, "999999"), cause)

		require.Error(t, err)
		assert.ErrorIs(t, err, fido2.ErrInvalidPIN)
		assert.NotErrorIs(t, err, ErrWebAuthnPINRequired)
		assert.Contains(t, err.Error(), "2 attempts remaining")
	})
}
