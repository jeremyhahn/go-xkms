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

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/virtualdevice"
)

// These tests cover the ceremony half of go-xkms#309: the resolved CTAP2 PIN
// must reach fido2.WebAuthnRegistrationOptions / WebAuthnAuthenticationOptions,
// because a PIN-protected authenticator refuses both ceremonies without it.
// They drive the real pkg/fido2 platform stack against the real virtual
// authenticator — the same pairing xkmsctl ships in FIDO2_USE_VIRTUAL mode —
// so a green run proves the PIN completed an actual pinUvAuthParam
// authorization, not that a double recorded a string.

const (
	testPIN      = "123456"
	testWrongPIN = "654321"
	testRPID     = "xkms.example.com"
)

// newVirtualPINHandler builds a FIDO2 handler over a virtual authenticator.
// A non-empty pin is installed on the authenticator as CTAP2 requires
// (SHA-256(PIN)[:16]), modelling a security key whose owner has set a PIN;
// an empty pin models a key with none configured.
func newVirtualPINHandler(t *testing.T, pin string) *fido2.FIDO2Handler {
	t.Helper()

	authCfg := authenticator.DefaultConfig()
	authCfg.Storage = authenticator.NewMemoryStorage()
	authCfg.UserPresenceHandler = authenticator.NewAutoGrantHandler()

	auth, err := authenticator.NewAuthenticator(authCfg)
	if err != nil {
		t.Fatalf("build virtual authenticator: %v", err)
	}
	if pin != "" {
		hash := sha256.Sum256([]byte(pin))
		auth.SetFIDO2PINHash(hash[:16])
	}

	device, err := virtualdevice.NewNativeVirtualDevice(&virtualdevice.NativeVirtualDeviceConfig{
		SerialNumber:  "XKMSCTL-PIN-309",
		Manufacturer:  "go-xkms",
		Product:       "xkmsctl PIN test",
		Authenticator: auth,
	})
	if err != nil {
		t.Fatalf("build virtual device: %v", err)
	}

	enumerator := virtualdevice.NewNativeVirtualDeviceEnumerator()
	if err := enumerator.RegisterDevice(device); err != nil {
		t.Fatalf("register virtual device: %v", err)
	}

	fidoCfg := fido2.DefaultConfig
	handler, err := fido2.NewHandler(&fidoCfg, enumerator)
	if err != nil {
		t.Fatalf("build fido2 handler: %v", err)
	}
	t.Cleanup(func() { _ = handler.Close() })

	return handler
}

// pinDirectoryClient answers a full registration ceremony so the local
// authenticator half runs to completion.
type pinDirectoryClient struct {
	mockBackendsClient
}

func (c *pinDirectoryClient) CreateUser(context.Context, *client.CreateUserRequest) (*client.GetUserResponse, error) {
	return &client.GetUserResponse{}, nil
}

func (c *pinDirectoryClient) BeginRegistration(context.Context, *client.BeginRegistrationRequest) (*client.BeginRegistrationResponse, error) {
	return &client.BeginRegistrationResponse{
		SessionID:   "sess-pin",
		OptionsJSON: validRegistrationOptionsJSON(),
	}, nil
}

func (c *pinDirectoryClient) FinishRegistration(context.Context, *client.FinishRegistrationRequest) (*client.FinishRegistrationResponse, error) {
	return &client.FinishRegistrationResponse{Success: true, CredentialID: "cred-pin"}, nil
}

// testPINSecret seals a test PIN string into protected memory, mirroring
// what resolvePINInput hands the ceremony. An empty pin returns nil, the
// zero value for "no PIN configured".
func testPINSecret(t *testing.T, pin string) *secure.Secret {
	t.Helper()

	if pin == "" {
		return nil
	}
	secret, err := secure.NewSecret([]byte(pin))
	if err != nil {
		t.Fatalf("seal test PIN: %v", err)
	}
	return secret
}

// registerPINCeremony runs webAuthnRegistration with the given handler and PIN.
func registerPINCeremony(t *testing.T, handler *fido2.FIDO2Handler, pin string) (*fido2.WebAuthnAttestation, error) {
	t.Helper()

	return webAuthnRegistration(
		context.Background(),
		&pinDirectoryClient{},
		handler,
		NewPrinter("text", io.Discard),
		"admin", "admin@example.com", "Admin", string(RoleAdmin), "",
		false, 5*time.Second, testPINSecret(t, pin),
	)
}

// TestWebAuthnRegistration_CarriesPINToTheAuthenticator is the register half
// of the fix: the resolved PIN must reach the ceremony, because a
// PIN-protected key refuses MakeCredential outright without one. The ceremony
// completing IS the assertion — the virtual authenticator verified a real
// pinUvAuthParam computed from this PIN.
func TestWebAuthnRegistration_CarriesPINToTheAuthenticator(t *testing.T) {
	handler := newVirtualPINHandler(t, testPIN)

	att, err := registerPINCeremony(t, handler, testPIN)
	if err != nil {
		t.Fatalf("registration against a PIN-protected authenticator must succeed with the PIN: %v", err)
	}
	if att == nil || len(att.CredentialID) == 0 {
		t.Fatal("want an attestation carrying the authenticator-assigned credential ID")
	}
}

// TestWebAuthnRegistration_MissingPINIsNamed proves the raw
// CTAP2_ERR_PIN_REQUIRED does not reach the operator: the failure names the
// missing PIN and the sources that supply it.
func TestWebAuthnRegistration_MissingPINIsNamed(t *testing.T) {
	handler := newVirtualPINHandler(t, testPIN)

	_, err := registerPINCeremony(t, handler, "")
	if err == nil {
		t.Fatal("a PIN-protected authenticator must refuse the ceremony without a PIN")
	}
	if !errors.Is(err, ErrWebAuthnPINRequired) {
		t.Fatalf("want ErrWebAuthnPINRequired, got %v", err)
	}
	if !errors.Is(err, fido2.ErrPINRequired) {
		t.Errorf("the CTAP cause must survive for diagnosis, got %v", err)
	}
	if !strings.Contains(err.Error(), "--"+pinFlagStdin) {
		t.Errorf("the failure must name the flag that supplies the PIN: %q", err.Error())
	}
}

// TestWebAuthnRegistration_NoPINAuthenticatorNeedsNone is the regression
// guard: against an authenticator with no PIN set, an empty PIN still works.
func TestWebAuthnRegistration_NoPINAuthenticatorNeedsNone(t *testing.T) {
	handler := newVirtualPINHandler(t, "")

	att, err := registerPINCeremony(t, handler, "")
	if err != nil {
		t.Fatalf("an authenticator with no PIN configured needs none: %v", err)
	}
	if att == nil || len(att.CredentialID) == 0 {
		t.Fatal("want an attestation carrying the authenticator-assigned credential ID")
	}
}

// loginAssertionOptions builds the server's CredentialAssertion for a
// credential previously registered on the virtual authenticator.
func loginAssertionOptions(t *testing.T, credentialID []byte) protocol.CredentialAssertion {
	t.Helper()

	optionsJSON := `{"publicKey":{"challenge":"` + b64url("login-challenge") + `",` +
		`"rpId":"` + testRPID + `",` +
		`"allowCredentials":[{"type":"public-key","id":"` +
		base64.RawURLEncoding.EncodeToString(credentialID) + `"}]}}`

	var assertionOpts protocol.CredentialAssertion
	if err := json.Unmarshal([]byte(optionsJSON), &assertionOpts); err != nil {
		t.Fatalf("build assertion options: %v", err)
	}
	return assertionOpts
}

// registerCredentialForLogin enrolls a credential on the handler's virtual
// authenticator so a login ceremony has something to assert with.
func registerCredentialForLogin(t *testing.T, handler *fido2.FIDO2Handler, pin string) []byte {
	t.Helper()

	att, err := registerPINCeremony(t, handler, pin)
	if err != nil {
		t.Fatalf("register the login credential: %v", err)
	}
	return att.CredentialID
}

// TestLoginAssertion_CarriesPINToTheAuthenticator is the login half of the
// fix — the exact gap of cmd/xkmsctl/user.go:403: the assertion options never
// carried a PIN, so login could not complete against a PIN-protected key.
func TestLoginAssertion_CarriesPINToTheAuthenticator(t *testing.T) {
	handler := newVirtualPINHandler(t, testPIN)
	credentialID := registerCredentialForLogin(t, handler, testPIN)

	assertion, err := loginAssertion(handler, loginAssertionOptions(t, credentialID), true, 5*time.Second, testPINSecret(t, testPIN))
	if err != nil {
		t.Fatalf("login against a PIN-protected authenticator must succeed with the PIN: %v", err)
	}
	if assertion == nil || len(assertion.PublicKeyCredentialJSON) == 0 {
		t.Fatal("want a signed assertion document")
	}
}

// TestLoginAssertion_MissingPINIsNamed mirrors the register-side diagnosis on
// the login path.
func TestLoginAssertion_MissingPINIsNamed(t *testing.T) {
	handler := newVirtualPINHandler(t, testPIN)
	credentialID := registerCredentialForLogin(t, handler, testPIN)

	_, err := loginAssertion(handler, loginAssertionOptions(t, credentialID), true, 5*time.Second, testPINSecret(t, ""))
	if err == nil {
		t.Fatal("a PIN-protected authenticator must refuse the assertion without a PIN")
	}
	if !errors.Is(err, ErrWebAuthnPINRequired) {
		t.Fatalf("want ErrWebAuthnPINRequired, got %v", err)
	}
	if !errors.Is(err, fido2.ErrPINRequired) {
		t.Errorf("the CTAP cause must survive for diagnosis, got %v", err)
	}
}

// TestLoginAssertion_WrongPINReportsRemainingAttempts proves a wrong PIN is
// reported as a PIN failure carrying the authenticator's own retry counter —
// a lockout must never read as anything else.
func TestLoginAssertion_WrongPINReportsRemainingAttempts(t *testing.T) {
	handler := newVirtualPINHandler(t, testPIN)
	credentialID := registerCredentialForLogin(t, handler, testPIN)

	_, err := loginAssertion(handler, loginAssertionOptions(t, credentialID), true, 5*time.Second, testPINSecret(t, testWrongPIN))
	if err == nil {
		t.Fatal("a wrong PIN must fail the assertion")
	}
	if !errors.Is(err, fido2.ErrInvalidPIN) {
		t.Fatalf("want ErrInvalidPIN reachable, got %v", err)
	}
	if errors.Is(err, ErrWebAuthnPINRequired) {
		t.Errorf("a wrong PIN is not a missing one: %v", err)
	}
	if !strings.Contains(err.Error(), "attempts remaining") {
		t.Errorf("the authenticator's retry counter must reach the operator: %q", err.Error())
	}
}

// TestLoginAssertion_NoPINAuthenticatorNeedsNone is the login regression
// guard: against an authenticator with no PIN set, an empty PIN still works.
func TestLoginAssertion_NoPINAuthenticatorNeedsNone(t *testing.T) {
	handler := newVirtualPINHandler(t, "")
	credentialID := registerCredentialForLogin(t, handler, "")

	assertion, err := loginAssertion(handler, loginAssertionOptions(t, credentialID), false, 5*time.Second, testPINSecret(t, ""))
	if err != nil {
		t.Fatalf("an authenticator with no PIN configured needs none: %v", err)
	}
	if assertion == nil || len(assertion.PublicKeyCredentialJSON) == 0 {
		t.Fatal("want a signed assertion document")
	}
}

// --- the before-the-network guard (issue #309, mirrored from #299) ---

// observingLoginClient records whether the server-side ceremony was begun.
type observingLoginClient struct {
	mockUserClient
	beginAuthCalled bool
}

func (c *observingLoginClient) BeginAuthentication(ctx context.Context, req *client.BeginAuthenticationRequest) (*client.BeginAuthenticationResponse, error) {
	c.beginAuthCalled = true
	return c.mockUserClient.BeginAuthentication(ctx, req)
}

// TestUserLoginCmd_RejectsEmptyStdinPINBeforeTheNetwork proves bad PIN input
// is caught before the server issues a challenge: correcting it should not
// first cost a round trip or a half-consumed session.
func TestUserLoginCmd_RejectsEmptyStdinPINBeforeTheNetwork(t *testing.T) {
	stubPINStdin(t, "\n")

	mock := &observingLoginClient{}
	withGlobalConfig(t, &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return mock, nil
		},
	})

	cmd := newUserLoginCmd()
	if err := cmd.Flags().Set(pinFlagStdin, "true"); err != nil {
		t.Fatalf("set %s: %v", pinFlagStdin, err)
	}

	code := captureExit(t, func() {
		userLoginCmd.Run(cmd, []string{"alice@example.com"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if mock.beginAuthCalled {
		t.Error("no ceremony may be begun on unusable PIN input")
	}
}

// TestUserRegisterCmd_RejectsEmptyStdinPINBeforeTheNetwork is the register
// half of the same guard: nothing may be created server-side on PIN input the
// operator has to redo anyway.
func TestUserRegisterCmd_RejectsEmptyStdinPINBeforeTheNetwork(t *testing.T) {
	stubPINStdin(t, "\r\n")

	mock := &mockUserClient{}
	withGlobalConfig(t, newUserTestConfig("text", mock))

	cmd := newUserRegisterCmd()
	if err := cmd.Flags().Set(pinFlagStdin, "true"); err != nil {
		t.Fatalf("set %s: %v", pinFlagStdin, err)
	}

	code := captureExit(t, func() {
		userRegisterCmd.Run(cmd, []string{"alice"})
	})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if mock.gotCreateUser != nil {
		t.Error("no account may be created on unusable PIN input")
	}
	if mock.gotBeginReg != nil {
		t.Error("no ceremony may be begun on unusable PIN input")
	}
}
