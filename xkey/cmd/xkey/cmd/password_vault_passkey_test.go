// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest/vaultservice"
	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
	fido2 "github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/vaultpasskey"
)

// vaultSimKey is the shared simulated security key (vaulttest.SimulatedKey).
type vaultSimKey = vaulttest.SimulatedKey

func newVaultSimKey(pin string) *vaultSimKey { return vaulttest.NewSimulatedKey(pin) }

// useVaultSimKey makes the passkey verbs drive key and counts how often they
// open it.
func useVaultSimKey(t *testing.T, key *vaultSimKey) *int {
	t.Helper()
	opened := 0
	original := vaultAuthenticatorFactory
	t.Cleanup(func() { vaultAuthenticatorFactory = original })
	vaultAuthenticatorFactory = func() (vaultAuthenticator, error) {
		opened++
		return key, nil
	}
	return &opened
}

// vaultServerClient is user alice's password client on a real XKMSService:
// every call carries her identity, as an authenticating transport attaches
// it.
type vaultServerClient struct {
	svc *pkgxkms.XKMSService
}

func (c *vaultServerClient) ctx(ctx context.Context) context.Context {
	return auth.WithIdentity(ctx, &auth.Identity{Subject: "alice", TenantID: vaultservice.Tenant})
}

func (c *vaultServerClient) Connect(context.Context) error { return nil }
func (c *vaultServerClient) Close() error                  { return nil }

func (c *vaultServerClient) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	return c.svc.PasswordStoreUnlock(c.ctx(ctx), req)
}

func (c *vaultServerClient) PasswordStoreLock(ctx context.Context) error {
	return c.svc.PasswordStoreLock(c.ctx(ctx))
}

func (c *vaultServerClient) PasswordStoreStatus(ctx context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return c.svc.PasswordStoreStatus(c.ctx(ctx))
}

func (c *vaultServerClient) PasswordStoreSetAccessMode(ctx context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	return c.svc.PasswordStoreSetAccessMode(c.ctx(ctx), req)
}

func (c *vaultServerClient) PasswordVaultStatus(ctx context.Context) (*transport.PasswordVaultStatusResponse, error) {
	return c.svc.PasswordVaultStatus(c.ctx(ctx))
}

func (c *vaultServerClient) PasswordVaultEnroll(ctx context.Context, req *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return c.svc.PasswordVaultEnroll(c.ctx(ctx), req)
}

func (c *vaultServerClient) PasswordVaultRotate(ctx context.Context, req *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return c.svc.PasswordVaultRotate(c.ctx(ctx), req)
}

func (c *vaultServerClient) PasswordVaultRemoveFactor(ctx context.Context, req *transport.PasswordVaultRemoveFactorRequest) error {
	return c.svc.PasswordVaultRemoveFactor(c.ctx(ctx), req)
}

func (c *vaultServerClient) PasswordVaultRecover(ctx context.Context, req *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return c.svc.PasswordVaultRecover(c.ctx(ctx), req)
}

// newVaultServerClient connects the password commands to alice's vault on a
// real XKMSService, with every vault secret source cleared so only what the
// test sets reaches a command.
func newVaultServerClient(t *testing.T) *vaultServerClient {
	t.Helper()
	t.Setenv("XKEY_VAULT_PASSPHRASE", "")
	t.Setenv("XKEY_VAULT_RECOVERY_CODE", "")
	t.Setenv(pinEnvVar, "")
	client := &vaultServerClient{svc: vaultservice.New(t).Service}
	original := passwordClientFactory
	passwordClientFactory = func() (PasswordStoreClientService, error) { return client, nil }
	t.Cleanup(func() { passwordClientFactory = original })
	return client
}

func (c *vaultServerClient) status(t *testing.T) *transport.PasswordVaultStatusResponse {
	t.Helper()
	status, err := c.PasswordVaultStatus(context.Background())
	require.NoError(t, err)
	return status
}

func (c *vaultServerClient) passkeys(t *testing.T) []transport.PasswordVaultFactor {
	t.Helper()
	var passkeys []transport.PasswordVaultFactor
	for _, f := range c.status(t).Factors {
		if f.Factor == vaultpasskey.Factor {
			passkeys = append(passkeys, f)
		}
	}
	return passkeys
}

func (c *vaultServerClient) lock(t *testing.T) {
	t.Helper()
	require.NoError(t, c.PasswordStoreLock(context.Background()))
	require.False(t, c.status(t).Unlocked)
}

// runPasswordCmd executes "xkey password <args>" and returns its stdout,
// its stderr and its error.
func runPasswordCmd(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	resetCommandFlagsForTest(t, RootCmd)
	resetPasswordFlags()
	stdout, stderr := new(bytes.Buffer), new(bytes.Buffer)
	RootCmd.SetOut(stdout)
	RootCmd.SetErr(stderr)
	RootCmd.SetArgs(append([]string{"password"}, args...))
	err := RootCmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestPasswordVaultPasskey_EnrollThenUnlockEndToEnd(t *testing.T) {
	server := newVaultServerClient(t)
	key := newVaultSimKey("123456")
	opened := useVaultSimKey(t, key)
	stubStdin(t, []byte("123456\n"), nil)

	out, prompts, err := runPasswordCmd(t, "vault", "enroll", "--passkey", "--pin-stdin", "--label", "yubikey")
	require.NoError(t, err)
	assert.Contains(t, prompts, "Touch your security key")
	assert.Contains(t, out, "RECOVERY CODE", "the first enrollment shows the recovery code")
	assert.Contains(t, out, "passkey")
	assert.Equal(t, 1, *opened)
	assert.True(t, key.Closed, "the authenticator is closed after use")

	passkeys := server.passkeys(t)
	require.Len(t, passkeys, 1)
	assert.Equal(t, "yubikey", passkeys[0].Label)
	assert.True(t, server.status(t).Unlocked, "the first enrollment opens the session")

	server.lock(t)
	t.Setenv(pinEnvVar, "123456")
	out, prompts, err = runPasswordCmd(t, "unlock", "--passkey")
	require.NoError(t, err)
	assert.Contains(t, prompts, "Touch your security key to unlock")
	assert.Contains(t, out, "Password store unlocked.")
	assert.True(t, server.status(t).Unlocked, "the passkey opened the session on the server")
}

func TestPasswordVaultPasskey_UnlockRefusals(t *testing.T) {
	enrollPasskey := func(t *testing.T) {
		t.Helper()
		t.Setenv(pinEnvVar, "123456")
		_, _, err := runPasswordCmd(t, "vault", "enroll", "--passkey")
		require.NoError(t, err)
	}
	tests := []struct {
		name    string
		setup   func(t *testing.T)
		pin     string
		wantErr error
	}{
		{
			name: "wrong PIN",
			setup: func(t *testing.T) {
				useVaultSimKey(t, newVaultSimKey("123456"))
				enrollPasskey(t)
			},
			pin:     "000000",
			wantErr: fido2.ErrInvalidPIN,
		},
		{
			name: "no passkey enrolled",
			setup: func(t *testing.T) {
				t.Setenv("XKEY_VAULT_PASSPHRASE", "correct horse")
				_, _, err := runPasswordCmd(t, "vault", "enroll")
				require.NoError(t, err)
				t.Setenv("XKEY_VAULT_PASSPHRASE", "")
				useVaultSimKey(t, newVaultSimKey("123456"))
			},
			pin:     "123456",
			wantErr: vaultpasskey.ErrNoPasskeyEnrolled,
		},
		{
			name: "passkey enrolled on another key",
			setup: func(t *testing.T) {
				useVaultSimKey(t, newVaultSimKey("123456"))
				enrollPasskey(t)
				useVaultSimKey(t, newVaultSimKey("123456"))
			},
			pin:     "123456",
			wantErr: vaultpasskey.ErrNoMatchingPasskey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newVaultServerClient(t)
			tt.setup(t)
			server.lock(t)

			t.Setenv(pinEnvVar, tt.pin)
			_, _, err := runPasswordCmd(t, "unlock", "--passkey")
			assert.ErrorIs(t, err, tt.wantErr)
			assert.ErrorIs(t, err, ErrPasswordUnlockFailed)
			assert.False(t, server.status(t).Unlocked, "a refused passkey leaves the session locked")
		})
	}
}

func TestPasswordVaultPasskey_MissingPINNeverTouchesTheKey(t *testing.T) {
	newVaultServerClient(t)
	opened := useVaultSimKey(t, newVaultSimKey("123456"))

	_, _, err := runPasswordCmd(t, "unlock", "--passkey")
	assert.ErrorIs(t, err, ErrPasswordPasskeyPINRequired)

	stubStdin(t, []byte("\n"), nil)
	_, _, err = runPasswordCmd(t, "unlock", "--passkey", "--pin-stdin")
	assert.ErrorIs(t, err, ErrPINInputStdinEmpty)
	assert.Zero(t, *opened, "no PIN, no authenticator")
}

func TestPasswordVaultPasskey_RecoverWithPasskey(t *testing.T) {
	server := newVaultServerClient(t)
	t.Setenv("XKEY_VAULT_PASSPHRASE", "correct horse")
	out, _, err := runPasswordCmd(t, "vault", "enroll", "--label", "laptop")
	require.NoError(t, err)
	code := recoveryCodeFrom(t, out)
	t.Setenv("XKEY_VAULT_PASSPHRASE", "")
	server.lock(t)

	useVaultSimKey(t, newVaultSimKey("123456"))
	t.Setenv(pinEnvVar, "123456")
	stubStdin(t, []byte(code+"\n"), nil)
	out, _, err = runPasswordCmd(t, "vault", "recover", "--passkey", "--recovery-code-stdin", "--label", "spare key")
	require.NoError(t, err)
	assert.Contains(t, out, "Vault recovered")
	assert.NotEqual(t, code, recoveryCodeFrom(t, out), "recovery issues a new code")

	passkeys := server.passkeys(t)
	require.Len(t, passkeys, 1)
	assert.Equal(t, "spare key", passkeys[0].Label)

	server.lock(t)
	_, _, err = runPasswordCmd(t, "unlock", "--passkey")
	require.NoError(t, err)
	assert.True(t, server.status(t).Unlocked, "the recovered passkey unlocks the vault")
}

// recoveryCodeFrom returns the recovery code a vault enroll or recover
// printed.
func recoveryCodeFrom(t *testing.T, out string) string {
	t.Helper()
	_, rest, found := strings.Cut(out, "RECOVERY CODE ================================\n")
	require.True(t, found, "no recovery code in:\n%s", out)
	code, _, found := strings.Cut(rest, "\n")
	require.True(t, found)
	return strings.TrimSpace(code)
}

func TestPasswordVaultPasskey_FlagRefusals(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr error
	}{
		{"passkey with passphrase", []string{"vault", "enroll", "--passkey", "--passphrase-stdin"}, ErrPasswordPasskeyWithPassphrase},
		{"PIN without passkey", []string{"unlock", "--pin-stdin"}, ErrPasswordPINWithoutPasskey},
		{"recovery code and PIN both on stdin", []string{"vault", "recover", "--passkey", "--recovery-code-stdin", "--pin-stdin"}, ErrPasswordPasskeySingleStdin},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newVaultServerClient(t)
			opened := useVaultSimKey(t, newVaultSimKey("123456"))
			stubStdin(t, []byte("123456\n"), nil)
			_, _, err := runPasswordCmd(t, tt.args...)
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Zero(t, *opened)
			assert.False(t, server.status(t).Initialized)
		})
	}
}

func TestPasswordVaultPasskey_RotateRefusesAPasskey(t *testing.T) {
	server := newVaultServerClient(t)
	useVaultSimKey(t, newVaultSimKey("123456"))
	t.Setenv(pinEnvVar, "123456")
	_, _, err := runPasswordCmd(t, "vault", "enroll", "--passkey", "--label", "yubikey")
	require.NoError(t, err)
	enrolled := server.passkeys(t)
	require.Len(t, enrolled, 1)

	// No passphrase is supplied: the refusal comes before one is read.
	_, _, err = runPasswordCmd(t, "vault", "rotate", "--factor-id", enrolled[0].ID)
	require.ErrorIs(t, err, ErrPasswordVaultRotatePasskey)
	assert.Contains(t, err.Error(), "enroll a new passkey")
	assert.Contains(t, err.Error(), "remove the old one")
	assert.Equal(t, enrolled, server.passkeys(t), "the passkey is untouched")
}

func TestPasswordVaultPasskey_RotateStillRotatesAPassphrase(t *testing.T) {
	server := newVaultServerClient(t)
	t.Setenv("XKEY_VAULT_PASSPHRASE", "correct horse")
	_, _, err := runPasswordCmd(t, "vault", "enroll", "--label", "laptop")
	require.NoError(t, err)
	var factorID string
	for _, f := range server.status(t).Factors {
		if f.Factor == vaultFactorPassphrase {
			factorID = f.ID
		}
	}

	t.Setenv("XKEY_VAULT_PASSPHRASE", "new phrase")
	out, _, err := runPasswordCmd(t, "vault", "rotate", "--factor-id", factorID)
	require.NoError(t, err)
	assert.Contains(t, out, "laptop", "the current label is kept")

	server.lock(t)
	_, _, err = runPasswordCmd(t, "unlock")
	require.NoError(t, err, "the rotated passphrase unlocks")
}

func TestPasswordVaultPasskey_NoSecurityKey(t *testing.T) {
	server := newVaultServerClient(t)
	errNoKey := errors.New("no FIDO2 device")
	original := vaultAuthenticatorFactory
	t.Cleanup(func() { vaultAuthenticatorFactory = original })
	vaultAuthenticatorFactory = func() (vaultAuthenticator, error) { return nil, errNoKey }
	t.Setenv(pinEnvVar, "123456")

	_, _, err := runPasswordCmd(t, "vault", "enroll", "--passkey")
	assert.ErrorIs(t, err, ErrPasswordVaultEnrollFailed)
	assert.ErrorIs(t, err, errNoKey)
	assert.False(t, server.status(t).Initialized)
}

// failingCloseKey is a security key whose handle fails to close.
type failingCloseKey struct{ *vaultSimKey }

var errVaultKeyClose = errors.New("close failed")

func (failingCloseKey) Close() error { return errVaultKeyClose }

func TestWithVaultAuthenticator_CloseFailureDiscardsTheSecret(t *testing.T) {
	key := failingCloseKey{newVaultSimKey("123456")}
	original := vaultAuthenticatorFactory
	t.Cleanup(func() { vaultAuthenticatorFactory = original })
	vaultAuthenticatorFactory = func() (vaultAuthenticator, error) { return key, nil }

	pin, err := secure.NewSecret(t.Context(), []byte("123456"))
	require.NoError(t, err)
	defer pin.Destroy()
	cred, err := withVaultAuthenticator(new(bytes.Buffer), vaultPasskeyEnrollPrompt, func(a vaultpasskey.Authenticator) (transport.PasswordVaultCredential, error) {
		return vaultpasskey.Enroll(a, vaultpasskey.Options{PIN: pin, RelyingPartyID: vaulttest.RelyingParty})
	})
	assert.ErrorIs(t, err, errVaultKeyClose)
	assert.Empty(t, cred.Secret, "a failed close returns no secret")
}

func TestNewVaultAuthenticator_UsesTheWebAuthnEnumerator(t *testing.T) {
	// The default factory discovers keys with the WebAuthn enumerator; one
	// that finds nothing fails the enrollment at discovery, never with a PIN
	// error.
	installEnumerator(t, &fakeEnumerator{})

	a, err := newVaultAuthenticator()
	require.NoError(t, err)
	defer func() { require.NoError(t, a.Close()) }()
	pin, err := secure.NewSecret(t.Context(), []byte("123456"))
	require.NoError(t, err)
	defer pin.Destroy()
	_, err = vaultpasskey.Enroll(a, vaultpasskey.Options{PIN: pin, RelyingPartyID: vaulttest.RelyingParty})
	assert.ErrorIs(t, err, pkgfido2.ErrNoDeviceFound)
}
