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

package main

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest/vaultservice"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/vaultpasskey"
)

// simKey is the shared simulated security key (vaulttest.SimulatedKey).
type simKey = vaulttest.SimulatedKey

func newSimKey(pin string) *simKey { return vaulttest.NewSimulatedKey(pin) }

// useSimKey makes the passkey verbs drive key and counts how often they
// open it.
func useSimKey(t *testing.T, key *simKey) *int {
	t.Helper()
	opened := 0
	original := vaultAuthenticatorFactory
	t.Cleanup(func() { vaultAuthenticatorFactory = original })
	vaultAuthenticatorFactory = func(*Config, string) (vaultAuthenticator, error) {
		opened++
		return key, nil
	}
	return &opened
}

// aliceService is the real vault service as seen by user alice: every vault
// call carries her identity, as the authenticating transports attach it.
type aliceService struct {
	*xkms.XKMSService
}

func alice(ctx context.Context) context.Context {
	return auth.WithIdentity(ctx, &auth.Identity{Subject: "alice", TenantID: vaultservice.Tenant})
}

func (s aliceService) PasswordStoreUnlock(ctx context.Context, req *transport.PasswordStoreUnlockRequest) error {
	return s.XKMSService.PasswordStoreUnlock(alice(ctx), req)
}

func (s aliceService) PasswordStoreLock(ctx context.Context) error {
	return s.XKMSService.PasswordStoreLock(alice(ctx))
}

func (s aliceService) PasswordVaultStatus(ctx context.Context) (*transport.PasswordVaultStatusResponse, error) {
	return s.XKMSService.PasswordVaultStatus(alice(ctx))
}

func (s aliceService) PasswordVaultEnroll(ctx context.Context, req *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return s.XKMSService.PasswordVaultEnroll(alice(ctx), req)
}

func (s aliceService) PasswordVaultRotate(ctx context.Context, req *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return s.XKMSService.PasswordVaultRotate(alice(ctx), req)
}

func (s aliceService) PasswordVaultRecover(ctx context.Context, req *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	return s.XKMSService.PasswordVaultRecover(alice(ctx), req)
}

// vaultServer is alice's vault on a real XKMSService, reached by xkmsctl
// through the SDK's embedded transport.
type vaultServer struct {
	svc aliceService
	cfg *Config
}

func newVaultServer(t *testing.T) *vaultServer {
	t.Helper()
	t.Setenv(pinEnvVar, "")
	svc := aliceService{vaultservice.New(t).Service}
	cfg := &Config{
		OutputFormat: "text",
		ClientFactory: func(*Config) (client.Client, error) {
			return client.NewEmbedded(svc)
		},
	}
	withGlobalConfig(t, cfg)
	return &vaultServer{svc: svc, cfg: cfg}
}

func (v *vaultServer) status(t *testing.T) *transport.PasswordVaultStatusResponse {
	t.Helper()
	status, err := v.svc.PasswordVaultStatus(context.Background())
	require.NoError(t, err)
	return status
}

func (v *vaultServer) lock(t *testing.T) {
	t.Helper()
	require.NoError(t, v.svc.PasswordStoreLock(context.Background()))
	require.False(t, v.status(t).Unlocked)
}

// passkeys returns the vault's passkey factors.
func (v *vaultServer) passkeys(t *testing.T) []transport.PasswordVaultFactor {
	t.Helper()
	var passkeys []transport.PasswordVaultFactor
	for _, f := range v.status(t).Factors {
		if f.Factor == vaultpasskey.Factor {
			passkeys = append(passkeys, f)
		}
	}
	return passkeys
}

// enrollPassphrase enrolls alice's first factor, a passphrase, and returns
// the recovery code.
func (v *vaultServer) enrollPassphrase(t *testing.T) string {
	t.Helper()
	resp, err := enrollVaultFactor(v.cfg, passphraseSource("correct horse", "laptop"))
	require.NoError(t, err)
	return resp.RecoveryCode
}

// discardPrinter swallows the touch prompts of the function-level tests.
func discardPrinter() *Printer {
	return NewPrinter("text", &bytes.Buffer{})
}

// init gives the vault commands the context Execute would: these tests drive
// Run directly, which leaves cmd.Context() nil, and the PIN is sealed under
// the command's context.
func init() {
	for _, cmd := range []*cobra.Command{passwordVaultEnrollCmd, passwordVaultRotateCmd, passwordVaultRecoverCmd, passwordUnlockCmd} {
		cmd.SetContext(context.Background())
	}
}

func TestPasskeyVault_EnrollThenUnlockEndToEnd(t *testing.T) {
	server := newVaultServer(t)
	key := newSimKey("123456")
	opened := useSimKey(t, key)

	resetCmdFlags(t, passwordVaultEnrollCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultEnrollCmd) })
	require.NoError(t, passwordVaultEnrollCmd.Flags().Set("passkey", "true"))
	require.NoError(t, passwordVaultEnrollCmd.Flags().Set("pin", "123456"))
	require.NoError(t, passwordVaultEnrollCmd.Flags().Set("label", "yubikey"))

	out := captureStdout(t, func() { passwordVaultEnrollCmd.Run(passwordVaultEnrollCmd, nil) })
	assert.Contains(t, out, "Touch your security key")
	assert.Contains(t, out, "RECOVERY CODE", "the first enrollment shows the recovery code")
	assert.Contains(t, out, "passkey")
	assert.Equal(t, 1, *opened)
	assert.True(t, key.Closed, "the authenticator is closed after use")

	passkeys := server.passkeys(t)
	require.Len(t, passkeys, 1)
	assert.Equal(t, "yubikey", passkeys[0].Label)
	assert.True(t, server.status(t).Unlocked, "the first enrollment opens the session")

	server.lock(t)
	resetCmdFlags(t, passwordUnlockCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordUnlockCmd) })
	require.NoError(t, passwordUnlockCmd.Flags().Set("passkey", "true"))
	require.NoError(t, passwordUnlockCmd.Flags().Set("pin", "123456"))

	out = captureStdout(t, func() { passwordUnlockCmd.Run(passwordUnlockCmd, nil) })
	assert.Contains(t, out, "Touch your security key to unlock")
	assert.Contains(t, out, "unlocked")
	assert.True(t, server.status(t).Unlocked, "the passkey opened the session on the server")
}

func TestPasskeyVault_UnlockRefusals(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, server *vaultServer) *simKey
		pin     string
		wantErr error
	}{
		{
			name: "wrong PIN",
			setup: func(t *testing.T, server *vaultServer) *simKey {
				key := newSimKey("123456")
				useSimKey(t, key)
				_, err := enrollVaultFactor(server.cfg, passkeyEnrollSource(server.cfg, discardPrinter(), testPINSecret(t, "123456"), "", ""))
				require.NoError(t, err)
				return key
			},
			pin:     "000000",
			wantErr: fido2.ErrInvalidPIN,
		},
		{
			name: "no passkey enrolled",
			setup: func(t *testing.T, server *vaultServer) *simKey {
				server.enrollPassphrase(t)
				key := newSimKey("123456")
				useSimKey(t, key)
				return key
			},
			pin:     "123456",
			wantErr: vaultpasskey.ErrNoPasskeyEnrolled,
		},
		{
			name: "passkey enrolled on another key",
			setup: func(t *testing.T, server *vaultServer) *simKey {
				useSimKey(t, newSimKey("123456"))
				_, err := enrollVaultFactor(server.cfg, passkeyEnrollSource(server.cfg, discardPrinter(), testPINSecret(t, "123456"), "", ""))
				require.NoError(t, err)
				other := newSimKey("123456")
				useSimKey(t, other)
				return other
			},
			pin:     "123456",
			wantErr: vaultpasskey.ErrNoMatchingPasskey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newVaultServer(t)
			tt.setup(t, server)
			server.lock(t)

			err := unlockPasswordStore(server.cfg, passkeyUnlockSource(server.cfg, discardPrinter(), testPINSecret(t, tt.pin), ""))
			assert.ErrorIs(t, err, tt.wantErr)
			assert.ErrorIs(t, err, ErrUnlockPasswordStoreFailed)
			assert.False(t, server.status(t).Unlocked, "a refused passkey leaves the session locked")
		})
	}
}

func TestPasskeyVault_MissingPINNeverTouchesTheKey(t *testing.T) {
	newVaultServer(t)
	opened := useSimKey(t, newSimKey("123456"))
	withPromptInput(t, "")

	resetCmdFlags(t, passwordUnlockCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordUnlockCmd) })
	require.NoError(t, passwordUnlockCmd.Flags().Set("passkey", "true"))

	_, err := resolveVaultPasskeyPIN(t.Context(), passwordUnlockCmd)
	assert.ErrorIs(t, err, ErrVaultPasskeyPINRequired)

	if code := captureExit(t, func() { passwordUnlockCmd.Run(passwordUnlockCmd, nil) }); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	assert.Zero(t, *opened, "no PIN, no authenticator")
}

func TestResolveVaultPasskeyPIN_Sources(t *testing.T) {
	t.Run("terminal prompt", func(t *testing.T) {
		t.Setenv(pinEnvVar, "")
		resetCmdFlags(t, passwordUnlockCmd)
		withTerminalPrompt(t, "246810", nil)
		pin, err := resolveVaultPasskeyPIN(t.Context(), passwordUnlockCmd)
		require.NoError(t, err)
		defer pin.Destroy()
		buf, err := pin.Open(t.Context())
		require.NoError(t, err)
		defer buf.Destroy()
		assert.Equal(t, "246810", string(buf.Bytes()))
	})
	t.Run("empty terminal entry", func(t *testing.T) {
		t.Setenv(pinEnvVar, "")
		resetCmdFlags(t, passwordUnlockCmd)
		withTerminalPrompt(t, "", nil)
		_, err := resolveVaultPasskeyPIN(t.Context(), passwordUnlockCmd)
		assert.ErrorIs(t, err, ErrVaultPasskeyPINRequired)
	})
	t.Run("environment wins over the prompt", func(t *testing.T) {
		t.Setenv(pinEnvVar, "135791")
		resetCmdFlags(t, passwordUnlockCmd)
		withTerminalPrompt(t, "", errPromptBoom)
		pin, err := resolveVaultPasskeyPIN(t.Context(), passwordUnlockCmd)
		require.NoError(t, err)
		pin.Destroy()
	})
	t.Run("terminal read failure", func(t *testing.T) {
		t.Setenv(pinEnvVar, "")
		resetCmdFlags(t, passwordUnlockCmd)
		withTerminalPrompt(t, "", errPromptBoom)
		_, err := resolveVaultPasskeyPIN(t.Context(), passwordUnlockCmd)
		assert.ErrorIs(t, err, errPromptBoom)
	})
}

func TestPasskeyVault_RecoverWithPasskey(t *testing.T) {
	server := newVaultServer(t)
	code := server.enrollPassphrase(t)
	require.NotEmpty(t, code)
	server.lock(t)
	useSimKey(t, newSimKey("123456"))
	withPromptInput(t, code+"\n")

	resetCmdFlags(t, passwordVaultRecoverCmd)
	t.Cleanup(func() { resetCmdFlags(t, passwordVaultRecoverCmd) })
	require.NoError(t, passwordVaultRecoverCmd.Flags().Set("passkey", "true"))
	require.NoError(t, passwordVaultRecoverCmd.Flags().Set("pin", "123456"))
	require.NoError(t, passwordVaultRecoverCmd.Flags().Set("label", "spare key"))

	out := captureStdout(t, func() { passwordVaultRecoverCmd.Run(passwordVaultRecoverCmd, nil) })
	assert.Contains(t, out, "Vault recovered")
	assert.Contains(t, out, "RECOVERY CODE")
	assert.NotContains(t, out, code, "recovery issues a new code")

	status := server.status(t)
	assert.True(t, status.Unlocked)
	factors := map[string]string{}
	for _, f := range status.Factors {
		factors[f.Label] = f.Factor
	}
	assert.Equal(t, vaultpasskey.Factor, factors["spare key"])

	server.lock(t)
	require.NoError(t, unlockPasswordStore(server.cfg, passkeyUnlockSource(server.cfg, discardPrinter(), testPINSecret(t, "123456"), "")))
	assert.True(t, server.status(t).Unlocked, "the recovered passkey unlocks the vault")
}

func TestPasskeyVault_RecoverRefusals(t *testing.T) {
	t.Run("recovery code and PIN both on stdin", func(t *testing.T) {
		newVaultServer(t)
		opened := useSimKey(t, newSimKey("123456"))
		resetCmdFlags(t, passwordVaultRecoverCmd)
		t.Cleanup(func() { resetCmdFlags(t, passwordVaultRecoverCmd) })
		require.NoError(t, passwordVaultRecoverCmd.Flags().Set("passkey", "true"))
		require.NoError(t, passwordVaultRecoverCmd.Flags().Set("recovery-code", "-"))
		require.NoError(t, passwordVaultRecoverCmd.Flags().Set(pinFlagStdin, "true"))

		if code := captureExit(t, func() { passwordVaultRecoverCmd.Run(passwordVaultRecoverCmd, nil) }); code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
		assert.Zero(t, *opened)
	})
	t.Run("a spent code enrolls no passkey", func(t *testing.T) {
		server := newVaultServer(t)
		server.enrollPassphrase(t)
		server.lock(t)
		useSimKey(t, newSimKey("123456"))
		_, err := recoverVault(server.cfg, "NOT-THE-CODE", passkeyEnrollSource(server.cfg, discardPrinter(), testPINSecret(t, "123456"), "", ""))
		assert.ErrorIs(t, err, ErrVaultRecoverFailed)
		assert.Empty(t, server.passkeys(t))
	})
}

func TestPasskeyVault_RotateRefusesAPasskey(t *testing.T) {
	server := newVaultServer(t)
	useSimKey(t, newSimKey("123456"))
	enrolled, err := enrollVaultFactor(server.cfg, passkeyEnrollSource(server.cfg, discardPrinter(), testPINSecret(t, "123456"), "", "yubikey"))
	require.NoError(t, err)
	// A terminal that fails any read proves no passphrase is asked for.
	withTerminalPrompt(t, "", errPromptBoom)

	_, err = rotateVaultFactor(server.cfg, enrolled.Factor.ID, "", "")
	require.ErrorIs(t, err, ErrVaultRotatePasskey)
	assert.Contains(t, err.Error(), "enroll a new passkey")
	assert.Contains(t, err.Error(), "remove the old one")

	passkeys := server.passkeys(t)
	require.Len(t, passkeys, 1)
	assert.Equal(t, enrolled.Factor.ID, passkeys[0].ID, "the passkey is untouched")
}

func TestPasskeyVault_RotateStillRotatesAPassphrase(t *testing.T) {
	server := newVaultServer(t)
	server.enrollPassphrase(t)
	var factorID string
	for _, f := range server.status(t).Factors {
		if f.Factor == vaultFactorPassphrase {
			factorID = f.ID
		}
	}

	resp, err := rotateVaultFactor(server.cfg, factorID, "new phrase", "")
	require.NoError(t, err)
	assert.Equal(t, "laptop", resp.Factor.Label, "the current label is kept")

	server.lock(t)
	require.NoError(t, unlockPasswordStore(server.cfg, passphraseSource("new phrase", "")))
}

func TestPasskeyVault_FlagConflictsAndAuthenticatorFailure(t *testing.T) {
	t.Run("passkey with passphrase", func(t *testing.T) {
		server := newVaultServer(t)
		resetCmdFlags(t, passwordVaultEnrollCmd)
		t.Cleanup(func() { resetCmdFlags(t, passwordVaultEnrollCmd) })
		require.NoError(t, passwordVaultEnrollCmd.Flags().Set("passkey", "true"))
		require.NoError(t, passwordVaultEnrollCmd.Flags().Set("passphrase", "correct horse"))

		_, _, err := resolveVaultCredentialSource(passwordVaultEnrollCmd, server.cfg, discardPrinter(), true, "correct horse", "", vaultNewFactor)
		assert.ErrorIs(t, err, ErrVaultPasskeyWithPassphrase)
		if code := captureExit(t, func() { passwordVaultEnrollCmd.Run(passwordVaultEnrollCmd, nil) }); code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
		assert.False(t, server.status(t).Initialized)
	})
	t.Run("PIN without passkey", func(t *testing.T) {
		server := newVaultServer(t)
		resetCmdFlags(t, passwordUnlockCmd)
		t.Cleanup(func() { resetCmdFlags(t, passwordUnlockCmd) })
		require.NoError(t, passwordUnlockCmd.Flags().Set(pinFlagValue, "123456"))
		require.NoError(t, passwordUnlockCmd.Flags().Set("passphrase", "correct horse"))

		_, _, err := resolveVaultCredentialSource(passwordUnlockCmd, server.cfg, discardPrinter(), false, "correct horse", "", vaultUnlock)
		assert.ErrorIs(t, err, ErrVaultPINWithoutPasskey)
	})
	t.Run("device without passkey", func(t *testing.T) {
		server := newVaultServer(t)
		resetCmdFlags(t, passwordUnlockCmd)
		t.Cleanup(func() { resetCmdFlags(t, passwordUnlockCmd) })
		require.NoError(t, passwordUnlockCmd.Flags().Set(passkeyDeviceFlag, "/dev/hidraw7"))

		_, _, err := resolveVaultCredentialSource(passwordUnlockCmd, server.cfg, discardPrinter(), false, "correct horse", "", vaultUnlock)
		assert.ErrorIs(t, err, ErrVaultDeviceWithoutPasskey)
	})
	t.Run("the named security key is opened", func(t *testing.T) {
		server := newVaultServer(t)
		var opened string
		original := vaultAuthenticatorFactory
		t.Cleanup(func() { vaultAuthenticatorFactory = original })
		vaultAuthenticatorFactory = func(_ *Config, device string) (vaultAuthenticator, error) {
			opened = device
			return nil, errors.New("no FIDO2 device")
		}
		resetCmdFlags(t, passwordVaultEnrollCmd)
		t.Cleanup(func() { resetCmdFlags(t, passwordVaultEnrollCmd) })
		require.NoError(t, passwordVaultEnrollCmd.Flags().Set(pinFlagValue, "123456"))
		require.NoError(t, passwordVaultEnrollCmd.Flags().Set(passkeyDeviceFlag, "/dev/hidraw7"))

		source, cleanup, err := resolveVaultCredentialSource(passwordVaultEnrollCmd, server.cfg, discardPrinter(), true, "", "", vaultNewFactor)
		require.NoError(t, err)
		defer cleanup()
		_, err = enrollVaultFactor(server.cfg, source)
		assert.Error(t, err)
		assert.Equal(t, "/dev/hidraw7", opened)
	})
	t.Run("no security key", func(t *testing.T) {
		server := newVaultServer(t)
		errNoKey := errors.New("no FIDO2 device")
		original := vaultAuthenticatorFactory
		t.Cleanup(func() { vaultAuthenticatorFactory = original })
		vaultAuthenticatorFactory = func(*Config, string) (vaultAuthenticator, error) { return nil, errNoKey }

		_, err := enrollVaultFactor(server.cfg, passkeyEnrollSource(server.cfg, discardPrinter(), testPINSecret(t, "123456"), "", ""))
		assert.ErrorIs(t, err, ErrCreateFIDO2HandlerFailed)
		assert.ErrorIs(t, err, errNoKey)
		assert.False(t, server.status(t).Initialized)
	})
}

func TestDefaultVaultAuthenticatorFactory_UsesTheConfiguredEnumerator(t *testing.T) {
	// The default factory discovers keys with the config's HID enumerator;
	// one that finds nothing fails the enrollment at discovery, never with a
	// PIN error.
	a, err := defaultVaultAuthenticatorFactory(&Config{HIDEnumerator: noHIDEnumerator{}}, "")
	require.NoError(t, err)
	defer closeQuietly(a)
	_, err = vaultpasskey.Enroll(a, vaultpasskey.Options{PIN: testPINSecret(t, "123456"), RelyingPartyID: vaulttest.RelyingParty})
	assert.ErrorIs(t, err, pkgfido2.ErrNoDeviceFound)
}
