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
	"context"
	"io"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/sdk/go/vaultpasskey"
	"github.com/spf13/cobra"
)

// This file is the passkey half of the personal vault verbs: a vault factor
// held by a FIDO2 security key's hmac-secret extension. The FIDO2 work is
// vaultpasskey's (sdk/go/vaultpasskey), shared with the xkey CLI and GUI so a
// passkey enrolled on any surface unlocks on every other; this file only
// resolves the PIN, opens the authenticator and tells the user to touch it.

// vaultPasskeyPINUsage documents the security key PIN inputs in the help of
// every vault verb that takes --passkey. The sources are the WebAuthn verbs'
// (pin_input.go); a vault passkey adds a no-echo prompt on a terminal because
// it always needs the PIN.
const vaultPasskeyPINUsage = `With --passkey the security key's PIN is always required. It is taken, in
precedence order, from --pin-stdin (preferred), the XKMS_FIDO2_PIN environment
variable, --pin (visible in 'ps'), or an interactive no-echo prompt on a
terminal.`

// Touch prompts. Enrollment touches the key twice: once to create the
// passkey and once to derive its secret.
const (
	vaultPasskeyEnrollPrompt = "Touch your security key to create the vault passkey, then touch it again to derive its secret..."
	vaultPasskeyUnlockPrompt = "Touch your security key to unlock your vault..."
)

// vaultAuthenticator is the FIDO2 authenticator a vault passkey runs on.
// *fido2.FIDO2Handler satisfies it.
type vaultAuthenticator interface {
	vaultpasskey.Authenticator
	io.Closer
}

// vaultAuthenticatorFactory opens the authenticator the passkey verbs drive.
// It is a package-level variable so tests can substitute a simulated
// authenticator for attached hardware; the release binary never reassigns it.
var vaultAuthenticatorFactory = defaultVaultAuthenticatorFactory

// defaultVaultAuthenticatorFactory opens the attached FIDO2 security key over
// HID, discovered with the same enumerator the WebAuthn verbs use.
func defaultVaultAuthenticatorFactory(cfg *Config) (vaultAuthenticator, error) {
	fidoConfig := fido2.DefaultConfig
	handler, err := fido2.NewHandler(&fidoConfig, cfg.HIDDeviceEnumerator())
	if err != nil {
		return nil, err
	}
	return handler, nil
}

// resolveVaultPasskeyPIN resolves the security key PIN a vault passkey
// needs: from the WebAuthn PIN sources (resolvePINInput), else from a no-echo
// prompt on a terminal. A vault passkey is always user-verified, so no PIN is
// an error here rather than the authenticator's decision.
func resolveVaultPasskeyPIN(cmd *cobra.Command) (*secure.Secret, error) {
	pin, err := resolvePINInput(cmd)
	if err != nil || pin != nil {
		return pin, err
	}
	if !isTerminalFn(secretStdinFd()) {
		return nil, ErrVaultPasskeyPINRequired
	}
	typed, err := resolveSecret("", "Security key PIN")
	if err != nil {
		return nil, err
	}
	if typed == "" {
		return nil, ErrVaultPasskeyPINRequired
	}
	return sealPIN(typed)
}

// passkeyEnrollSource returns the source of a new vault passkey, created on
// the security key with label.
func passkeyEnrollSource(cfg *Config, printer *Printer, pin *secure.Secret, label string) vaultCredentialSource {
	return func(context.Context, client.Client) (client.PasswordVaultCredential, error) {
		return withVaultAuthenticator(cfg, printer, vaultPasskeyEnrollPrompt, func(a vaultpasskey.Authenticator) (client.PasswordVaultCredential, error) {
			return vaultpasskey.Enroll(a, vaultpasskey.Options{PIN: pin, Label: label})
		})
	}
}

// passkeyUnlockSource returns the source of a passkey unlock credential: the
// vault's passkey factors, read from the server, evaluated on the security
// key.
func passkeyUnlockSource(cfg *Config, printer *Printer, pin *secure.Secret) vaultCredentialSource {
	return func(ctx context.Context, cl client.Client) (client.PasswordVaultCredential, error) {
		status, err := cl.PasswordVaultStatus(ctx)
		if err != nil {
			return client.PasswordVaultCredential{}, &WrappedError{Sentinel: ErrVaultStatusFailed, Err: err}
		}
		return withVaultAuthenticator(cfg, printer, vaultPasskeyUnlockPrompt, func(a vaultpasskey.Authenticator) (client.PasswordVaultCredential, error) {
			return vaultpasskey.Unlock(a, status.Factors, vaultpasskey.Options{PIN: pin})
		})
	}
}

// withVaultAuthenticator opens the security key, asks the user to touch it,
// runs fn on it and closes it.
func withVaultAuthenticator(cfg *Config, printer *Printer, prompt string, fn func(vaultpasskey.Authenticator) (client.PasswordVaultCredential, error)) (client.PasswordVaultCredential, error) {
	authenticator, err := vaultAuthenticatorFactory(cfg)
	if err != nil {
		return client.PasswordVaultCredential{}, &WrappedError{Sentinel: ErrCreateFIDO2HandlerFailed, Err: err}
	}
	defer closeQuietly(authenticator)

	if err := printer.PrintPrompt(prompt); err != nil {
		return client.PasswordVaultCredential{}, err
	}
	return fn(authenticator)
}
