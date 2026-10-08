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
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/jeremyhahn/go-enclave"
	fido2 "github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/vaultpasskey"
	"github.com/spf13/cobra"
)

// This file is the passkey half of the personal vault verbs: a vault factor
// held by a FIDO2 security key's hmac-secret extension. The FIDO2 work is
// vaultpasskey's (sdk/go/vaultpasskey), shared with xkmsctl and the xkey GUI
// so a passkey enrolled on any surface unlocks on every other; this file only
// resolves the PIN, opens the authenticator and tells the user to touch it.

// vaultPasskeyFlag selects a passkey instead of a passphrase.
const vaultPasskeyFlag = "passkey"

// Personal vault passkey errors.
var (
	// ErrPasswordPasskeyWithPassphrase indicates --passkey was combined with
	// --passphrase-stdin: a vault verb sends exactly one factor.
	ErrPasswordPasskeyWithPassphrase = errors.New("password: --passkey and --passphrase-stdin are mutually exclusive")

	// ErrPasswordPINWithoutPasskey indicates --pin-stdin was given without
	// --passkey. The security key PIN serves only a vault passkey; it never
	// unlocks the vault by itself.
	ErrPasswordPINWithoutPasskey = errors.New("password: --" + pinFlagStdin + " is the security key PIN and needs --passkey")

	// ErrPasswordPasskeyPINRequired indicates no security key PIN was
	// supplied for a vault passkey, which is always PIN-verified.
	ErrPasswordPasskeyPINRequired = errors.New("password: a vault passkey needs your security key's PIN; supply it with --" +
		pinFlagStdin + " (preferred) or the " + pinEnvVar + " environment variable")

	// ErrPasswordPasskeySingleStdin indicates both the recovery code and the
	// security key PIN were asked to come from standard input.
	ErrPasswordPasskeySingleStdin = errors.New("password: only one of --recovery-code-stdin and --" + pinFlagStdin +
		" may be given; supply the other through its environment variable")

	// ErrPasswordVaultRotatePasskey indicates rotate named a passkey factor.
	// A passkey's secret is bound to its credential on the security key, so
	// there is no new secret to rotate to.
	ErrPasswordVaultRotatePasskey = errors.New("password: a passkey cannot be rotated: enroll a new passkey " +
		"('xkey password vault enroll --passkey') and remove the old one ('xkey password vault remove')")
)

// vaultPasskeyUsage documents the passkey inputs in command help.
const vaultPasskeyUsage = `With --passkey the factor is a passkey on your FIDO2 security key, always
verified with the key's PIN; touch the key when asked. The PIN may be
supplied two ways, in precedence order:

  --pin-stdin      read it from standard input (preferred)
  XKEY_PIN         environment variable

There is no "--pin" value flag: a value on the command line is visible to
every other process on the host via 'ps'.`

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
// authenticator for attached hardware.
var vaultAuthenticatorFactory = newVaultAuthenticator

// newVaultAuthenticator opens the attached FIDO2 security key -- or the xkey
// virtual authenticator -- over HID, discovered with the same enumerator the
// WebAuthn ceremonies use.
func newVaultAuthenticator() (vaultAuthenticator, error) {
	cfg := fido2.DefaultConfig
	cfg.Timeout = webauthnCeremonyTimeout
	cfg.UserPresenceTimeout = webauthnCeremonyTimeout
	handler, err := fido2.NewHandler(&cfg, webauthnEnumeratorFactory())
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrWebAuthnAuthenticatorUnavailable, Cause: err}
	}
	return handler, nil
}

// vaultCredentialSource produces the credential a vault verb sends. It runs
// once the server connection is open -- so a passkey is never created on a
// security key for a server that cannot be reached -- and is handed the
// client, which a passkey unlock needs to read the vault's factors.
type vaultCredentialSource func(ctx context.Context, client PasswordStoreClientService) (transport.PasswordVaultCredential, error)

// vaultCredentialPurpose says whether a vault credential sets a new factor
// (enroll, recover) or opens an existing one (unlock).
type vaultCredentialPurpose int

const (
	vaultNewFactor vaultCredentialPurpose = iota
	vaultUnlock
)

// addVaultPasskeyFlags declares --passkey and the security key PIN source on
// a vault verb.
func addVaultPasskeyFlags(cmd *cobra.Command, usage string) {
	cmd.Flags().Bool(vaultPasskeyFlag, false, usage)
	addPINFlags(cmd)
}

// resolveVaultCredentialSource resolves the factor an enroll, recover or
// unlock verb sends: a passkey when --passkey is set (its PIN resolved now,
// the authenticator driven once the server is reached), otherwise the
// passphrase from --passphrase-stdin or XKEY_VAULT_PASSPHRASE. The returned
// cleanup wipes the passphrase or destroys the sealed PIN.
func resolveVaultCredentialSource(cmd *cobra.Command, label string, purpose vaultCredentialPurpose) (vaultCredentialSource, func(), error) {
	usePasskey, err := cmd.Flags().GetBool(vaultPasskeyFlag)
	if err != nil {
		return nil, nil, err
	}
	passphraseFromStdin, err := cmd.Flags().GetBool(vaultPassphraseSource.stdinFlag)
	if err != nil {
		return nil, nil, err
	}
	pinFromStdin, err := cmd.Flags().GetBool(pinFlagStdin)
	if err != nil {
		return nil, nil, &SentinelCauseError{Sentinel: ErrPINInputFlagsMissing, Cause: err}
	}

	keySource, err := resolveVaultKeySource(cmd, label, purpose)
	if err != nil {
		return nil, nil, err
	}
	if keySource != nil {
		if usePasskey || passphraseFromStdin {
			return nil, nil, ErrPasswordKeyFactorConflict
		}
		return keySource, func() {}, nil
	}

	if !usePasskey {
		if pinFromStdin {
			return nil, nil, ErrPasswordPINWithoutPasskey
		}
		passphrase, err := resolveVaultSecret(cmd, vaultPassphraseSource, ErrPasswordMissingPassphrase)
		if err != nil {
			return nil, nil, err
		}
		source := func(context.Context, PasswordStoreClientService) (transport.PasswordVaultCredential, error) {
			return vaultPassphraseCredential(passphrase, label), nil
		}
		return source, func() { enclave.Wipe(passphrase) }, nil
	}

	if passphraseFromStdin {
		return nil, nil, ErrPasswordPasskeyWithPassphrase
	}
	pin, err := resolveVaultPasskeyPIN(cmd)
	if err != nil {
		return nil, nil, err
	}
	out := cmd.ErrOrStderr()
	if purpose == vaultUnlock {
		return passkeyUnlockSource(out, pin), pin.Destroy, nil
	}
	return passkeyEnrollSource(out, pin, label), pin.Destroy, nil
}

// resolveVaultPasskeyPIN resolves the security key PIN from the user PIN
// sources (--pin-stdin, XKEY_PIN) and seals it. A vault passkey is always
// user-verified, so no PIN is an error here rather than the authenticator's
// decision.
func resolveVaultPasskeyPIN(cmd *cobra.Command) (*secure.Secret, error) {
	pin, err := userPINSource.resolveBytes(cmd)
	if err != nil {
		return nil, err
	}
	if len(pin) == 0 {
		return nil, ErrPasswordPasskeyPINRequired
	}
	defer enclave.Wipe(pin)
	secret, err := secure.NewSecret(cmd.Context(), pin)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrWebAuthnPINSealFailed, Cause: err}
	}
	return secret, nil
}

// passkeyEnrollSource returns the source of a new vault passkey, created on
// the security key with label for the relying party the server advertises
// in its vault status.
func passkeyEnrollSource(out io.Writer, pin *secure.Secret, label string) vaultCredentialSource {
	return func(ctx context.Context, client PasswordStoreClientService) (transport.PasswordVaultCredential, error) {
		status, err := client.PasswordVaultStatus(ctx)
		if err != nil {
			return transport.PasswordVaultCredential{}, &SentinelCauseError{Sentinel: ErrPasswordVaultStatusFailed, Cause: err}
		}
		if status.PasskeyRPID == "" {
			return transport.PasswordVaultCredential{}, vaultpasskey.ErrNoRelyingParty
		}
		return withVaultAuthenticator(out, vaultPasskeyEnrollPrompt, func(a vaultpasskey.Authenticator) (transport.PasswordVaultCredential, error) {
			return vaultpasskey.Enroll(a, vaultpasskey.Options{PIN: pin, Label: label, RelyingPartyID: status.PasskeyRPID})
		})
	}
}

// passkeyUnlockSource returns the source of a passkey unlock credential: the
// vault's passkey factors, read from the server, evaluated on the security
// key.
func passkeyUnlockSource(out io.Writer, pin *secure.Secret) vaultCredentialSource {
	return func(ctx context.Context, client PasswordStoreClientService) (transport.PasswordVaultCredential, error) {
		status, err := client.PasswordVaultStatus(ctx)
		if err != nil {
			return transport.PasswordVaultCredential{}, &SentinelCauseError{Sentinel: ErrPasswordVaultStatusFailed, Cause: err}
		}
		return withVaultAuthenticator(out, vaultPasskeyUnlockPrompt, func(a vaultpasskey.Authenticator) (transport.PasswordVaultCredential, error) {
			return vaultpasskey.Unlock(a, status.Factors, vaultpasskey.Options{PIN: pin})
		})
	}
}

// withVaultAuthenticator opens the security key, asks the user on out to
// touch it, runs fn on it and closes it, joining a close failure into the
// result.
func withVaultAuthenticator(out io.Writer, prompt string, fn func(vaultpasskey.Authenticator) (transport.PasswordVaultCredential, error)) (cred transport.PasswordVaultCredential, err error) {
	authenticator, err := vaultAuthenticatorFactory()
	if err != nil {
		return transport.PasswordVaultCredential{}, err
	}
	defer func() {
		if closeErr := authenticator.Close(); closeErr != nil {
			clear(cred.Secret)
			cred = transport.PasswordVaultCredential{}
			err = errors.Join(err, closeErr)
		}
	}()

	if _, err := fmt.Fprintln(out, prompt); err != nil {
		return transport.PasswordVaultCredential{}, err
	}
	return fn(authenticator)
}
