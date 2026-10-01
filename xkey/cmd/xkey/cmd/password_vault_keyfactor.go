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
	"log/slog"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/vaulttoken"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"github.com/spf13/cobra"
)

// This file is the key-factor half of the personal vault verbs: a vault
// factor whose secret only a private key in one of xKey's key backends
// recovers -- the slot 9d key of a PIV backend, a certificate's key, or a
// TPM key under a named policy. vaulttoken (shared with the xkey GUI and
// xkmsctl) does the work; this file opens xKey's local key store, the one
// the GUI uses, and names the key.

// Key factor flags.
const (
	vaultKeyFactorFlag  = "key-factor"
	vaultKeyBackendFlag = "key-backend"
	vaultKeyIDFlag      = "key-id"
	vaultTPMPolicyFlag  = "tpm-policy"
	vaultUnlockKeyFlag  = "key"
)

// Key factor errors.
var (
	// ErrPasswordKeyFactorConflict indicates a key factor was combined with
	// another factor: a vault verb sends exactly one.
	ErrPasswordKeyFactorConflict = errors.New("password: a key factor (--" + vaultKeyFactorFlag + ", --" + vaultUnlockKeyFlag +
		") cannot be combined with --passkey or --passphrase-stdin")

	// ErrPasswordKeyBackendRequired indicates --key-factor without
	// --key-backend.
	ErrPasswordKeyBackendRequired = errors.New("password: --" + vaultKeyBackendFlag + " names the xKey key backend holding the key (e.g. pkcs11, tpm2, software)")

	// ErrPasswordKeyStoreUnavailable indicates xKey's local key store could
	// not be opened.
	ErrPasswordKeyStoreUnavailable = errors.New("password: xKey's local key store could not be opened")
)

// vaultKeyFactorUsage documents the key-factor inputs in command help.
const vaultKeyFactorUsage = `With --key-factor the factor is a key in one of xKey's key backends; the
server seals the factor's secret to the key and only the key recovers it:

  --key-factor piv          the key in PIV slot 9d of --key-backend
  --key-factor certificate  key --key-id, with its certificate in the backend
  --key-factor tpm          TPM key --key-id (record its policy: --tpm-policy)

xKey's key store is opened with the barrier password
(--barrier-password-stdin, --barrier-password-file or XKEY_BARRIER_PASSWORD).`

// localKeyBackends opens xKey's local key store -- the barrier-protected
// "keys/" namespace and the backends the configuration names, exactly what
// the GUI runs -- and returns the backend lookup key factors resolve their
// tokens through. It is a package-level variable so tests can substitute
// their own backends.
var localKeyBackends = openLocalKeyBackends

func openLocalKeyBackends(cmd *cobra.Command) (vaulttoken.Lookup, error) {
	home, err := xhome.Resolve()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPasswordKeyStoreUnavailable, Cause: err}
	}
	dataDir, err := home.EnsureDataDir()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPasswordKeyStoreUnavailable, Cause: err}
	}
	barrier, _, err := resolveSecretStoreBackend(cmd, dataDir, "key store", slog.Default())
	if err != nil {
		return nil, err
	}
	var datastore xkms.StorageBackend
	if barrier != nil {
		if datastore, err = xkms.NewStoragePrefixBackend(barrier, "keys/"); err != nil {
			return nil, &SentinelCauseError{Sentinel: ErrPasswordKeyStoreUnavailable, Cause: err}
		}
	}
	configs := map[xkms.ServiceBackendType]map[string]interface{}{}
	if cfg := GetConfig(); cfg != nil {
		for name, c := range cfg.KeyBackendConfigs() {
			configs[xkms.ServiceBackendType(name)] = c
		}
	}
	xkms.Reset()
	if err := xkms.AutoInitialize(&xkms.AutoConfig{Datastore: datastore, DefaultBackend: "software", BackendConfigs: configs}); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrPasswordKeyStoreUnavailable, Cause: err}
	}
	return xkms.GetBackend, nil
}

// addVaultKeyFactorFlags declares the key-factor flags of a verb that
// enrolls one (enroll, recover).
func addVaultKeyFactorFlags(cmd *cobra.Command) {
	cmd.Flags().String(vaultKeyFactorFlag, "", "Enroll a key factor instead: piv, certificate or tpm")
	cmd.Flags().String(vaultKeyBackendFlag, "", "xKey key backend holding the key (e.g. pkcs11, tpm2, software)")
	cmd.Flags().String(vaultKeyIDFlag, "", "ID of the key in the backend (certificate, tpm; piv uses slot 9d)")
	cmd.Flags().String(vaultTPMPolicyFlag, "", "Named TPM policy the TPM key is bound to (recorded on the factor)")
	addBarrierPasswordFlags(cmd)
}

// addVaultUnlockKeyFlag declares --key on the unlock verb.
func addVaultUnlockKeyFlag(cmd *cobra.Command) {
	cmd.Flags().Bool(vaultUnlockKeyFlag, false, "Unlock with a PIV, certificate or TPM key factor whose key is in xKey's key backends")
	addBarrierPasswordFlags(cmd)
}

// resolveVaultKeySource returns the key-factor credential source a verb
// asked for, or nil when it asked for none. An enroll or recover verb names
// the key (--key-factor); the unlock verb takes the first vault key factor
// whose key is here (--key).
func resolveVaultKeySource(cmd *cobra.Command, label string, purpose vaultCredentialPurpose) (vaultCredentialSource, error) {
	if purpose == vaultUnlock {
		useKey, err := cmd.Flags().GetBool(vaultUnlockKeyFlag)
		if err != nil || !useKey {
			return nil, nil
		}
		return keyUnlockSource(cmd), nil
	}
	factor, err := cmd.Flags().GetString(vaultKeyFactorFlag)
	if err != nil || factor == "" {
		return nil, nil
	}
	backend, _ := cmd.Flags().GetString(vaultKeyBackendFlag)
	if backend == "" {
		return nil, ErrPasswordKeyBackendRequired
	}
	keyID, _ := cmd.Flags().GetString(vaultKeyIDFlag)
	policy, _ := cmd.Flags().GetString(vaultTPMPolicyFlag)
	ref := transport.PasswordVaultKeyRef{Backend: backend, KeyID: keyID, TPMPolicy: policy}
	return keyEnrollSource(cmd, factor, ref, label), nil
}

// keyEnrollSource resolves the named key, self-tests it -- a token that
// cannot open a secret sealed to its own key is refused before anything is
// enrolled -- and builds its enrollment credential.
func keyEnrollSource(cmd *cobra.Command, factor string, ref transport.PasswordVaultKeyRef, label string) vaultCredentialSource {
	return func(ctx context.Context, _ PasswordStoreClientService) (transport.PasswordVaultCredential, error) {
		lookup, err := localKeyBackends(cmd)
		if err != nil {
			return transport.PasswordVaultCredential{}, err
		}
		key, err := vaulttoken.Resolve(ctx, lookup, factor, ref)
		if err != nil {
			return transport.PasswordVaultCredential{}, err
		}
		if err := vaulttoken.SelfTest(ctx, key.Token); err != nil {
			return transport.PasswordVaultCredential{}, err
		}
		return vaulttoken.EnrollCredential(factor, key, label)
	}
}

// keyUnlockSource reads the vault's factors from the server and recovers
// the secret of the first key factor whose key is in xKey's backends.
func keyUnlockSource(cmd *cobra.Command) vaultCredentialSource {
	return func(ctx context.Context, client PasswordStoreClientService) (transport.PasswordVaultCredential, error) {
		status, err := client.PasswordVaultStatus(ctx)
		if err != nil {
			return transport.PasswordVaultCredential{}, &SentinelCauseError{Sentinel: ErrPasswordVaultStatusFailed, Cause: err}
		}
		lookup, err := localKeyBackends(cmd)
		if err != nil {
			return transport.PasswordVaultCredential{}, err
		}
		return vaulttoken.Find(ctx, lookup, status.Factors)
	}
}
