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

package services

import (
	"context"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/vaulttoken"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// This file is the key-factor half of the personal vault: a PIV card's
// slot 9d key, a certificate's key or a TPM key, held in one of xKey's own
// key backends (the PIV, PKCS#11, TPM and software backends the app runs).
// The server seals each factor's secret to the key's public half; xKey
// recovers it with the key, which never leaves its backend, and sends only
// that secret. vaulttoken (shared with the xkey CLI and xkmsctl) does the
// work.

// keyBackends returns the key backend lookup key factors resolve their
// tokens through: xKey's running xkms backends, unless a test set one.
func (s *StaticPasswordService) keyBackends() vaulttoken.Lookup {
	if s.keyLookup != nil {
		return s.keyLookup
	}
	return xkmssdk.GetBackend
}

// EnrollKeyFactor enrolls a key held in one of xKey's key backends as a
// vault factor: factor is "piv" (the slot 9d key of the PIV backend
// backend), "certificate" (key keyID with its certificate) or "tpm" (TPM key
// keyID under named policy tpmPolicy). The first enrollment initializes the
// vault and returns the recovery code. The key is self-tested first
// (vaulttoken.SelfTest), so a token that cannot open a secret sealed to it
// is refused before anything is enrolled.
func (s *StaticPasswordService) EnrollKeyFactor(factor, backend, keyID, tpmPolicy, label string) (*PasswordVaultEnrollResult, error) {
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}
	ctx := s.getContext()
	cred, err := s.keyFactorCredential(ctx, factor, backend, keyID, tpmPolicy, label)
	if err != nil {
		return s.auditVaultResult(audit.OpPasswordVaultFactorEnrolled, nil, err)
	}
	resp, enrollErr := client.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{PasswordVaultCredential: cred})
	return s.auditVaultResult(audit.OpPasswordVaultFactorEnrolled, resp, enrollErr)
}

// RecoverWithKeyFactor uses the one-time recovery code to enroll a key
// factor (see EnrollKeyFactor) when the user's other factors are lost.
func (s *StaticPasswordService) RecoverWithKeyFactor(recoveryCode, factor, backend, keyID, tpmPolicy, label string) (*PasswordVaultEnrollResult, error) {
	if recoveryCode == "" {
		return nil, ErrStaticPWRecoveryCodeRequired
	}
	client, err := s.getClient()
	if err != nil {
		return nil, err
	}
	ctx := s.getContext()
	cred, err := s.keyFactorCredential(ctx, factor, backend, keyID, tpmPolicy, label)
	if err != nil {
		return s.auditVaultResult(audit.OpPasswordVaultRecovered, nil, err)
	}
	resp, recoverErr := client.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{
		RecoveryCode:            recoveryCode,
		PasswordVaultCredential: cred,
	})
	return s.auditVaultResult(audit.OpPasswordVaultRecovered, resp, recoverErr)
}

// UnlockWithKeyFactor opens the caller's personal session with the first
// of the vault's key factors whose key is in xKey's backends.
func (s *StaticPasswordService) UnlockWithKeyFactor() error {
	client, err := s.getClient()
	if err != nil {
		return err
	}
	unlockErr := s.unlockWithKeyFactor(s.getContext(), client, nil)
	details := map[string]any{"factor": "key"}
	if auditErr := s.logPasswordEvent(audit.OpPasswordStoreUnlocked, "", unlockErr == nil, unlockErr, details); auditErr != nil {
		return auditErr
	}
	return unlockErr
}

// unlockWithKeyFactor reads the vault's factors from the server, recovers
// the secret of the first key factor whose token is here -- restricted to
// the fingerprints in only, when given -- and unlocks with it.
func (s *StaticPasswordService) unlockWithKeyFactor(ctx context.Context, client transport.Client, only map[string]bool) error {
	status, err := client.PasswordVaultStatus(ctx)
	if err != nil {
		return err
	}
	factors := status.Factors
	if only != nil {
		factors = factors[:0:0]
		for _, f := range status.Factors {
			if only[f.KeyFingerprint] {
				factors = append(factors, f)
			}
		}
	}
	cred, err := vaulttoken.Find(ctx, s.keyBackends(), factors)
	if err != nil {
		return err
	}
	defer clear(cred.Secret)
	return client.PasswordStoreUnlock(ctx, &transport.PasswordStoreUnlockRequest{PasswordVaultCredential: cred})
}

// keyFactorCredential resolves the key, self-tests it and builds its
// enrollment credential.
func (s *StaticPasswordService) keyFactorCredential(ctx context.Context, factor, backend, keyID, tpmPolicy, label string) (transport.PasswordVaultCredential, error) {
	ref := transport.PasswordVaultKeyRef{Backend: backend, KeyID: keyID, TPMPolicy: tpmPolicy}
	key, err := vaulttoken.Resolve(ctx, s.keyBackends(), factor, ref)
	if err != nil {
		return transport.PasswordVaultCredential{}, err
	}
	if err := vaulttoken.SelfTest(ctx, key.Token); err != nil {
		return transport.PasswordVaultCredential{}, err
	}
	return vaulttoken.EnrollCredential(factor, key, label)
}
