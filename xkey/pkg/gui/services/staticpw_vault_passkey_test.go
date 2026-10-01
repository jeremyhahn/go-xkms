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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/vaulttest/vaultservice"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	fido2 "github.com/jeremyhahn/go-xkms/sdk/go/fido2"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport/embedded"
	"github.com/jeremyhahn/go-xkms/sdk/go/vaultpasskey"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
)

// vaultSimKey is the shared simulated security key (vaulttest.SimulatedKey).
type vaultSimKey = vaulttest.SimulatedKey

func newVaultSimKey(pin string) *vaultSimKey { return vaulttest.NewSimulatedKey(pin) }

// passkeyVault is a StaticPasswordService connected, as user alice, to a
// real XKMSService's vault through the SDK's embedded transport, with its
// security key simulated and its audit events recorded.
type passkeyVault struct {
	svc    *StaticPasswordService
	client transport.Client
	ctx    context.Context
	audit  *spwRecordingAuditLogger
}

func newPasskeyVault(t *testing.T, key *vaultSimKey) *passkeyVault {
	t.Helper()
	tr, err := embedded.New(vaultservice.New(t).Service)
	require.NoError(t, err)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "alice", TenantID: vaultservice.Tenant})

	svc := NewStaticPasswordService(staticpw.NewStore(xkms.NewStorageMemory()))
	svc.SetContext(ctx)
	svc.SetClient(tr)
	rec := &spwRecordingAuditLogger{}
	svc.SetAuditLogger(rec)
	v := &passkeyVault{svc: svc, client: tr, ctx: ctx, audit: rec}
	v.useKey(key)
	return v
}

// useKey makes the service's passkey calls drive key.
func (v *passkeyVault) useKey(key *vaultSimKey) {
	v.svc.vaultAuthenticatorOpener = func() (vaultAuthenticator, error) { return key, nil }
}

func (v *passkeyVault) status(t *testing.T) *PasswordVaultStatus {
	t.Helper()
	status, err := v.svc.VaultStatus()
	require.NoError(t, err)
	return status
}

func (v *passkeyVault) lock(t *testing.T) {
	t.Helper()
	require.NoError(t, v.client.PasswordStoreLock(v.ctx))
	require.False(t, v.status(t).Unlocked)
}

func (v *passkeyVault) passkeys(t *testing.T) []PasswordVaultFactor {
	t.Helper()
	var passkeys []PasswordVaultFactor
	for _, f := range v.status(t).Factors {
		if f.Factor == vaultpasskey.Factor {
			passkeys = append(passkeys, f)
		}
	}
	return passkeys
}

func TestStaticPasswordService_EnrollPasskeyThenUnlock(t *testing.T) {
	key := newVaultSimKey("123456")
	v := newPasskeyVault(t, key)

	result, err := v.svc.EnrollPasskey("yubikey", "123456")
	require.NoError(t, err)
	assert.NotEmpty(t, result.RecoveryCode, "the first enrollment returns the recovery code")
	assert.Equal(t, vaultpasskey.Factor, result.Factor.Factor)
	assert.Equal(t, "yubikey", result.Factor.Label)
	assert.True(t, key.Closed, "the security key is closed after use")
	assert.Equal(t, audit.OpPasswordVaultFactorEnrolled, v.audit.last().Operation)
	assert.True(t, v.audit.last().Success)
	assert.Equal(t, vaultpasskey.Factor, v.audit.last().Details["factor"])

	v.lock(t)
	require.NoError(t, v.svc.UnlockWithPasskey("123456"))
	assert.True(t, v.status(t).Unlocked, "the passkey opened the session on the server")
	assert.Equal(t, audit.OpPasswordStoreUnlocked, v.audit.last().Operation)
	assert.True(t, v.audit.last().Success)
	assert.Equal(t, vaultpasskey.Factor, v.audit.last().Details["factor"])

	second, err := v.svc.EnrollPasskey("spare", "123456")
	require.NoError(t, err)
	assert.Empty(t, second.RecoveryCode, "only the first enrollment returns a recovery code")
	assert.Len(t, v.passkeys(t), 2)
}

func TestStaticPasswordService_UnlockWithPasskey_Refusals(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, v *passkeyVault)
		pin     string
		wantErr error
	}{
		{
			name: "wrong PIN",
			setup: func(t *testing.T, v *passkeyVault) {
				_, err := v.svc.EnrollPasskey("", "123456")
				require.NoError(t, err)
			},
			pin:     "000000",
			wantErr: fido2.ErrInvalidPIN,
		},
		{
			name:    "missing PIN",
			setup:   func(t *testing.T, v *passkeyVault) {},
			pin:     "",
			wantErr: ErrStaticPWSecurityKeyPINRequired,
		},
		{
			name: "no passkey enrolled",
			setup: func(t *testing.T, v *passkeyVault) {
				_, err := v.svc.EnrollPassphrase("correct horse", "laptop")
				require.NoError(t, err)
			},
			pin:     "123456",
			wantErr: vaultpasskey.ErrNoPasskeyEnrolled,
		},
		{
			name: "passkey enrolled on another key",
			setup: func(t *testing.T, v *passkeyVault) {
				_, err := v.svc.EnrollPasskey("", "123456")
				require.NoError(t, err)
				v.useKey(newVaultSimKey("123456"))
			},
			pin:     "123456",
			wantErr: vaultpasskey.ErrNoMatchingPasskey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newPasskeyVault(t, newVaultSimKey("123456"))
			tt.setup(t, v)
			if v.status(t).Initialized {
				v.lock(t)
			}
			audited := len(v.audit.entries)

			err := v.svc.UnlockWithPasskey(tt.pin)
			assert.ErrorIs(t, err, tt.wantErr)
			assert.False(t, v.status(t).Unlocked, "a refused passkey leaves the session locked")
			if errors.Is(tt.wantErr, ErrStaticPWSecurityKeyPINRequired) {
				assert.Len(t, v.audit.entries, audited, "invalid input is not an unlock attempt")
				return
			}
			require.Len(t, v.audit.entries, audited+1)
			assert.Equal(t, audit.OpPasswordStoreUnlocked, v.audit.last().Operation)
			assert.False(t, v.audit.last().Success, "a refused unlock is audited as a failure")
		})
	}
}

func TestStaticPasswordService_RecoverWithPasskey(t *testing.T) {
	v := newPasskeyVault(t, newVaultSimKey("123456"))
	first, err := v.svc.EnrollPassphrase("correct horse", "laptop")
	require.NoError(t, err)
	v.lock(t)

	result, err := v.svc.RecoverWithPasskey(first.RecoveryCode, "spare key", "123456")
	require.NoError(t, err)
	assert.NotEmpty(t, result.RecoveryCode)
	assert.NotEqual(t, first.RecoveryCode, result.RecoveryCode, "recovery replaces the code")
	assert.Equal(t, "spare key", result.Factor.Label)
	assert.Equal(t, audit.OpPasswordVaultRecovered, v.audit.last().Operation)
	assert.True(t, v.audit.last().Success)

	v.lock(t)
	require.NoError(t, v.svc.UnlockWithPasskey("123456"))
	assert.True(t, v.status(t).Unlocked, "the recovered passkey unlocks the vault")
}

func TestStaticPasswordService_RecoverWithPasskey_Errors(t *testing.T) {
	t.Run("missing recovery code", func(t *testing.T) {
		v := newPasskeyVault(t, newVaultSimKey("123456"))
		_, err := v.svc.RecoverWithPasskey("", "", "123456")
		assert.ErrorIs(t, err, ErrStaticPWRecoveryCodeRequired)
	})
	t.Run("missing PIN", func(t *testing.T) {
		v := newPasskeyVault(t, newVaultSimKey("123456"))
		_, err := v.svc.RecoverWithPasskey("CODE", "", "")
		assert.ErrorIs(t, err, ErrStaticPWSecurityKeyPINRequired)
	})
	t.Run("wrong code is audited and enrolls no passkey", func(t *testing.T) {
		v := newPasskeyVault(t, newVaultSimKey("123456"))
		_, err := v.svc.EnrollPassphrase("correct horse", "laptop")
		require.NoError(t, err)
		v.lock(t)
		_, err = v.svc.RecoverWithPasskey("NOT-THE-CODE", "", "123456")
		require.Error(t, err)
		assert.Equal(t, audit.OpPasswordVaultRecovered, v.audit.last().Operation)
		assert.False(t, v.audit.last().Success)
		assert.Empty(t, v.passkeys(t))
	})
}

func TestStaticPasswordService_EnrollPasskey_Errors(t *testing.T) {
	t.Run("no client", func(t *testing.T) {
		svc := NewStaticPasswordService(nil)
		_, err := svc.EnrollPasskey("", "123456")
		assert.ErrorIs(t, err, ErrStaticPWNoClient)
	})
	t.Run("wrong PIN is audited as a failure", func(t *testing.T) {
		v := newPasskeyVault(t, newVaultSimKey("123456"))
		_, err := v.svc.EnrollPasskey("", "000000")
		assert.ErrorIs(t, err, fido2.ErrInvalidPIN)
		assert.Equal(t, audit.OpPasswordVaultFactorEnrolled, v.audit.last().Operation)
		assert.False(t, v.audit.last().Success)
		assert.False(t, v.status(t).Initialized)
	})
	t.Run("no security key", func(t *testing.T) {
		v := newPasskeyVault(t, newVaultSimKey("123456"))
		errNoKey := errors.New("no FIDO2 device")
		v.svc.vaultAuthenticatorOpener = func() (vaultAuthenticator, error) { return nil, errNoKey }
		_, err := v.svc.EnrollPasskey("", "123456")
		assert.ErrorIs(t, err, ErrStaticPWSecurityKeyUnavailable)
		assert.ErrorIs(t, err, errNoKey)
	})
	t.Run("a failed close discards the passkey", func(t *testing.T) {
		key := newVaultSimKey("123456")
		key.CloseErr = errors.New("close failed")
		v := newPasskeyVault(t, key)
		_, err := v.svc.EnrollPasskey("", "123456")
		assert.ErrorIs(t, err, key.CloseErr)
		assert.False(t, v.status(t).Initialized, "nothing is enrolled when the key cannot be closed")
	})
	t.Run("audit write failure fails the enrollment", func(t *testing.T) {
		v := newPasskeyVault(t, newVaultSimKey("123456"))
		v.audit.logErr = errors.New("audit down")
		_, err := v.svc.EnrollPasskey("", "123456")
		assert.ErrorIs(t, err, v.audit.logErr)
	})
}
