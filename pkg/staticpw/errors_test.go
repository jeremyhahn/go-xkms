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

package staticpw

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTypedErrors pins the typed errors' contract with their callers: each
// names its origin in the message and keeps its cause reachable through
// errors.Is, so transports map the failure by its sentinel.
func TestTypedErrors(t *testing.T) {
	cause := errors.New("disk full")
	tests := []struct {
		name    string
		err     error
		wantIs  error
		wantMsg string
	}{
		{
			name:    "DAO creation",
			err:     ErrDAOCreation{Cause: cause},
			wantIs:  cause,
			wantMsg: "staticpw: failed to create DAO: disk full",
		},
		{
			name:    "personal entry decrypt",
			err:     &PersonalEntryDecryptError{Key: "entry/1", Err: cause},
			wantIs:  cause,
			wantMsg: "staticpw: personal entry entry/1 does not open with the user's key: disk full",
		},
		{
			name:    "vault keyring store",
			err:     &VaultStoreError{Op: "put", Key: "f1", Err: cause},
			wantIs:  cause,
			wantMsg: "staticpw: vault keyring put f1: disk full",
		},
		{
			name:    "vault crypto",
			err:     &VaultCryptoError{Op: "wrap", Err: cause},
			wantIs:  cause,
			wantMsg: "staticpw: vault wrap: disk full",
		},
		{
			name:    "vault key keeps its cause",
			err:     &VaultKeyError{Err: cause},
			wantIs:  cause,
			wantMsg: "staticpw: key factor: disk full",
		},
		{
			name:    "vault key is an invalid credential",
			err:     &VaultKeyError{Err: cause},
			wantIs:  ErrVaultInvalidCredential,
			wantMsg: "staticpw: key factor: disk full",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.err, tt.wantIs)
			assert.EqualError(t, tt.err, tt.wantMsg)
		})
	}
}

// TestVaultFactorKEK_NilSecret pins that a factor given no credential
// derives no key and reports ErrVaultInvalidCredential through
// VaultCryptoError.
func TestVaultFactorKEK_NilSecret(t *testing.T) {
	f := &vaultFactor{VaultFactorInfo: VaultFactorInfo{Type: FactorPassphrase}}

	kek, err := f.kek(context.Background(), nil)

	assert.Nil(t, kek)
	require.ErrorIs(t, err, ErrVaultInvalidCredential)
	var cryptoErr *VaultCryptoError
	require.ErrorAs(t, err, &cryptoErr)
	assert.Equal(t, "kdf", cryptoErr.Op)
}
