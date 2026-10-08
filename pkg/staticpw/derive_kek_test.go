// Copyright (c) 2026 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package staticpw

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

func factorOf(t FactorType) *vaultFactor {
	return &vaultFactor{VaultFactorInfo: VaultFactorInfo{Type: t}, Salt: []byte("0123456789abcdef")}
}

// TestVaultFactorKEK_DerivesStableKey proves the KEK is derived under the
// secret's borrow, is key-sized, and is the same for the same secret.
func TestVaultFactorKEK_DerivesStableKey(t *testing.T) {
	f := factorOf(FactorRecovery)

	derive := func() []byte {
		secret, err := secure.NewSecret(t.Context(), []byte("RECOVERYSECRET"))
		require.NoError(t, err)
		defer secret.Destroy()
		kek, err := f.kek(t.Context(), secret)
		require.NoError(t, err)
		return kek
	}

	first, second := derive(), derive()
	assert.Len(t, first, 32)
	assert.Equal(t, first, second)
}

// TestVaultFactorKEK_RejectsBadInput proves a nil secret, an unknown factor
// type and an unparameterised passphrase factor all fail closed.
func TestVaultFactorKEK_RejectsBadInput(t *testing.T) {
	secret, err := secure.NewSecret(t.Context(), []byte("secret"))
	require.NoError(t, err)
	defer secret.Destroy()

	var cryptoErr *VaultCryptoError

	kek, err := factorOf(FactorRecovery).kek(t.Context(), nil)
	assert.True(t, errors.As(err, &cryptoErr))
	assert.Nil(t, kek)

	kek, err = factorOf(FactorType("bogus")).kek(t.Context(), secret)
	assert.ErrorIs(t, err, ErrVaultInvalidCredential)
	assert.Nil(t, kek)

	kek, err = factorOf(FactorPassphrase).kek(t.Context(), secret)
	assert.True(t, errors.As(err, &cryptoErr))
	assert.Nil(t, kek)
}
