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

package vaulttest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/fido2"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

func sealPIN(t *testing.T, pin string) *secure.Secret {
	t.Helper()
	sealed, err := secure.NewSecret([]byte(pin))
	require.NoError(t, err)
	return sealed
}

func TestSimulatedKeyCheckPIN_AcceptsTheRightPIN(t *testing.T) {
	key := NewSimulatedKey("1234")

	assert.NoError(t, key.checkPIN(sealPIN(t, "1234")))
}

func TestSimulatedKeyCheckPIN_RejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		key  *SimulatedKey
		pin  *secure.Secret
		want error
	}{
		{"missing PIN", NewSimulatedKey("1234"), nil, fido2.ErrPINRequired},
		{"wrong PIN", NewSimulatedKey("1234"), sealPIN(t, "9999"), fido2.ErrInvalidPIN},
		{"key without a PIN", NewSimulatedKey(""), sealPIN(t, "1234"), fido2.ErrInvalidPIN},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.key.checkPIN(tt.pin), tt.want)
		})
	}
}
