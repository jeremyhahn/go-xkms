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

package apimodule

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestModule_PasswordVaultRelyingParty proves which relying party the
// module's vault passkeys are created for: the explicit option, else the
// self-built WebAuthn relying party's, else none.
func TestModule_PasswordVaultRelyingParty(t *testing.T) {
	svc := func() *xkms.XKMSService { return nil }
	webauthn := WithWebAuthnConfig(&config.WebAuthnConfig{RPID: "console.example.com"})

	cases := []struct {
		name string
		opts []Option
		want string
	}{
		{"explicit wins", []Option{webauthn, WithPasswordVaultRelyingParty("kms.example.com")}, "kms.example.com"},
		{"webauthn relying party", []Option{webauthn}, "console.example.com"},
		{"none", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewModule(svc, tc.opts...)
			require.NoError(t, err)
			assert.Equal(t, tc.want, m.passwordVaultRelyingParty())
		})
	}
}
