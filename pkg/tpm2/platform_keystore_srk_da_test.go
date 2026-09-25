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

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestEnableDAOnSRK_NilAttrs proves enableDAOnSRK tolerates a nil
// *types.KeyAttributes rather than panicking -- a caller building SRK
// attributes from a template that failed earlier must be able to no-op
// through this helper.
func TestEnableDAOnSRK_NilAttrs(t *testing.T) {
	assert.NotPanics(t, func() { enableDAOnSRK(nil) })
}

// TestEnableDAOnSRK_NilTPMAttributes proves enableDAOnSRK no-ops when the
// attributes carry no TPMAttributes yet, rather than dereferencing a nil
// Template.
func TestEnableDAOnSRK_NilTPMAttributes(t *testing.T) {
	attrs := &types.KeyAttributes{CN: "srk"}
	assert.NotPanics(t, func() { enableDAOnSRK(attrs) })
	assert.Nil(t, attrs.TPMAttributes)
}

// TestEnableDAOnSRK_ClearsNoDA proves the ordinary case: the template's NoDA
// attribute is cleared so wrong-PIN authorization failures against the
// platform SRK trip TPM dictionary-attack protection (TPM rule: EK and SSRK
// stay at TCG defaults; only the PSRK carries this DA behavior).
func TestEnableDAOnSRK_ClearsNoDA(t *testing.T) {
	tmpl := tpm2.RSASRKTemplate
	tmpl.ObjectAttributes.NoDA = true
	attrs := &types.KeyAttributes{
		CN: "srk",
		TPMAttributes: &types.TPMAttributes{
			Template: tmpl,
		},
	}

	enableDAOnSRK(attrs)

	assert.False(t, attrs.TPMAttributes.Template.ObjectAttributes.NoDA)
}
