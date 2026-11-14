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

package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestSigningKeyTools_SignImageErrors proves malformed params, a malformed
// reference and a password without a username are invalid params, and that
// a server without the signing-key service refuses the tool; none of the
// errors echoes the password.
func TestSigningKeyTools_SignImageErrors(t *testing.T) {
	s, _ := newReleaseKeyMCP(t)
	for name, params := range map[string]any{
		"malformed params": "not an object",
		"malformed reference": transport.SignImageRequest{
			Reference: "not a reference",
			Registry:  &transport.ImageRegistryCredentials{Username: "ci", Password: []byte("registry-password")},
		},
		"password without a username": transport.SignImageRequest{
			Reference: "registry.example.com/acme/app:v1",
			Registry:  &transport.ImageRegistryCredentials{Password: []byte("registry-password")},
		},
	} {
		var out map[string]any
		err := invokeOIDC(t, s, "acme", "alice", "attestation.signing_key.sign_image", params, &out)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr, name)
		assert.Equal(t, ErrCodeInvalidParams, keyErr.Code, name)
		assert.NotContains(t, err.Error(), "registry-password", name)
	}

	var out map[string]any
	err := invokeOIDC(t, createTestServer(t), "acme", "alice", "attestation.signing_key.sign_image",
		transport.SignImageRequest{Reference: "registry.example.com/acme/app:v1"}, &out)
	var keyErr *KeyOpError
	assert.ErrorAs(t, err, &keyErr)
}
