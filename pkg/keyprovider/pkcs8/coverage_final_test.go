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

package pkcs8

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSigner_X25519NotSigner verifies that calling Signer on an X25519 key
// returns ErrKeyNotSigner since X25519 keys implement key agreement, not signing.
func TestSigner_X25519NotSigner(t *testing.T) {
	be, _ := createTestBackend(t)

	attrs := &types.KeyAttributes{
		CN:               "x25519-signer-test",
		KeyType:          backend.KEY_TYPE_TLS,
		StoreType:        backend.STORE_SW,
		KeyAlgorithm:     x509.PublicKeyAlgorithm(0), // Custom
		X25519Attributes: &types.X25519Attributes{},
	}

	_, err := be.GenerateKey(attrs)
	require.NoError(t, err)

	_, err = be.Signer(attrs)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrKeyNotSigner))
}
