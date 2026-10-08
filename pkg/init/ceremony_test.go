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

package initialize

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSPKIPin_IsTheHexSHA256OfTheSubjectPublicKeyInfo pins the one encoding
// of the CA pin first-contact clients verify against.
func TestSPKIPin_IsTheHexSHA256OfTheSubjectPublicKeyInfo(t *testing.T) {
	root := newMockCA(t)
	cert, err := root.CACertificate()
	require.NoError(t, err)

	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	assert.Equal(t, hex.EncodeToString(sum[:]), SPKIPin(cert))
	assert.Len(t, SPKIPin(cert), 2*sha256.Size)
}

// TestSPKIPin_DiffersForDifferentKeys proves the pin binds the key: two CAs
// never share one.
func TestSPKIPin_DiffersForDifferentKeys(t *testing.T) {
	a, err := newMockCA(t).CACertificate()
	require.NoError(t, err)
	b, err := newMockCA(t).CACertificate()
	require.NoError(t, err)

	assert.NotEqual(t, SPKIPin(a), SPKIPin(b))
}
