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

package xkms

import (
	"context"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildKeyAttributes_RefusesSeparatorInKeyID is #169, and it is a
// SERVICE-layer test on purpose.
//
// Tightening the transport validators (#168) fixes REST, which calls them.
// It does not fix MCP: handleGenerateKey checks only that key_id is non-empty,
// and XKMSService.GenerateKey does the same before handing the value to
// buildKeyAttributes, which assigns CN verbatim. Neither pkg/api/mcp nor
// pkg/xkms called a key-ID validator at all, so the path #169 actually
// measured — the one callers use most — crossed no validator.
//
// The guard therefore belongs where the CN first becomes an identifier
// segment, which is a boundary every method crosses, rather than in each
// handler that would otherwise have to remember.
func TestBuildKeyAttributes_RefusesSeparatorInKeyID(t *testing.T) {
	for _, keyID := range []string{"a:b", "acme:evil", "software:signing:rsa:mykey"} {
		_, err := buildKeyAttributes(&transport.GenerateKeyRequest{
			KeyID:     keyID,
			KeyType:   "tls",
			Algorithm: "rsa",
		}, "software")
		require.Error(t, err, "a key ID containing the separator must be refused: %q", keyID)
		assert.ErrorIs(t, err, ErrInvalidKeyID)
	}
}

// TestBuildKeyAttributes_RefusesOtherUnsafeKeyIDs covers the rest of the
// charset at the same boundary — a slash would reach a storage path, a null
// byte a filename.
func TestBuildKeyAttributes_RefusesOtherUnsafeKeyIDs(t *testing.T) {
	for name, keyID := range map[string]string{
		"slash":          "a/b",
		"path traversal": "../../etc/passwd",
		"null byte":      "key\x00id",
		"space":          "my key",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := buildKeyAttributes(&transport.GenerateKeyRequest{
				KeyID:     keyID,
				KeyType:   "tls",
				Algorithm: "rsa",
			}, "software")
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidKeyID)
		})
	}
}

// TestBuildKeyAttributes_AcceptsLegalKeyIDs is the companion: the guard must
// not refuse names that were always legal and round trip correctly.
func TestBuildKeyAttributes_AcceptsLegalKeyIDs(t *testing.T) {
	for _, keyID := range []string{"mykey", "my-key", "my_key", "my.key", "Key2026"} {
		attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
			KeyID:     keyID,
			KeyType:   "tls",
			Algorithm: "rsa",
		}, "software")
		require.NoError(t, err, "%q is a legal key ID", keyID)
		assert.Equal(t, keyID, attrs.CN)
	}
}

// TestBuildKeyAttributes_KeyIDCannotShiftTheStorageIdentifier is the property
// underneath all of the above, and the reason the colon is the character that
// matters.
//
// KeyAttributes.ID() emits a fixed number of ':'-joined segments —
// "software:tls:my-key:rsa" — and parseStorageKeyID disambiguates purely by
// counting them. A separator inside the CN adds a segment, so every field
// after it is read one position out and the CN comes back as something else
// entirely.
//
// The invariant a legal key ID must satisfy is therefore that it contributes
// no separators of its own: the segment count is a property of the format, not
// of the caller's name.
func TestBuildKeyAttributes_KeyIDCannotShiftTheStorageIdentifier(t *testing.T) {
	const wantSegments = 4 // backend:keytype:cn:algorithm

	for _, keyID := range []string{"mykey", "my-key", "my_key", "my.key", "a", "Key2026"} {
		attrs, err := buildKeyAttributes(&transport.GenerateKeyRequest{
			KeyID:     keyID,
			KeyType:   "tls",
			Algorithm: "rsa",
		}, "software")
		require.NoError(t, err)

		segments := strings.Split(attrs.ID(), ":")
		assert.Len(t, segments, wantSegments,
			"key ID %q must not add a segment to the storage identifier", keyID)
		assert.Equal(t, keyID, segments[2],
			"the CN must occupy its own segment, unshifted")
	}

	// And the refused shape is exactly the one that would have shifted it: had
	// "a:b" been accepted, ID() would carry five segments and the CN would read
	// back as "b".
	_, err := buildKeyAttributes(&transport.GenerateKeyRequest{
		KeyID:     "a:b",
		KeyType:   "tls",
		Algorithm: "rsa",
	}, "software")
	require.Error(t, err)
}

// TestXKMSServiceGenerateKey_RefusesSeparatorInKeyID drives #169's own repro
// through the entry point the issue measured.
//
// The issue reported: generateKey(key_id="a:b") returns nil, list_keys shows a
// key named "b", and getKey("a:b") reports key not found. MCP's
// handleGenerateKey checks only that key_id is non-empty and hands the value
// straight to this method, so the refusal has to hold here rather than in a
// transport that MCP does not use.
//
// The boundary test above covers buildKeyAttributes directly; this one covers
// the path a caller actually takes, so a later change that bypassed the
// builder would still be caught.
func TestXKMSServiceGenerateKey_RefusesSeparatorInKeyID(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	software := newMockKeyStoreWithSealer("software", types.BackendTypeSoftware)
	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": software},
		DefaultBackend: "software",
	}))

	svc, err := Get()
	require.NoError(t, err)

	resp, err := svc.GenerateKey(context.Background(), &transport.GenerateKeyRequest{
		KeyID:     "a:b",
		KeyType:   "tls",
		Algorithm: "rsa",
		Backend:   "software",
	})
	require.Error(t, err, "generateKey must not silently create an unreachable key")
	assert.Nil(t, resp, "no key may be reported as created")
	assert.ErrorIs(t, err, ErrInvalidKeyID)
}
