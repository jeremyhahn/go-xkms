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

package tokenstore

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenEntry_IsExpired_True(t *testing.T) {
	entry := &TokenEntry{
		ServerURL: "https://example.com",
		Token:     "test-jwt",
		ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
	}
	assert.True(t, entry.IsExpired())
}

func TestTokenEntry_IsExpired_False(t *testing.T) {
	entry := &TokenEntry{
		ServerURL: "https://example.com",
		Token:     "test-jwt",
		ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
	}
	assert.False(t, entry.IsExpired())
}

func TestTokenEntry_IsExpired_ZeroTime(t *testing.T) {
	entry := &TokenEntry{
		ServerURL: "https://example.com",
		Token:     "test-jwt",
	}
	assert.False(t, entry.IsExpired())
}

func TestTokenEntry_Validate_Success(t *testing.T) {
	entry := &TokenEntry{
		ServerURL: "https://example.com",
		Token:     "test-jwt",
	}
	assert.NoError(t, entry.Validate())
}

func TestTokenEntry_Validate_EmptyServer(t *testing.T) {
	entry := &TokenEntry{
		Token: "test-jwt",
	}
	assert.ErrorIs(t, entry.Validate(), ErrInvalidServer)
}

func TestTokenEntry_Validate_EmptyToken(t *testing.T) {
	entry := &TokenEntry{
		ServerURL: "https://example.com",
	}
	assert.ErrorIs(t, entry.Validate(), ErrTokenNotFound)
}

func TestTokenEntry_Constants(t *testing.T) {
	// Verify source constants are distinct.
	sources := map[string]bool{
		SourceOIDC:      true,
		SourceFIDO2:     true,
		SourceBootstrap: true,
	}
	assert.Len(t, sources, 3)

	// Verify type constants are distinct.
	types := map[string]bool{
		TypeBearer:  true,
		TypeRefresh: true,
	}
	assert.Len(t, types, 2)
}
