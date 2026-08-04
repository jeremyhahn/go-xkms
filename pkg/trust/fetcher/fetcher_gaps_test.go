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

package fetcher

import (
	"bytes"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBundleBytes_Envelope covers both the flat {"bundle":...} shape and the
// nested platform envelope {"payload":{"bundle":...}}.
func TestBundleBytes_Envelope(t *testing.T) {
	flat := jsonBundleResponse{Bundle: []byte("flat-bundle")}
	assert.Equal(t, []byte("flat-bundle"), flat.bundleBytes())

	nested := jsonBundleResponse{Payload: &jsonBundlePayload{Bundle: []byte("nested-bundle")}}
	assert.Equal(t, []byte("nested-bundle"), nested.bundleBytes())

	// Flat takes precedence when both are present.
	both := jsonBundleResponse{Bundle: []byte("flat"), Payload: &jsonBundlePayload{Bundle: []byte("nested")}}
	assert.Equal(t, []byte("flat"), both.bundleBytes())

	assert.Nil(t, jsonBundleResponse{}.bundleBytes())
}

// TestContentTypeMatches covers the case-insensitive prefix match and the
// short-string (ct shorter than prefix) rejection branch.
func TestContentTypeMatches(t *testing.T) {
	assert.True(t, contentTypeMatches("Application/JSON; charset=utf-8", "application/json"))
	assert.True(t, contentTypeMatches("application/json", "application/json"))
	assert.False(t, contentTypeMatches("app", "application/json"), "shorter-than-prefix must not match")
	assert.False(t, contentTypeMatches("text/plain", "application/json"))
}

// TestEqualFold covers the case-fold match and the per-byte mismatch branch.
func TestEqualFold(t *testing.T) {
	assert.True(t, equalFold("AbC", "abc"))
	assert.True(t, equalFold("", ""))
	assert.False(t, equalFold("abc", "abd"))
	assert.False(t, equalFold("abc", "ab"))
}

// TestTryParsePEM_SkipThenSucceed verifies a non-CERTIFICATE PEM block preceding
// a valid certificate is skipped, and the certificate is still parsed.
func TestTryParsePEM_SkipThenSucceed(t *testing.T) {
	_, caPEM := makeTestCA(t)

	junk := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("not-a-real-key")})
	mixed := append(bytes.Clone(junk), caPEM...)

	certs, ok := tryParsePEM(mixed)
	require.True(t, ok, "must find the certificate after skipping the non-CERTIFICATE block")
	require.Len(t, certs, 1)
}

// TestTryParsePEM_NoCertificates verifies an all-non-CERTIFICATE stream yields
// no certs.
func TestTryParsePEM_NoCertificates(t *testing.T) {
	junk := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("x")})
	certs, ok := tryParsePEM(junk)
	assert.False(t, ok)
	assert.Empty(t, certs)
}
