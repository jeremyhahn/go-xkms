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

package image

import (
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidDigest(t *testing.T) {
	for _, digest := range []string{testSHA256, testSHA512} {
		assert.True(t, validDigest(digest), digest)
	}
	for _, digest := range []string{
		"",
		"sha256",
		"sha256:",
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("a", 65),
		"sha256:" + strings.Repeat("g", 64),
		"sha256:" + strings.Repeat("A", 64),
		"sha512:" + strings.Repeat("a", 64),
		"sha1:" + strings.Repeat("a", 40),
	} {
		assert.False(t, validDigest(digest), digest)
	}
}

func TestSplitDigest(t *testing.T) {
	algorithm, encoded, ok := splitDigest(testSHA256)
	assert.True(t, ok)
	assert.Equal(t, "sha256", algorithm)
	assert.Equal(t, strings.Repeat("ab", 32), encoded)

	algorithm, encoded, ok = splitDigest("md5:" + strings.Repeat("a", 32))
	assert.False(t, ok)
	assert.Empty(t, algorithm)
	assert.Empty(t, encoded)
}

func TestSHA256Digest(t *testing.T) {
	// The SHA-256 of the empty JSON object, the OCI empty descriptor's digest.
	assert.Equal(t, "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", sha256Digest([]byte("{}")))
}

func TestMatchesDigest(t *testing.T) {
	data := []byte("manifest")
	sum := sha512.Sum512(data)

	assert.True(t, matchesDigest(sha256Digest(data), data))
	assert.True(t, matchesDigest("sha512:"+hex.EncodeToString(sum[:]), data))
	assert.False(t, matchesDigest(sha256Digest(data), []byte("other")))
	assert.False(t, matchesDigest("sha256:abc", data))
}
