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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"regexp"
	"strings"
)

// digestAlgorithm is one of the digest algorithms the OCI image
// specification registers.
type digestAlgorithm struct {
	// hexLength is the length of the hex-encoded digest.
	hexLength int

	// sum hashes data.
	sum func(data []byte) []byte
}

// digestAlgorithms maps an OCI digest algorithm name to its definition.
var digestAlgorithms = map[string]digestAlgorithm{
	"sha256": {hexLength: sha256.Size * 2, sum: sha256Sum},
	"sha512": {hexLength: sha512.Size * 2, sum: sha512Sum},
}

// hexRegex matches the lowercase hex encoding OCI digests use.
var hexRegex = regexp.MustCompile(`^[a-f0-9]+$`)

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func sha512Sum(data []byte) []byte {
	sum := sha512.Sum512(data)
	return sum[:]
}

// splitDigest splits an OCI digest into its algorithm and hex encoding,
// reporting false unless the algorithm is registered and the encoding has
// its length.
func splitDigest(digest string) (string, string, bool) {
	algorithm, encoded, found := strings.Cut(digest, ":")
	definition, known := digestAlgorithms[algorithm]
	if !found || !known || len(encoded) != definition.hexLength || !hexRegex.MatchString(encoded) {
		return "", "", false
	}
	return algorithm, encoded, true
}

// validDigest reports whether digest is a well-formed OCI digest.
func validDigest(digest string) bool {
	_, _, ok := splitDigest(digest)
	return ok
}

// sha256Digest returns the OCI digest of data, "sha256:<hex>".
func sha256Digest(data []byte) string {
	return "sha256:" + hex.EncodeToString(sha256Sum(data))
}

// matchesDigest reports whether data hashes to digest.
func matchesDigest(digest string, data []byte) bool {
	algorithm, encoded, ok := splitDigest(digest)
	if !ok {
		return false
	}
	return hex.EncodeToString(digestAlgorithms[algorithm].sum(data)) == encoded
}
