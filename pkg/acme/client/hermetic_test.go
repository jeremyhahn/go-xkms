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

package client

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unreachableDirectoryURL is the DirectoryURL for an acme.Client that a test
// expects to fail BEFORE any ACME request is made (a validation error, a
// nil CSR, a malformed authorization). golang.org/x/crypto/acme substitutes
// Let's Encrypt PRODUCTION for an empty DirectoryURL, so a literal that
// omits it is a latent outbound HTTPS call from the unit gate: the day the
// validation it relies on regresses, the test reaches the public internet
// and fails on a ten-second TLS timeout instead of on the defect (#152).
// Port 1 on loopback refuses the connection immediately, so a test that
// unexpectedly gets that far fails fast, locally, and for a reason that
// names the URL.
const unreachableDirectoryURL = "http://127.0.0.1:1/directory"

var acmeClientLiteral = regexp.MustCompile(`&?acme\.Client\{`)

// TestACMEClientLiteralsAreHermetic is the grep gate for #152: every
// acme.Client literal in this package's tests must set DirectoryURL, to a
// local test server or to unreachableDirectoryURL. It scans the test sources
// on disk so a regressed literal in any test file fails the suite, even if
// the test it sits in happens to fail before reaching the network today.
func TestACMEClientLiteralsAreHermetic(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	var violations []string
	literals := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		content, err := os.ReadFile(name)
		require.NoError(t, err)
		src := string(content)
		for _, loc := range acmeClientLiteral.FindAllStringIndex(src, -1) {
			literals++
			body := literalBody(src, loc[1])
			if !strings.Contains(body, "DirectoryURL") {
				line := strings.Count(src[:loc[0]], "\n") + 1
				violations = append(violations, name+":"+strconv.Itoa(line))
			}
		}
	}

	require.Greater(t, literals, 100, "the gate must actually find the package's acme.Client literals")
	assert.Empty(t, violations,
		"acme.Client literals without DirectoryURL default to Let's Encrypt production; set it to the test server or to unreachableDirectoryURL:\n%s",
		strings.Join(violations, "\n"))
}

// literalBody returns the text of a composite literal whose opening brace
// was just consumed at src[open-1], up to and including its closing brace.
func literalBody(src string, open int) string {
	depth := 1
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open:i]
			}
		}
	}
	return src[open:]
}

// The gate must catch the shape it exists for: a literal with no fields, a
// keyed literal without DirectoryURL, and must accept both hermetic forms.
func TestLiteralBody_FindsTheClosingBrace(t *testing.T) {
	// The literal token is assembled at run time so this file does not itself
	// contain a bare acme.Client literal for the gate above to trip on.
	open := "&acme." + "Client{"
	src := "x := " + open + "Key: k, HTTPClient: &http.Client{Timeout: t}}; y := 1"
	loc := acmeClientLiteral.FindStringIndex(src)
	require.NotNil(t, loc)
	assert.Equal(t, "Key: k, HTTPClient: &http.Client{Timeout: t}", literalBody(src, loc[1]))
	assert.NotContains(t, literalBody(src, loc[1]), "DirectoryURL")
	hermetic := open + "DirectoryURL: unreachableDirectoryURL}"
	assert.Contains(t, literalBody(hermetic, len(open)), "DirectoryURL")
}
