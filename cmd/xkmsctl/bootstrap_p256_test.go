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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-truststrap/pkg/p256proto"
)

// newTestP256KeyHex generates a P-256 static key and returns its hex encoding
// for use as test input, mirroring newTestStaticKeyHex for the Noise suite.
func newTestP256KeyHex(t *testing.T) string {
	t.Helper()

	key, err := p256proto.GenerateStaticKey()
	require.NoError(t, err)
	defer key.Destroy()

	alloc, err := enclave.ProcessAllocator()
	require.NoError(t, err)
	buf, err := alloc.NewSized(p256proto.HexKeySize)
	require.NoError(t, err)
	defer func() { require.NoError(t, buf.Destroy()) }()
	require.NoError(t, p256proto.EncodeStaticKey(buf, key))

	var encoded string
	require.NoError(t, buf.WithBytes(func(b []byte) error {
		encoded = string(b)
		return nil
	}))
	return encoded
}

// TestDecodeP256PublicKey_WipesInput verifies the hex scalar handed in is
// moved into protected memory, not copied: the caller's slice is zeroed
// whether or not the decode succeeds.
func TestDecodeP256PublicKey_WipesInput(t *testing.T) {
	hexKey := []byte(newTestP256KeyHex(t))

	public, err := decodeP256PublicKey(hexKey)
	require.NoError(t, err)
	assert.Len(t, public, p256proto.PublicKeySize)
	assert.Equal(t, make([]byte, len(hexKey)), hexKey, "the caller's hex scalar must be wiped")
}

// TestDecodeP256PublicKey_Errors verifies each failure is reported under the
// sentinel that names its stage, so an operator can tell a key that does not
// decode from a host that refused the protected buffer.
func TestDecodeP256PublicKey_Errors(t *testing.T) {
	_, err := decodeP256PublicKey(nil)
	assert.ErrorIs(t, err, ErrProtectedKeyBufferFailed)
	assert.ErrorIs(t, err, enclave.ErrEmptyEnclave)

	_, err = decodeP256PublicKey([]byte(strings.Repeat("zz", 32)))
	assert.ErrorIs(t, err, ErrDecodeKeyFailed)
}

// TestP256GenerateKey_RequiresOutputFile covers the same ruling the Noise verb
// is held to: the private key is only ever written to a file, so with no
// --output the command must fail rather than print it.
func TestP256GenerateKey_RequiresOutputFile(t *testing.T) {
	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() { generateP256Key("") })
	})

	assert.True(t, exitCalled)
	assert.NotContains(t, stdout, "Private key")

	// Assert WHICH error, not merely that one happened.
	assert.Contains(t, stderr, "--output is required",
		"expected the missing-output error specifically, got: %s", stderr)
}

// TestP256GenerateKey_OutputFile asserts the private key reaches the file and
// nowhere else, at the right length and mode.
func TestP256GenerateKey_OutputFile(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "p256.key")

	output := captureStdout(t, func() { generateP256Key(keyFile) })

	assert.Contains(t, output, "Private key written to:")
	assert.NotContains(t, output, "Private key: ")
	assert.Contains(t, output, "Public key:")

	data, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	assert.Len(t, strings.TrimSpace(string(data)), p256proto.HexKeySize)

	info, err := os.Stat(keyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// TestP256GenerateKey_RefusesExistingFile covers the permission hole
// os.WriteFile leaves open, and the identity replacement a silent overwrite
// would cause: clients pin the responder key, so replacing it breaks them all.
func TestP256GenerateKey_RefusesExistingFile(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "p256.key")

	const sentinel = "do not overwrite me\n"
	require.NoError(t, os.WriteFile(keyFile, []byte(sentinel), 0644))

	exitCalled := false
	oldExit := exitFunc
	exitFunc = func(code int) { exitCalled = true }
	defer func() { exitFunc = oldExit }()

	captureStdout(t, func() { generateP256Key(keyFile) })

	assert.True(t, exitCalled, "expected generate-p256-key to fail on an existing path")

	data, err := os.ReadFile(keyFile)
	require.NoError(t, err)
	assert.Equal(t, sentinel, string(data), "the existing file was overwritten")

	info, err := os.Stat(keyFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(),
		"permissions changed on a file the command should not have touched")
}

// TestP256Key_GenerateShowRoundTrip is the assertion that makes the pair
// useful rather than merely present: the public key generate-p256-key prints
// is the one show-p256-key derives from the file it wrote. An operator
// distributes the first and the server serves the second, so a mismatch would
// hand every client a key that pins nothing.
func TestP256Key_GenerateShowRoundTrip(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "p256.key")

	generated := captureStdout(t, func() { generateP256Key(keyFile) })
	shown := captureStdout(t, func() { showP256Key(keyFile, "") })

	generatedPub := publicKeyFromOutput(t, generated)
	shownPub := publicKeyFromOutput(t, shown)

	assert.Equal(t, generatedPub, shownPub,
		"generate-p256-key and show-p256-key disagree about the public key")

	// An uncompressed P-256 point is 65 bytes, so 130 hex characters, and
	// begins with the 0x04 tag. Asserting the shape catches a truncated or
	// compressed encoding that a string comparison alone would accept.
	assert.Len(t, shownPub, p256proto.PublicKeySize*2)
	assert.True(t, strings.HasPrefix(shownPub, "04"),
		"expected an uncompressed point (0x04 tag), got %s", shownPub)
}

// publicKeyFromOutput pulls the hex public key out of a command's stdout.
func publicKeyFromOutput(t *testing.T, output string) string {
	t.Helper()

	for _, line := range strings.Split(output, "\n") {
		if _, rest, found := strings.Cut(line, "Public key:"); found {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no public key line in output: %q", output)
	return ""
}

// TestP256ShowKey_FromHex covers the inline-hex input path.
func TestP256ShowKey_FromHex(t *testing.T) {
	output := captureStdout(t, func() { showP256Key("", newTestP256KeyHex(t)) })

	pub := publicKeyFromOutput(t, output)
	assert.Len(t, pub, p256proto.PublicKeySize*2)
}

// TestP256ShowKey_ErrorPaths covers the operator mistakes: naming neither
// input, naming a file that does not exist, and supplying a key of the wrong
// length, which must be reported rather than decoded into something unusable.
//
// A Curve25519 key pasted into this verb is deliberately NOT among them: both
// curves use a 32-byte scalar, so it is the right length and decodes to a
// valid, wrong key. No length check can catch it.
func TestP256ShowKey_ErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		keyFile string
		keyHex  string
		wantErr string
	}{
		{
			name:    "neither input",
			wantErr: "key",
		},
		{
			name:    "missing file",
			keyFile: filepath.Join(t.TempDir(), "absent.key"),
			wantErr: "key file",
		},
		{
			name: "truncated key",
			// Half a scalar: the length check's actual job.
			keyHex:  strings.Repeat("ab", 16),
			wantErr: "want 64",
		},
		{
			name:    "not hex at all",
			keyHex:  strings.Repeat("zz", 32),
			wantErr: "decode",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exitCalled := false
			oldExit := exitFunc
			exitFunc = func(code int) { exitCalled = true }
			defer func() { exitFunc = oldExit }()

			var stdout string
			stderr := captureStderr(t, func() {
				stdout = captureStdout(t, func() { showP256Key(tc.keyFile, tc.keyHex) })
			})

			assert.True(t, exitCalled, "expected the command to fail")
			assert.NotContains(t, stdout, "Public key:",
				"a failed lookup must not print a public key")
			assert.Contains(t, strings.ToLower(stderr), strings.ToLower(tc.wantErr),
				"expected %q in stderr, got: %s", tc.wantErr, stderr)
		})
	}
}
