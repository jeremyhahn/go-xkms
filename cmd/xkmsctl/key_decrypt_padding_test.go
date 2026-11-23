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
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestKeyDecrypt_PaddingDefaultsToOAEPSHA256 pins that key decrypt sends
// RSA-OAEP SHA-256 unless --padding names PKCS#1 v1.5 (issue #2280).
func TestKeyDecrypt_PaddingDefaultsToOAEPSHA256(t *testing.T) {
	ct := base64.StdEncoding.EncodeToString([]byte("ct"))
	cases := []struct {
		name        string
		flags       map[string]string
		wantPadding string
		wantHash    string
	}{
		{name: "default", flags: nil, wantPadding: "oaep", wantHash: "sha256"},
		{name: "oaep-sha256", flags: map[string]string{"padding": "oaep-sha256"}, wantPadding: "oaep", wantHash: "sha256"},
		{name: "pkcs1v15", flags: map[string]string{"padding": "pkcs1v15"}, wantPadding: "pkcs1v15", wantHash: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockKeyVersionClient{}
			_, code := runKeyVersionCmd(t, mock, "text", keyDecryptCmd, []string{"k", ct}, tc.flags)
			require.Equal(t, -1, code)
			req, ok := mock.requests["decrypt"].(*client.DecryptRequest)
			require.True(t, ok, "decrypt request recorded")
			assert.Equal(t, tc.wantPadding, req.Padding)
			assert.Equal(t, tc.wantHash, req.Hash)
		})
	}
}

// TestKeyDecrypt_UnknownPaddingFailsBeforeRequest pins that an unknown
// --padding value exits 1 with the typed error before any client is built.
func TestKeyDecrypt_UnknownPaddingFailsBeforeRequest(t *testing.T) {
	_, _, err := decryptPaddingOptions("bogus")
	var perr *DecryptPaddingError
	require.ErrorAs(t, err, &perr)
	assert.Equal(t, "bogus", perr.Value)
	assert.ErrorIs(t, err, ErrInvalidDecryptPadding)

	mock := &mockKeyVersionClient{}
	factoryCalls := 0
	resetCmdFlags(t, keyDecryptCmd)
	t.Cleanup(func() { resetCmdFlags(t, keyDecryptCmd) })
	withGlobalConfig(t, &Config{
		OutputFormat: "text",
		Backend:      "software",
		ClientFactory: func(*Config) (client.Client, error) {
			factoryCalls++
			return mock, nil
		},
	})
	require.NoError(t, keyDecryptCmd.Flags().Set("padding", "bogus"))
	ct := base64.StdEncoding.EncodeToString([]byte("ct"))
	code := -1
	stderr := captureStderr(t, func() {
		code = captureExit(t, func() { keyDecryptCmd.Run(keyDecryptCmd, []string{"k", ct}) })
	})
	assert.Equal(t, 1, code)
	assert.Zero(t, factoryCalls, "no client is created for an unknown padding")
	_, sent := mock.requests["decrypt"]
	assert.False(t, sent, "no decrypt request is sent")
	assert.Contains(t, stderr, "bogus")
	assert.Contains(t, stderr, "oaep-sha256")
	assert.Contains(t, stderr, "pkcs1v15")
}

// TestKeyDecrypt_EmbeddedRSARoundTripDefaultPolicy drives encrypt-asym then
// decrypt on the embedded transport under the default policy: the default
// padding round-trips and pkcs1v15 is refused by the legacy-wrap policy.
func TestKeyDecrypt_EmbeddedRSARoundTripDefaultPolicy(t *testing.T) {
	require.False(t, types.AllowLegacyKeyWrap(), "default policy refuses PKCS#1 v1.5")

	xkms.Reset()
	t.Cleanup(xkms.Reset)

	cfg := NewConfig()
	cfg.Protocol = "embedded"
	cfg.KeyDir = t.TempDir()
	cfg.OutputFormat = "text"
	withGlobalConfig(t, cfg)

	cl, err := cfg.CreateClient()
	require.NoError(t, err)
	t.Cleanup(func() { closeQuietly(cl) })
	ctx := context.Background()
	require.NoError(t, cl.Connect(ctx))

	const keyID = "rsa-decrypt-2280"
	_, err = cl.GenerateKey(ctx, &client.GenerateKeyRequest{
		KeyID:     keyID,
		Backend:   cfg.Backend,
		KeyType:   "rsa",
		KeySize:   2048,
		Algorithm: "rsa",
	})
	require.NoError(t, err)

	plaintext := []byte("issue 2280 round trip")
	enc, err := cl.EncryptAsym(ctx, &client.EncryptAsymRequest{
		Backend:   cfg.Backend,
		KeyID:     keyID,
		Plaintext: plaintext,
		Hash:      "sha256",
	})
	require.NoError(t, err)
	ct := base64.StdEncoding.EncodeToString(enc.Ciphertext)

	run := func(flags map[string]string) (string, string, int) {
		resetCmdFlags(t, keyDecryptCmd)
		t.Cleanup(func() { resetCmdFlags(t, keyDecryptCmd) })
		for name, value := range flags {
			require.NoError(t, keyDecryptCmd.Flags().Set(name, value))
		}
		code := -1
		var stdout string
		stderr := captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				code = captureExit(t, func() { keyDecryptCmd.Run(keyDecryptCmd, []string{keyID, ct}) })
			})
		})
		return stdout, stderr, code
	}

	stdout, stderr, code := run(nil)
	require.Equal(t, -1, code, "default padding decrypts: %s", stderr)
	assert.Contains(t, stdout, base64.StdEncoding.EncodeToString(plaintext))

	_, stderr, code = run(map[string]string{"padding": "pkcs1v15"})
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "unauthenticated key wrapping is disabled by policy")
}
