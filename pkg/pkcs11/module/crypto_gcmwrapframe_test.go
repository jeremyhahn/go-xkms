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

package module

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// PKCS#11 v3.2 §6.13.3: C_WrapKey with CKM_AES_GCM returns the ciphertext
// with the tag appended, and the IV travels only in CK_GCM_PARAMS.pIv. The
// key service frames its wrap as mode || nonce || ciphertext || tag, so the
// module strips the frame on the way out and rebuilds it on the way in.

func TestUnframeGCMWrapReturnsCiphertextAndTag(t *testing.T) {
	iv := bytes.Repeat([]byte{0x0a}, GCMNonceSize)
	body := bytes.Repeat([]byte{0xc7}, 16+GCMTagSize)

	for _, mode := range []byte{gcmWrapModeExplicit, gcmWrapModeRandom} {
		framed := slices.Concat([]byte{mode}, iv, body)
		got, err := unframeGCMWrap(framed, iv, GCMTagSize)
		require.NoError(t, err, "mode 0x%02x", mode)
		assert.Equal(t, body, got, "the IV and mode byte must not reach the caller")

		got[0] ^= 0xff
		assert.Equal(t, byte(0xc7), framed[1+GCMNonceSize], "the result must not alias the service's buffer")
	}
}

func TestUnframeGCMWrapRefusesAFrameItCannotVouchFor(t *testing.T) {
	iv := bytes.Repeat([]byte{0x0a}, GCMNonceSize)
	body := bytes.Repeat([]byte{0xc7}, 16+GCMTagSize)
	otherIV := bytes.Repeat([]byte{0x0b}, GCMNonceSize)

	tests := []struct {
		name   string
		framed []byte
		iv     []byte
		code   CK_RV
	}{
		{"short IV", slices.Concat([]byte{gcmWrapModeExplicit}, iv, body), iv[:8], CKR_MECHANISM_PARAM_INVALID},
		{"no IV", slices.Concat([]byte{gcmWrapModeExplicit}, iv, body), nil, CKR_MECHANISM_PARAM_INVALID},
		{"tag only", slices.Concat([]byte{gcmWrapModeExplicit}, iv, body[:GCMTagSize]), iv, CKR_FUNCTION_FAILED},
		{"unknown mode", slices.Concat([]byte{0x02}, iv, body), iv, CKR_FUNCTION_FAILED},
		{"other nonce", slices.Concat([]byte{gcmWrapModeExplicit}, otherIV, body), iv, CKR_FUNCTION_FAILED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unframeGCMWrap(tt.framed, tt.iv, GCMTagSize)
			require.Error(t, err)
			assert.Nil(t, got)
			assert.True(t, errorHasCode(err, tt.code), "want %s, got %v", tt.code.String(), err)
		})
	}
}

func TestFrameGCMWrapNamesTheConstructionThatOpensIt(t *testing.T) {
	iv := bytes.Repeat([]byte{0x0a}, GCMNonceSize)
	wrapped := bytes.Repeat([]byte{0xc7}, 16+GCMTagSize)

	full, err := frameGCMWrap(wrapped, iv, GCMTagSize)
	require.NoError(t, err)
	assert.Equal(t, slices.Concat([]byte{gcmWrapModeRandom}, iv, wrapped), full,
		"a 96-bit IV with a full tag opens through the random-nonce construction in every FIPS posture")

	truncated, err := frameGCMWrap(wrapped, iv, 12)
	require.NoError(t, err)
	assert.Equal(t, slices.Concat([]byte{gcmWrapModeExplicit}, iv, wrapped), truncated,
		"a truncated tag needs arbitrary-IV GCM")
}

func TestFrameGCMWrapRefusesAWrappedKeyItCannotFrame(t *testing.T) {
	iv := bytes.Repeat([]byte{0x0a}, GCMNonceSize)

	_, err := frameGCMWrap(make([]byte, 32), iv[:11], GCMTagSize)
	assert.True(t, errorHasCode(err, CKR_MECHANISM_PARAM_INVALID), "got %v", err)

	_, err = frameGCMWrap(make([]byte, GCMTagSize), iv, GCMTagSize)
	assert.True(t, errorHasCode(err, CKR_WRAPPED_KEY_LEN_RANGE),
		"a blob no longer than its tag carries no key: got %v", err)
}

func TestUnwrapKeyByIDRefusesAGCMUnwrapWithoutTheIV(t *testing.T) {
	client := newWrapTransport(map[string][]byte{"unwrap-kek": []byte("unwrap-iv-KEK-01")})
	cm := NewCryptoManager(client, &CryptoManagerConfig{DefaultBackend: "wrapnonce-be"})

	_, err := cm.UnwrapKeyByID(context.Background(), &UnwrapKeyByIDRequest{
		UnwrappingKeyID: "unwrap-kek",
		WrappedKey:      make([]byte, 16+GCMTagSize),
		Algorithm:       string(types.WrapAESGCM),
		Params:          WrapMechanismParams{TagBits: 128},
	})
	require.Error(t, err)
	assert.True(t, errorHasCode(err, CKR_MECHANISM_PARAM_INVALID), "got %v", err)
}
