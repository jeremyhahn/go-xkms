// Copyright (c) 2026 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// TestEncodeNoiseStaticKeyHex_NilKey proves a missing key is an error and
// yields no bytes.
func TestEncodeNoiseStaticKeyHex_NilKey(t *testing.T) {
	hexKey, err := encodeNoiseStaticKeyHex(nil)
	require.Error(t, err)
	assert.Nil(t, hexKey)
}

// TestEncodeP256StaticKeyHex_RoundTrips proves the hex form decodes back to
// the same key.
func TestEncodeP256StaticKeyHex_RoundTrips(t *testing.T) {
	key, err := bootstrap.GenerateP256StaticKey()
	require.NoError(t, err)
	defer key.Destroy()

	hexKey, err := encodeP256StaticKeyHex(key)
	require.NoError(t, err)
	require.Len(t, hexKey, bootstrap.P256HexKeySize)

	decoded, err := decodeP256StaticKey(hexKey)
	require.NoError(t, err)
	defer decoded.Destroy()
	assert.Equal(t, key.PublicBytes(), decoded.PublicBytes())
}

// TestEncodeP256StaticKeyHex_NilKey proves a missing key is an error and
// yields no bytes.
func TestEncodeP256StaticKeyHex_NilKey(t *testing.T) {
	hexKey, err := encodeP256StaticKeyHex(nil)
	require.Error(t, err)
	assert.Nil(t, hexKey)
}
