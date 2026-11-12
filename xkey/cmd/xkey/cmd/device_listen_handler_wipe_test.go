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

package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
)

// TestEncodeBridgeResponse_WipesTheEncodedResult proves the bridge's encoded
// result, which can carry a decrypted plaintext or a shared secret, is zeroed
// once it has been copied into the response frame.
func TestEncodeBridgeResponse_WipesTheEncodedResult(t *testing.T) {
	result := json.RawMessage(`{"plaintext":"c2VjcmV0"}`)
	resp := &pairingproto.Response{JSONRPC: "2.0", ID: 7, Result: result}

	frame, err := encodeBridgeResponse(resp)
	require.NoError(t, err)

	assert.Contains(t, string(frame), "c2VjcmV0", "the frame must carry the result")
	assert.Equal(t, make([]byte, len(result)), []byte(result), "the encoded result must be wiped")
}

// TestEncodeBridgeResponse_WipesOnEncodeError proves the result is wiped even
// when the response cannot be encoded.
func TestEncodeBridgeResponse_WipesOnEncodeError(t *testing.T) {
	result := json.RawMessage(`{"plaintext":`) // not valid JSON
	resp := &pairingproto.Response{JSONRPC: "2.0", ID: 7, Result: result}

	_, err := encodeBridgeResponse(resp)
	require.Error(t, err)
	assert.Equal(t, make([]byte, len(result)), []byte(result), "the result must be wiped on error")
}
