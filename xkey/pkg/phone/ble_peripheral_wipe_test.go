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

//go:build ble

package phone

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBLEPeripheral_ProcessRequestWipesPlaintexts proves the request
// plaintext and the handler's response, both of which can carry key material,
// are zeroed once Noise has encrypted the response, and that the phone still
// receives the response intact.
func TestBLEPeripheral_ProcessRequestWipesPlaintexts(t *testing.T) {
	handler := &retainingHandler{}
	writer := newCaptureWriter()
	p := newTestPeripheral(t, handler, writer)
	initiator := establishSession(t, p)

	request := []byte(`{"jsonrpc":"2.0","id":1,"method":"remote.decrypt"}`)
	encrypted, err := initiator.Encrypt(request)
	require.NoError(t, err)
	require.NoError(t, p.processRequest(context.Background(), encrypted))

	plaintext, err := initiator.Decrypt(writer.reassemble(t))
	require.NoError(t, err)
	require.Contains(t, string(plaintext), "c2VjcmV0", "the phone must still get the response")

	require.Len(t, handler.request, len(request))
	require.Equal(t, make([]byte, len(request)), handler.request, "request plaintext must be wiped")
	require.Equal(t, make([]byte, len(handler.response)), handler.response, "response plaintext must be wiped")
}
