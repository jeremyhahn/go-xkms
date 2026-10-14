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

package phone

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// retainingHandler keeps the exact slices the server hands it and returns, so
// a test can see whether the server wiped them after use.
type retainingHandler struct {
	mu       sync.Mutex
	request  []byte
	response []byte
}

func (h *retainingHandler) HandleRequest(_ context.Context, request []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.request = request
	h.response = []byte(`{"jsonrpc":"2.0","id":1,"result":{"plaintext":"c2VjcmV0"}}`)
	return h.response, nil
}

// TestTCPPairingServer_WipesRequestAndResponsePlaintext proves the request
// plaintext and the handler's response, both of which can carry key material,
// are zeroed once Noise has encrypted the response, and that the client still
// receives the response intact.
func TestTCPPairingServer_WipesRequestAndResponsePlaintext(t *testing.T) {
	handler := &retainingHandler{}
	srv, err := NewTCPPairingServer(&TCPPairingConfig{
		ListenAddr:     "127.0.0.1:0",
		RequestHandler: handler,
		LiveAttest:     alwaysLiveAttestForTest,
	})
	require.NoError(t, err)
	require.NoError(t, srv.Start())

	conn, err := net.DialTimeout("tcp", srv.Addr(), 2*time.Second)
	require.NoError(t, err)
	session := clientHandshake(t, conn)

	request := []byte(`{"jsonrpc":"2.0","id":1,"method":"remote.decrypt"}`)
	encrypted, err := session.Encrypt(request)
	require.NoError(t, err)
	require.NoError(t, tcpSend(conn, encrypted))

	ciphertext, err := tcpReceive(conn)
	require.NoError(t, err)
	plaintext, err := session.Decrypt(ciphertext)
	require.NoError(t, err)
	require.Contains(t, string(plaintext), "c2VjcmV0", "the client must still get the response")

	// Stop joins the connection goroutine, so the handler's slices are safe
	// to read afterwards.
	require.NoError(t, conn.Close())
	require.NoError(t, srv.Stop())

	handler.mu.Lock()
	defer handler.mu.Unlock()
	require.Len(t, handler.request, len(request))
	require.Equal(t, make([]byte, len(handler.request)), handler.request, "request plaintext must be wiped")
	require.False(t, bytes.Contains(handler.response, []byte("c2VjcmV0")), "response plaintext must be wiped")
	require.Equal(t, make([]byte, len(handler.response)), handler.response)
}
