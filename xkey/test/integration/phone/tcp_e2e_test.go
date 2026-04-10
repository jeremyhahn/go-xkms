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

//go:build integration

package phone

// tcp_e2e_test.go tests the Noise XX encrypted transport protocol over
// real TCP connections. This validates the transport layer (the upper-most
// abstraction for the pairing protocol per CLAUDE.md) since individual
// protocol steps (handshake, encryption, fragmentation) have no CLI commands.

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tcpE2EClient wraps a TCP connection and Noise session for E2E testing.
type tcpE2EClient struct {
	conn    net.Conn
	session *phone.NoiseSession
}

// newTCPE2EClient connects to the TCP phone server, performs a Noise XX
// handshake, and returns a client ready to send encrypted JSON-RPC requests.
func newTCPE2EClient(t *testing.T, serverAddr string) *tcpE2EClient {
	t.Helper()

	conn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	require.NoError(t, err, "dial TCP server")

	clientKey, err := phone.GenerateStaticKey()
	require.NoError(t, err, "generate client static key")

	session, err := phone.NewNoiseSession(&phone.NoiseSessionConfig{
		LocalStaticKey: clientKey,
		IsInitiator:    true,
	})
	require.NoError(t, err, "create client noise session")
	require.NoError(t, session.InitHandshake(), "init client handshake")

	// Noise XX step 1: initiator sends msg1 (e)
	msg1, complete, err := session.HandshakeMessage(nil)
	require.NoError(t, err, "handshake msg1")
	require.False(t, complete, "handshake should not be complete after msg1")
	require.NoError(t, tcpWrite(conn, msg1), "send msg1")

	// Noise XX step 2: receive msg2 from responder (e, ee, s, es)
	msg2, err := tcpRead(conn)
	require.NoError(t, err, "receive msg2")

	// Noise XX step 3: process msg2, generate msg3 (s, se) — completes for initiator
	msg3, complete, err := session.HandshakeMessage(msg2)
	require.NoError(t, err, "handshake msg3")
	require.True(t, complete, "handshake should be complete for initiator")
	require.NoError(t, tcpWrite(conn, msg3), "send msg3")

	return &tcpE2EClient{conn: conn, session: session}
}

// sendRequest encrypts a JSON-RPC request, sends it over TCP, reads the
// encrypted response, and decrypts it.
func (c *tcpE2EClient) sendRequest(t *testing.T, req *phone.Request) *phone.Response {
	t.Helper()

	reqBytes, err := json.Marshal(req)
	require.NoError(t, err, "marshal request")

	encrypted, err := c.session.Encrypt(reqBytes)
	require.NoError(t, err, "encrypt request")

	require.NoError(t, tcpWrite(c.conn, encrypted), "send encrypted request")

	ciphertext, err := tcpRead(c.conn)
	require.NoError(t, err, "receive encrypted response")

	plaintext, err := c.session.Decrypt(ciphertext)
	require.NoError(t, err, "decrypt response")

	var resp phone.Response
	require.NoError(t, json.Unmarshal(plaintext, &resp), "unmarshal response")
	return &resp
}

func (c *tcpE2EClient) close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// tcpWrite sends a message with 2-byte big-endian length-prefix framing.
func tcpWrite(conn net.Conn, data []byte) error {
	frame := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(data)))
	copy(frame[2:], data)
	_, err := conn.Write(frame)
	return err
}

// tcpRead reads a 2-byte big-endian length-prefixed message from the connection.
func tcpRead(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(header)
	if length == 0 {
		return []byte{}, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// startServer is a test helper that creates, starts, and registers cleanup
// for a TCPPhoneServer.
func startServer(t *testing.T) *TCPPhoneServer {
	t.Helper()

	srv, err := NewTCPPhoneServer()
	require.NoError(t, err, "create TCP phone server")

	require.NoError(t, srv.Start(), "start TCP phone server")
	t.Cleanup(func() { srv.Stop() })

	return srv
}

func TestTCPE2E_Handshake(t *testing.T) {
	srv := startServer(t)

	client := newTCPE2EClient(t, srv.Addr())
	defer client.close()

	// Handshake succeeded if we get here without error.
	assert.NotNil(t, client.session)
}

func TestTCPE2E_Ping(t *testing.T) {
	srv := startServer(t)

	client := newTCPE2EClient(t, srv.Addr())
	defer client.close()

	resp := client.sendRequest(t, phone.NewRequest(phone.MethodPing, nil))
	require.Nil(t, resp.Error, "ping should not return error")

	result, err := phone.DecodeResult[phone.PingResult](resp)
	require.NoError(t, err)
	assert.True(t, result.Pong)
}

func TestTCPE2E_GetInfo(t *testing.T) {
	srv := startServer(t)

	client := newTCPE2EClient(t, srv.Addr())
	defer client.close()

	resp := client.sendRequest(t, phone.NewRequest(phone.MethodGetInfo, nil))
	require.Nil(t, resp.Error)

	result, err := phone.DecodeResult[phone.GetInfoResult](resp)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0-mock-tcp", result.Version)
	assert.Equal(t, "Mock Phone (TCP)", result.DeviceName)
	assert.Contains(t, result.SupportedAlgorithms, phone.COSEAlgES256)
	assert.Contains(t, result.SupportedAlgorithms, phone.COSEAlgES384)
	assert.Contains(t, result.SupportedAlgorithms, phone.COSEAlgES512)
}

func TestTCPE2E_GenerateKey(t *testing.T) {
	srv := startServer(t)

	client := newTCPE2EClient(t, srv.Addr())
	defer client.close()

	credID := make([]byte, 32)
	rand.Read(credID)

	resp := client.sendRequest(t, phone.NewRequest(phone.MethodGenerateKey, &phone.GenerateKeyParams{
		CredentialID: credID,
		Algorithm:    phone.COSEAlgES256,
	}))
	require.Nil(t, resp.Error, "generate key should not return error")

	result, err := phone.DecodeResult[phone.GenerateKeyResult](resp)
	require.NoError(t, err)
	assert.NotEmpty(t, result.PublicKeyCOSE)
	assert.Equal(t, 1, srv.KeyCount())
}

func TestTCPE2E_Sign(t *testing.T) {
	srv := startServer(t)

	client := newTCPE2EClient(t, srv.Addr())
	defer client.close()

	credID := make([]byte, 32)
	rand.Read(credID)

	// Generate key first.
	genResp := client.sendRequest(t, phone.NewRequest(phone.MethodGenerateKey, &phone.GenerateKeyParams{
		CredentialID: credID,
		Algorithm:    phone.COSEAlgES256,
	}))
	require.Nil(t, genResp.Error)

	// Sign data.
	dataHash := make([]byte, 32) // SHA-256 sized hash
	rand.Read(dataHash)
	signResp := client.sendRequest(t, phone.NewRequest(phone.MethodSign, &phone.SignParams{
		CredentialID: credID,
		DataHash:     dataHash,
	}))
	require.Nil(t, signResp.Error)

	result, err := phone.DecodeResult[phone.SignResult](signResp)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Signature)
	// ES256 produces a 64-byte fixed-size signature (32 bytes r + 32 bytes s).
	assert.Len(t, result.Signature, 64)
}

func TestTCPE2E_DeleteKey(t *testing.T) {
	srv := startServer(t)

	client := newTCPE2EClient(t, srv.Addr())
	defer client.close()

	credID := make([]byte, 32)
	rand.Read(credID)

	// Generate key.
	genResp := client.sendRequest(t, phone.NewRequest(phone.MethodGenerateKey, &phone.GenerateKeyParams{
		CredentialID: credID,
		Algorithm:    phone.COSEAlgES256,
	}))
	require.Nil(t, genResp.Error)
	assert.Equal(t, 1, srv.KeyCount())

	// Delete key.
	delResp := client.sendRequest(t, phone.NewRequest(phone.MethodDeleteKey, &phone.DeleteKeyParams{
		CredentialID: credID,
	}))
	require.Nil(t, delResp.Error)

	result, err := phone.DecodeResult[phone.DeleteKeyResult](delResp)
	require.NoError(t, err)
	assert.True(t, result.Deleted)
	assert.Equal(t, 0, srv.KeyCount())
}

func TestTCPE2E_LoadKey(t *testing.T) {
	srv := startServer(t)

	client := newTCPE2EClient(t, srv.Addr())
	defer client.close()

	credID := make([]byte, 32)
	rand.Read(credID)

	// Generate key.
	genResp := client.sendRequest(t, phone.NewRequest(phone.MethodGenerateKey, &phone.GenerateKeyParams{
		CredentialID: credID,
		Algorithm:    phone.COSEAlgES256,
	}))
	require.Nil(t, genResp.Error)

	genResult, err := phone.DecodeResult[phone.GenerateKeyResult](genResp)
	require.NoError(t, err)

	// Load key and compare.
	loadResp := client.sendRequest(t, phone.NewRequest(phone.MethodLoadKey, &phone.LoadKeyParams{
		CredentialID: credID,
		Algorithm:    phone.COSEAlgES256,
	}))
	require.Nil(t, loadResp.Error)

	loadResult, err := phone.DecodeResult[phone.LoadKeyResult](loadResp)
	require.NoError(t, err)
	assert.Equal(t, genResult.PublicKeyCOSE, loadResult.PublicKeyCOSE)
}

func TestTCPE2E_SignKeyNotFound(t *testing.T) {
	srv := startServer(t)

	client := newTCPE2EClient(t, srv.Addr())
	defer client.close()

	nonExistentCredID := make([]byte, 32)
	rand.Read(nonExistentCredID)

	dummyHash := make([]byte, 32)
	rand.Read(dummyHash)
	resp := client.sendRequest(t, phone.NewRequest(phone.MethodSign, &phone.SignParams{
		CredentialID: nonExistentCredID,
		DataHash:     dummyHash,
	}))
	require.NotNil(t, resp.Error)
	assert.Equal(t, phone.ErrorCodeKeyNotFound, resp.Error.Code)
}

func TestTCPE2E_MethodNotFound(t *testing.T) {
	srv := startServer(t)

	client := newTCPE2EClient(t, srv.Addr())
	defer client.close()

	resp := client.sendRequest(t, phone.NewRequest("nonexistent.method", nil))
	require.NotNil(t, resp.Error)
	assert.Equal(t, phone.ErrorCodeMethodNotFound, resp.Error.Code)
}

func TestTCPE2E_MultipleOperations(t *testing.T) {
	srv := startServer(t)

	client := newTCPE2EClient(t, srv.Addr())
	defer client.close()

	// Run 10 generate/sign/delete cycles over the same TCP connection.
	for i := 0; i < 10; i++ {
		credID := make([]byte, 32)
		rand.Read(credID)

		genResp := client.sendRequest(t, phone.NewRequest(phone.MethodGenerateKey, &phone.GenerateKeyParams{
			CredentialID: credID,
			Algorithm:    phone.COSEAlgES256,
		}))
		require.Nil(t, genResp.Error, "iteration %d: generate key", i)

		signHash := make([]byte, 32)
		rand.Read(signHash)
		signResp := client.sendRequest(t, phone.NewRequest(phone.MethodSign, &phone.SignParams{
			CredentialID: credID,
			DataHash:     signHash,
		}))
		require.Nil(t, signResp.Error, "iteration %d: sign", i)

		delResp := client.sendRequest(t, phone.NewRequest(phone.MethodDeleteKey, &phone.DeleteKeyParams{
			CredentialID: credID,
		}))
		require.Nil(t, delResp.Error, "iteration %d: delete key", i)
	}

	assert.Equal(t, 0, srv.KeyCount())
}

func TestTCPE2E_ConcurrentClients(t *testing.T) {
	srv := startServer(t)

	const numClients = 5
	var wg sync.WaitGroup
	errs := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			client := newTCPE2EClient(t, srv.Addr())
			defer client.close()

			// Each client does a ping.
			resp := client.sendRequest(t, phone.NewRequest(phone.MethodPing, nil))
			if resp.Error != nil {
				errs <- resp.Error
				return
			}

			// Each client generates a key.
			credID := make([]byte, 32)
			rand.Read(credID)
			genResp := client.sendRequest(t, phone.NewRequest(phone.MethodGenerateKey, &phone.GenerateKeyParams{
				CredentialID: credID,
				Algorithm:    phone.COSEAlgES256,
			}))
			if genResp.Error != nil {
				errs <- genResp.Error
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent client error: %v", err)
	}

	assert.Equal(t, numClients, srv.KeyCount())
}

func TestTCPE2E_ClientDisconnectReconnect(t *testing.T) {
	srv := startServer(t)

	// First connection.
	client1 := newTCPE2EClient(t, srv.Addr())
	resp := client1.sendRequest(t, phone.NewRequest(phone.MethodPing, nil))
	require.Nil(t, resp.Error)
	client1.close()

	// Short delay for the server to detect the disconnection.
	time.Sleep(50 * time.Millisecond)

	// Second connection with fresh Noise session.
	client2 := newTCPE2EClient(t, srv.Addr())
	defer client2.close()

	resp = client2.sendRequest(t, phone.NewRequest(phone.MethodPing, nil))
	require.Nil(t, resp.Error)

	result, err := phone.DecodeResult[phone.PingResult](resp)
	require.NoError(t, err)
	assert.True(t, result.Pong)
}

func TestTCPE2E_AllAlgorithms(t *testing.T) {
	algorithms := []struct {
		name    string
		alg     int
		sigSize int
	}{
		{"ES256", phone.COSEAlgES256, 64},
		{"ES384", phone.COSEAlgES384, 96},
		{"ES512", phone.COSEAlgES512, 132},
	}

	for _, tt := range algorithms {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t)

			client := newTCPE2EClient(t, srv.Addr())
			defer client.close()

			credID := make([]byte, 32)
			rand.Read(credID)

			// Generate key.
			genResp := client.sendRequest(t, phone.NewRequest(phone.MethodGenerateKey, &phone.GenerateKeyParams{
				CredentialID: credID,
				Algorithm:    tt.alg,
			}))
			require.Nil(t, genResp.Error)

			genResult, err := phone.DecodeResult[phone.GenerateKeyResult](genResp)
			require.NoError(t, err)
			assert.NotEmpty(t, genResult.PublicKeyCOSE)

			// Sign data.
			sigHash := make([]byte, 32)
			rand.Read(sigHash)
			signResp := client.sendRequest(t, phone.NewRequest(phone.MethodSign, &phone.SignParams{
				CredentialID: credID,
				DataHash:     sigHash,
			}))
			require.Nil(t, signResp.Error)

			signResult, err := phone.DecodeResult[phone.SignResult](signResp)
			require.NoError(t, err)
			assert.Len(t, signResult.Signature, tt.sigSize)
		})
	}
}
