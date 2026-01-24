// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package authenticator

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
)

// testResponseCollector collects HID responses for testing.
type testResponseCollector struct {
	responses [][]byte
	mu        sync.Mutex
}

func newTestResponseCollector() *testResponseCollector {
	return &testResponseCollector{
		responses: make([][]byte, 0),
	}
}

func (c *testResponseCollector) handler(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Make a copy
	resp := make([]byte, len(data))
	copy(resp, data)
	c.responses = append(c.responses, resp)
}

func (c *testResponseCollector) getResponses() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([][]byte, len(c.responses))
	copy(result, c.responses)
	return result
}

func (c *testResponseCollector) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.responses = c.responses[:0]
}

// createTestHandler creates a CTAPHIDHandler with test authenticator.
func createTestHandler(t *testing.T) (*CTAPHIDHandler, *testResponseCollector) {
	t.Helper()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.EnableHMACSecret = true
	config.EnableResidentKey = true

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	handler := NewCTAPHIDHandler(auth)
	collector := newTestResponseCollector()
	handler.SetResponseHandler(collector.handler)

	return handler, collector
}

// createInitPacket creates a CTAPHID_INIT packet.
func createInitPacket(cid uint32, nonce []byte) []byte {
	packet := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(packet[0:4], cid)
	packet[4] = CTAPHIDInit
	binary.BigEndian.PutUint16(packet[5:7], uint16(len(nonce)))
	copy(packet[7:], nonce)
	return packet
}

// createPingPacket creates a CTAPHID_PING packet.
func createPingPacket(cid uint32, payload []byte) []byte {
	packet := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(packet[0:4], cid)
	packet[4] = CTAPHIDPing
	binary.BigEndian.PutUint16(packet[5:7], uint16(len(payload)))
	copy(packet[7:], payload)
	return packet
}

// createCBORPacket creates a CTAPHID_CBOR packet.
func createCBORPacket(cid uint32, payload []byte) []byte {
	packet := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(packet[0:4], cid)
	packet[4] = CTAPHIDCBOR
	binary.BigEndian.PutUint16(packet[5:7], uint16(len(payload)))
	if len(payload) <= InitPacketPayloadSize {
		copy(packet[7:], payload)
	} else {
		copy(packet[7:], payload[:InitPacketPayloadSize])
	}
	return packet
}

// createContPacket creates a continuation packet.
func createContPacket(cid uint32, seq byte, payload []byte) []byte {
	packet := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(packet[0:4], cid)
	packet[4] = seq
	copy(packet[5:], payload)
	return packet
}

// parseInitResponse parses a CTAPHID_INIT response.
func parseInitResponse(t *testing.T, packet []byte) (nonce []byte, cid uint32) {
	t.Helper()

	if len(packet) < HIDPacketSize {
		t.Fatalf("packet too short: %d", len(packet))
	}

	cmd := packet[4]
	if cmd != CTAPHIDInit {
		t.Fatalf("expected INIT response, got command 0x%02X", cmd)
	}

	payloadLen := int(binary.BigEndian.Uint16(packet[5:7]))
	if payloadLen < 17 {
		t.Fatalf("INIT response too short: %d", payloadLen)
	}

	nonce = packet[7:15]
	cid = binary.BigEndian.Uint32(packet[15:19])
	return nonce, cid
}

// TestCTAPHIDHandler_Init tests channel initialization.
func TestCTAPHIDHandler_Init(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Send INIT with nonce
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := createInitPacket(CIDBroadcast, nonce)

	handler.HandleMessage(packet)

	// Check response
	responses := collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	respNonce, cid := parseInitResponse(t, responses[0])

	// Verify nonce echo
	if !bytes.Equal(respNonce, nonce) {
		t.Errorf("nonce mismatch: got %v, want %v", respNonce, nonce)
	}

	// Verify we got a valid CID
	if cid == 0 || cid == CIDBroadcast {
		t.Errorf("invalid CID allocated: 0x%08X", cid)
	}
}

// TestCTAPHIDHandler_InitInvalidLength tests INIT with wrong nonce length.
func TestCTAPHIDHandler_InitInvalidLength(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Send INIT with wrong nonce length
	nonce := []byte{0x01, 0x02, 0x03} // Should be 8 bytes
	packet := createInitPacket(CIDBroadcast, nonce)

	handler.HandleMessage(packet)

	// Check for error response
	responses := collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	cmd := responses[0][4]
	if cmd != CTAPHIDError {
		t.Errorf("expected ERROR response, got command 0x%02X", cmd)
	}
}

// TestCTAPHIDHandler_Ping tests ping echo.
func TestCTAPHIDHandler_Ping(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// First initialize a channel
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Send ping
	pingData := []byte("Hello, FIDO!")
	pingPacket := createPingPacket(cid, pingData)
	handler.HandleMessage(pingPacket)

	// Check response
	responses = collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	// Verify ping response
	respCID := binary.BigEndian.Uint32(responses[0][0:4])
	if respCID != cid {
		t.Errorf("CID mismatch: got 0x%08X, want 0x%08X", respCID, cid)
	}

	respCmd := responses[0][4]
	if respCmd != CTAPHIDPing {
		t.Errorf("expected PING response, got command 0x%02X", respCmd)
	}

	respLen := int(binary.BigEndian.Uint16(responses[0][5:7]))
	if respLen != len(pingData) {
		t.Errorf("response length mismatch: got %d, want %d", respLen, len(pingData))
	}

	respPayload := responses[0][7 : 7+respLen]
	if !bytes.Equal(respPayload, pingData) {
		t.Errorf("payload mismatch: got %v, want %v", respPayload, pingData)
	}
}

// TestCTAPHIDHandler_PingBroadcast tests ping on broadcast channel (should fail).
func TestCTAPHIDHandler_PingBroadcast(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Send ping to broadcast channel (invalid)
	pingData := []byte("Hello!")
	pingPacket := createPingPacket(CIDBroadcast, pingData)
	handler.HandleMessage(pingPacket)

	// Check for error response
	responses := collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	cmd := responses[0][4]
	if cmd != CTAPHIDError {
		t.Errorf("expected ERROR response, got command 0x%02X", cmd)
	}
}

// TestCTAPHIDHandler_CBORGetInfo tests CBOR GetInfo command.
func TestCTAPHIDHandler_CBORGetInfo(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// First initialize a channel
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Send GetInfo command (CTAP command 0x04)
	cborPayload := []byte{CmdGetInfo} // Just the command byte, no CBOR data
	cborPacket := createCBORPacket(cid, cborPayload)
	handler.HandleMessage(cborPacket)

	// Check response
	responses = collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected at least 1 response")
	}

	// Verify CBOR response
	respCID := binary.BigEndian.Uint32(responses[0][0:4])
	if respCID != cid {
		t.Errorf("CID mismatch: got 0x%08X, want 0x%08X", respCID, cid)
	}

	respCmd := responses[0][4]
	if respCmd != CTAPHIDCBOR {
		t.Errorf("expected CBOR response, got command 0x%02X", respCmd)
	}

	// First byte of payload should be status (0x00 = success)
	respLen := int(binary.BigEndian.Uint16(responses[0][5:7]))
	if respLen < 1 {
		t.Fatal("response too short")
	}

	status := responses[0][7]
	if status != StatusOK {
		t.Errorf("expected status OK (0x00), got 0x%02X", status)
	}
}

// TestCTAPHIDHandler_CBORInvalidChannel tests CBOR on uninitialized channel.
func TestCTAPHIDHandler_CBORInvalidChannel(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Send CBOR to an uninitialized channel
	cborPayload := []byte{CmdGetInfo}
	cborPacket := createCBORPacket(0x12345678, cborPayload)
	handler.HandleMessage(cborPacket)

	// Check for error response
	responses := collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	cmd := responses[0][4]
	if cmd != CTAPHIDError {
		t.Errorf("expected ERROR response, got command 0x%02X", cmd)
	}
}

// TestCTAPHIDHandler_MultiPacketPing tests multi-packet ping reassembly.
func TestCTAPHIDHandler_MultiPacketPing(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// First initialize a channel
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Create a large ping payload (larger than 57 bytes)
	pingData := make([]byte, 100)
	for i := range pingData {
		pingData[i] = byte(i)
	}

	// Send init packet with full length but partial data
	initPing := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(initPing[0:4], cid)
	initPing[4] = CTAPHIDPing
	binary.BigEndian.PutUint16(initPing[5:7], uint16(len(pingData)))
	copy(initPing[7:], pingData[:InitPacketPayloadSize])
	handler.HandleMessage(initPing)

	// Send continuation packet with remaining data
	remaining := pingData[InitPacketPayloadSize:]
	contPacket := createContPacket(cid, 0, remaining)
	handler.HandleMessage(contPacket)

	// Check response
	responses = collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected at least 1 response")
	}

	// Reassemble response if multi-packet
	var respPayload []byte
	for i, resp := range responses {
		if i == 0 {
			respLen := int(binary.BigEndian.Uint16(resp[5:7]))
			if respLen <= InitPacketPayloadSize {
				respPayload = resp[7 : 7+respLen]
			} else {
				respPayload = append(respPayload, resp[7:]...)
			}
		} else {
			respPayload = append(respPayload, resp[5:]...)
		}
	}

	// Trim to expected length
	if len(respPayload) > len(pingData) {
		respPayload = respPayload[:len(pingData)]
	}

	if !bytes.Equal(respPayload, pingData) {
		t.Errorf("ping response mismatch")
	}
}

// TestCTAPHIDHandler_MultiPacketResponse tests multi-packet response fragmentation.
func TestCTAPHIDHandler_MultiPacketResponse(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// First initialize a channel
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// GetInfo typically returns more than 57 bytes
	cborPayload := []byte{CmdGetInfo}
	cborPacket := createCBORPacket(cid, cborPayload)
	handler.HandleMessage(cborPacket)

	// Check responses
	responses = collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected at least 1 response")
	}

	// Verify first packet is an init packet
	firstResp := responses[0]
	if firstResp[4] != CTAPHIDCBOR {
		t.Errorf("expected CBOR response, got 0x%02X", firstResp[4])
	}

	respLen := int(binary.BigEndian.Uint16(firstResp[5:7]))

	// If response is > 57 bytes, we should have continuation packets
	if respLen > InitPacketPayloadSize {
		expectedPackets := 1 + (respLen-InitPacketPayloadSize+ContPacketPayloadSize-1)/ContPacketPayloadSize
		if len(responses) < expectedPackets {
			t.Errorf("expected at least %d packets for %d byte response, got %d",
				expectedPackets, respLen, len(responses))
		}

		// Verify continuation packets have correct sequence
		for i := 1; i < len(responses); i++ {
			seq := responses[i][4]
			if seq != byte(i-1) {
				t.Errorf("packet %d has wrong sequence: got %d, want %d", i, seq, i-1)
			}
		}
	}
}

// TestCTAPHIDHandler_Wink tests wink command.
func TestCTAPHIDHandler_Wink(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// First initialize a channel
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Send wink
	winkPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(winkPacket[0:4], cid)
	winkPacket[4] = CTAPHIDWink
	binary.BigEndian.PutUint16(winkPacket[5:7], 0)
	handler.HandleMessage(winkPacket)

	// Check response
	responses = collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	if responses[0][4] != CTAPHIDWink {
		t.Errorf("expected WINK response, got 0x%02X", responses[0][4])
	}
}

// TestCTAPHIDHandler_Cancel tests cancel command.
func TestCTAPHIDHandler_Cancel(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// First initialize a channel
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Send cancel
	cancelPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(cancelPacket[0:4], cid)
	cancelPacket[4] = CTAPHIDCancel
	binary.BigEndian.PutUint16(cancelPacket[5:7], 0)
	handler.HandleMessage(cancelPacket)

	// Cancel should not generate a response
	responses = collector.getResponses()
	if len(responses) != 0 {
		t.Errorf("expected no response for CANCEL, got %d", len(responses))
	}
}

// TestCTAPHIDHandler_InvalidCommand tests unknown command handling.
func TestCTAPHIDHandler_InvalidCommand(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// First initialize a channel
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Send unknown command
	unknownPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(unknownPacket[0:4], cid)
	unknownPacket[4] = 0xFF // Unknown command with high bit set
	binary.BigEndian.PutUint16(unknownPacket[5:7], 0)
	handler.HandleMessage(unknownPacket)

	// Check for error response
	responses = collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	if responses[0][4] != CTAPHIDError {
		t.Errorf("expected ERROR response, got 0x%02X", responses[0][4])
	}

	// Error code should be invalid command
	errCode := responses[0][7]
	if errCode != CTAPHIDErrInvalidCmd {
		t.Errorf("expected invalid command error (0x%02X), got 0x%02X",
			CTAPHIDErrInvalidCmd, errCode)
	}
}

// TestCTAPHIDHandler_SequenceMismatch tests sequence number validation.
func TestCTAPHIDHandler_SequenceMismatch(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// First initialize a channel
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Start a multi-packet ping
	pingData := make([]byte, 100)
	initPing := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(initPing[0:4], cid)
	initPing[4] = CTAPHIDPing
	binary.BigEndian.PutUint16(initPing[5:7], uint16(len(pingData)))
	copy(initPing[7:], pingData[:InitPacketPayloadSize])
	handler.HandleMessage(initPing)

	// Send continuation packet with wrong sequence (1 instead of 0)
	contPacket := createContPacket(cid, 1, pingData[InitPacketPayloadSize:])
	handler.HandleMessage(contPacket)

	// Should get error response
	responses = collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	if responses[0][4] != CTAPHIDError {
		t.Errorf("expected ERROR response, got 0x%02X", responses[0][4])
	}

	errCode := responses[0][7]
	if errCode != CTAPHIDErrInvalidSeq {
		t.Errorf("expected invalid sequence error (0x%02X), got 0x%02X",
			CTAPHIDErrInvalidSeq, errCode)
	}
}

// TestCTAPHIDHandler_Close tests handler closure.
func TestCTAPHIDHandler_Close(t *testing.T) {
	handler, collector := createTestHandler(t)

	// Close the handler
	err := handler.Close()
	if err != nil {
		t.Fatalf("unexpected error on close: %v", err)
	}

	// Messages should be ignored after close
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(packet)

	responses := collector.getResponses()
	if len(responses) != 0 {
		t.Errorf("expected no responses after close, got %d", len(responses))
	}

	// Close again should be safe
	err = handler.Close()
	if err != nil {
		t.Fatalf("unexpected error on second close: %v", err)
	}
}

// TestCTAPHIDHandler_ShortPacket tests handling of short packets.
func TestCTAPHIDHandler_ShortPacket(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Send a short packet
	shortPacket := make([]byte, 10)
	handler.HandleMessage(shortPacket)

	// Should get error response
	responses := collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	if responses[0][4] != CTAPHIDError {
		t.Errorf("expected ERROR response, got 0x%02X", responses[0][4])
	}
}

// TestCTAPHIDHandler_MultipleChannels tests multiple concurrent channels.
func TestCTAPHIDHandler_MultipleChannels(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Initialize first channel
	nonce1 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket1 := createInitPacket(CIDBroadcast, nonce1)
	handler.HandleMessage(initPacket1)

	responses := collector.getResponses()
	_, cid1 := parseInitResponse(t, responses[0])
	collector.clear()

	// Initialize second channel
	nonce2 := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	initPacket2 := createInitPacket(CIDBroadcast, nonce2)
	handler.HandleMessage(initPacket2)

	responses = collector.getResponses()
	_, cid2 := parseInitResponse(t, responses[0])
	collector.clear()

	// Channels should be different
	if cid1 == cid2 {
		t.Errorf("channels should have different CIDs: both got 0x%08X", cid1)
	}

	// Both channels should work independently
	ping1 := createPingPacket(cid1, []byte("channel1"))
	handler.HandleMessage(ping1)

	ping2 := createPingPacket(cid2, []byte("channel2"))
	handler.HandleMessage(ping2)

	responses = collector.getResponses()
	if len(responses) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(responses))
	}
}

// TestCTAPHIDHandler_Authenticator tests Authenticator accessor.
func TestCTAPHIDHandler_Authenticator(t *testing.T) {
	handler, _ := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	auth := handler.Authenticator()
	if auth == nil {
		t.Error("Authenticator() returned nil")
	}
}

// TestCTAPHIDHandler_NoResponseHandler tests behavior without response handler.
func TestCTAPHIDHandler_NoResponseHandler(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer func() { _ = auth.Close() }()

	handler := NewCTAPHIDHandler(auth)
	defer func() { _ = handler.Close() }()

	// Don't set response handler

	// Should not panic
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(packet)
}

// TestCTAPHIDHandler_U2FCommand tests U2F command rejection.
func TestCTAPHIDHandler_U2FCommand(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// First initialize a channel
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Send U2F command (not supported by native authenticator)
	u2fPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(u2fPacket[0:4], cid)
	u2fPacket[4] = CTAPHIDU2F
	binary.BigEndian.PutUint16(u2fPacket[5:7], 0)
	handler.HandleMessage(u2fPacket)

	// Should get error response
	responses = collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	if responses[0][4] != CTAPHIDError {
		t.Errorf("expected ERROR response, got 0x%02X", responses[0][4])
	}
}
