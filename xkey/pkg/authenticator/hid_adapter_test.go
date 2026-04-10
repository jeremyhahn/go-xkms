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

package authenticator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
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

// TestCTAPHIDHandler_InitWINKCapability tests that the CTAPHID_INIT response
// includes the WINK capability bit (0x01) in the capabilities byte.
// Per CTAP HID spec, the capabilities byte is at offset 16 of the response payload.
func TestCTAPHIDHandler_InitWINKCapability(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(packet)

	responses := collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected exactly 1 INIT response, got %d", len(responses))
	}

	resp := responses[0]
	// Verify this is an INIT response.
	if resp[4] != byte(CTAPHIDInit) {
		t.Fatalf("expected INIT response command byte 0x%02x, got 0x%02x", CTAPHIDInit, resp[4])
	}

	// The INIT response payload starts at byte 7.
	// Payload layout: nonce(8) + CID(4) + protocolVersion(1) + majorVer(1) + minorVer(1) + buildVer(1) + capabilities(1)
	// Capabilities byte is at payload offset 16, which is resp[7+16] = resp[23].
	payloadLen := int(binary.BigEndian.Uint16(resp[5:7]))
	if payloadLen < 17 {
		t.Fatalf("INIT response payload must be at least 17 bytes, got %d", payloadLen)
	}

	capabilities := resp[7+16] // Capabilities byte
	winkBit := capabilities & 0x01
	if winkBit != 0x01 {
		t.Errorf("WINK capability bit (0x01) must be set in INIT response capabilities, got 0x%02x", capabilities)
	}

	// Also verify CBOR capability (0x04) is set.
	cborBit := capabilities & 0x04
	if cborBit != 0x04 {
		t.Errorf("CBOR capability bit (0x04) must be set in INIT response capabilities, got 0x%02x", capabilities)
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

// TestCTAPHIDHandler_SequentialCBORCommands verifies that multiple CBOR
// commands can be sent on the same channel without re-initializing. This
// reproduces the webauthn.io flow: INIT -> GetInfo -> GetInfo -> MakeCredential.
func TestCTAPHIDHandler_SequentialCBORCommands(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Initialize a channel
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	initPacket := createInitPacket(CIDBroadcast, nonce)
	handler.HandleMessage(initPacket)

	responses := collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected INIT response")
	}
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// First CBOR command: GetInfo
	cborPayload := []byte{CmdGetInfo}
	handler.HandleMessage(createCBORPacket(cid, cborPayload))

	responses = collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected response to first GetInfo")
	}
	if responses[0][4] != CTAPHIDCBOR {
		t.Fatalf("first GetInfo: expected CBOR response (0x%02X), got 0x%02X",
			CTAPHIDCBOR, responses[0][4])
	}
	if responses[0][7] != StatusOK {
		t.Fatalf("first GetInfo: expected StatusOK (0x00), got 0x%02X", responses[0][7])
	}
	collector.clear()

	// Second CBOR command on SAME channel: GetInfo again
	handler.HandleMessage(createCBORPacket(cid, cborPayload))

	responses = collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected response to second GetInfo - channel must survive after first command")
	}
	if responses[0][4] != CTAPHIDCBOR {
		t.Fatalf("second GetInfo: expected CBOR response (0x%02X), got 0x%02X",
			CTAPHIDCBOR, responses[0][4])
	}
	if responses[0][7] != StatusOK {
		t.Fatalf("second GetInfo: expected StatusOK (0x00), got 0x%02X", responses[0][7])
	}
	collector.clear()

	// Third CBOR command on SAME channel: GetInfo one more time
	handler.HandleMessage(createCBORPacket(cid, cborPayload))

	responses = collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected response to third GetInfo - channel must persist across commands")
	}
	if responses[0][4] != CTAPHIDCBOR {
		t.Fatalf("third GetInfo: expected CBOR response (0x%02X), got 0x%02X",
			CTAPHIDCBOR, responses[0][4])
	}
	if responses[0][7] != StatusOK {
		t.Fatalf("third GetInfo: expected StatusOK (0x00), got 0x%02X", responses[0][7])
	}
}

// TestCTAPHIDHandler_ChannelPersistsAfterMultiPacket verifies that the channel
// remains valid after a multi-packet message reassembly completes.
func TestCTAPHIDHandler_ChannelPersistsAfterMultiPacket(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Initialize a channel
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	handler.HandleMessage(createInitPacket(CIDBroadcast, nonce))

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Send multi-packet ping that spans init + 1 continuation packet
	pingLen := InitPacketPayloadSize + 10
	pingData := make([]byte, pingLen)
	for i := range pingData {
		pingData[i] = byte(i & 0xFF)
	}

	// Init packet
	initPkt := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(initPkt[0:4], cid)
	initPkt[4] = CTAPHIDPing
	binary.BigEndian.PutUint16(initPkt[5:7], uint16(pingLen))
	copy(initPkt[7:], pingData[:InitPacketPayloadSize])
	handler.HandleMessage(initPkt)

	// Continuation packet
	contPkt := createContPacket(cid, 0, pingData[InitPacketPayloadSize:])
	handler.HandleMessage(contPkt)

	// Verify ping response
	responses = collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected ping response")
	}
	if responses[0][4] != CTAPHIDPing {
		t.Fatalf("expected PING response, got 0x%02X", responses[0][4])
	}
	collector.clear()

	// Now send a CBOR command on the SAME channel - this must succeed
	handler.HandleMessage(createCBORPacket(cid, []byte{CmdGetInfo}))

	responses = collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected GetInfo response after multi-packet ping - channel must survive reassembly")
	}
	if responses[0][4] != CTAPHIDCBOR {
		t.Fatalf("post-reassembly GetInfo: expected CBOR response (0x%02X), got 0x%02X",
			CTAPHIDCBOR, responses[0][4])
	}
	if responses[0][7] != StatusOK {
		t.Fatalf("post-reassembly GetInfo: expected StatusOK, got 0x%02X", responses[0][7])
	}
}

// TestCTAPHIDHandler_ChannelPersistsAfterCancel verifies that the channel
// remains usable after a CANCEL command.
func TestCTAPHIDHandler_ChannelPersistsAfterCancel(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	// Initialize a channel
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	handler.HandleMessage(createInitPacket(CIDBroadcast, nonce))

	responses := collector.getResponses()
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()

	// Send CANCEL
	cancelPkt := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(cancelPkt[0:4], cid)
	cancelPkt[4] = CTAPHIDCancel
	binary.BigEndian.PutUint16(cancelPkt[5:7], 0)
	handler.HandleMessage(cancelPkt)

	// CANCEL produces no response, just clear any potential output
	collector.clear()

	// Now send a CBOR command on the SAME channel - must succeed
	handler.HandleMessage(createCBORPacket(cid, []byte{CmdGetInfo}))

	responses = collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected GetInfo response after CANCEL - channel must survive cancel")
	}
	if responses[0][4] != CTAPHIDCBOR {
		t.Fatalf("post-cancel GetInfo: expected CBOR response (0x%02X), got 0x%02X",
			CTAPHIDCBOR, responses[0][4])
	}
	if responses[0][7] != StatusOK {
		t.Fatalf("post-cancel GetInfo: expected StatusOK, got 0x%02X", responses[0][7])
	}
}

// delayedApproveHandler is a UserPresenceHandler that delays before approving.
// Used to test that CTAPHID_KEEPALIVE messages are sent during the delay.
type delayedApproveHandler struct {
	delay time.Duration
}

func (h *delayedApproveHandler) RequestUserPresence(_ context.Context, _ *UserPresenceRequest) (*UserPresenceResult, error) {
	time.Sleep(h.delay)
	return &UserPresenceResult{Approved: true}, nil
}

func (h *delayedApproveHandler) RequestUserVerification(_ context.Context, _ *UserVerificationRequest) (*UserVerificationResult, error) {
	return &UserVerificationResult{Verified: true}, nil
}

// createTestHandlerWithDelay creates a CTAPHIDHandler with a delayed user presence handler.
func createTestHandlerWithDelay(t *testing.T, delay time.Duration) (*CTAPHIDHandler, *testResponseCollector) {
	t.Helper()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = false
	config.EnableHMACSecret = false
	config.EnableResidentKey = true
	config.UserPresenceHandler = &delayedApproveHandler{delay: delay}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	handler := NewCTAPHIDHandler(auth)
	collector := newTestResponseCollector()
	handler.SetResponseHandler(collector.handler)

	return handler, collector
}

// buildMakeCredentialCBOR constructs a minimal valid MakeCredential CBOR payload
// (including the CmdMakeCredential command byte prefix).
func buildMakeCredentialCBOR(t *testing.T) []byte {
	t.Helper()

	clientDataHash := make([]byte, 32)
	for i := range clientDataHash {
		clientDataHash[i] = byte(i)
	}

	mcRequest := map[int]interface{}{
		0x01: clientDataHash,
		0x02: map[string]interface{}{"id": "test.example.com", "name": "Test RP"},
		0x03: map[string]interface{}{"id": []byte{0x01, 0x02, 0x03}, "name": "testuser"},
		0x04: []map[string]interface{}{{"type": "public-key", "alg": -7}},
	}

	data, err := cbor.Marshal(mcRequest)
	if err != nil {
		t.Fatalf("failed to encode MakeCredential CBOR: %v", err)
	}

	return append([]byte{CmdMakeCredential}, data...)
}

// sendMultiPacketCBOR sends a CBOR payload that may span multiple HID packets.
func sendMultiPacketCBOR(handler *CTAPHIDHandler, cid uint32, payload []byte) {
	// Send init packet
	handler.HandleMessage(createCBORPacket(cid, payload))

	// Send continuation packets if needed
	if len(payload) > InitPacketPayloadSize {
		remaining := payload[InitPacketPayloadSize:]
		seq := byte(0)
		for len(remaining) > 0 {
			contLen := ContPacketPayloadSize
			if contLen > len(remaining) {
				contLen = len(remaining)
			}
			handler.HandleMessage(createContPacket(cid, seq, remaining[:contLen]))
			remaining = remaining[contLen:]
			seq++
		}
	}
}

// initializeChannel performs CTAPHID_INIT and returns the allocated channel ID.
func initializeChannel(t *testing.T, handler *CTAPHIDHandler, collector *testResponseCollector) uint32 {
	t.Helper()
	nonce := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	handler.HandleMessage(createInitPacket(CIDBroadcast, nonce))
	responses := collector.getResponses()
	if len(responses) == 0 {
		t.Fatal("no INIT response received")
	}
	_, cid := parseInitResponse(t, responses[0])
	collector.clear()
	return cid
}

// TestCTAPHIDHandler_KeepalivesDuringMakeCredential verifies that CTAPHID_KEEPALIVE
// messages are sent while the authenticator is waiting for user presence during
// MakeCredential. Without keepalives, browsers like Chrome will timeout and abort.
func TestCTAPHIDHandler_KeepalivesDuringMakeCredential(t *testing.T) {
	handler, collector := createTestHandlerWithDelay(t, 500*time.Millisecond)
	defer func() { _ = handler.Close() }()

	cid := initializeChannel(t, handler, collector)

	// Send MakeCredential (multi-packet CBOR command)
	payload := buildMakeCredentialCBOR(t)
	sendMultiPacketCBOR(handler, cid, payload)

	// Wait for the delayed response plus margin
	time.Sleep(800 * time.Millisecond)

	responses := collector.getResponses()

	// Categorize responses: keepalives vs CBOR response
	keepaliveCount := 0
	var cborResponseIdx int = -1
	for i, resp := range responses {
		cmd := resp[4]
		if cmd == CTAPHIDKeepalive {
			keepaliveCount++
			// Verify CID matches
			respCID := binary.BigEndian.Uint32(resp[0:4])
			if respCID != cid {
				t.Errorf("keepalive CID = 0x%08x, want 0x%08x", respCID, cid)
			}
			// Verify keepalive status is STATUS_UPNEEDED for MakeCredential
			bcnt := binary.BigEndian.Uint16(resp[5:7])
			if bcnt != 1 {
				t.Errorf("keepalive BCNT = %d, want 1", bcnt)
			}
			status := resp[7]
			if status != KeepaliveStatusUpNeeded {
				t.Errorf("keepalive status = 0x%02x, want KeepaliveStatusUpNeeded (0x%02x)",
					status, KeepaliveStatusUpNeeded)
			}
		} else if cmd == CTAPHIDCBOR {
			cborResponseIdx = i
		}
	}

	// Must have at least 1 keepalive during the 500ms delay (at 100ms intervals, expect ~4-5)
	if keepaliveCount == 0 {
		t.Fatal("expected keepalive messages during MakeCredential, got none")
	}
	t.Logf("received %d keepalive messages during 500ms user presence delay", keepaliveCount)

	// Must have the CBOR response
	if cborResponseIdx < 0 {
		t.Fatal("expected CBOR response after keepalives")
	}

	// CBOR response must come AFTER all keepalives
	if cborResponseIdx < keepaliveCount {
		t.Errorf("CBOR response (idx=%d) arrived before all keepalives (count=%d)",
			cborResponseIdx, keepaliveCount)
	}

	// Verify MakeCredential succeeded (status byte = 0x00)
	cborResp := responses[cborResponseIdx]
	cborStatus := cborResp[7]
	if cborStatus != StatusOK {
		t.Errorf("MakeCredential status = 0x%02x, want StatusOK (0x00)", cborStatus)
	}
}

// TestCTAPHIDHandler_NoKeepalivesForGetInfo verifies that CTAPHID_KEEPALIVE
// messages are NOT sent for quick commands like GetInfo that don't require
// user interaction.
func TestCTAPHIDHandler_NoKeepalivesForGetInfo(t *testing.T) {
	handler, collector := createTestHandler(t)
	defer func() { _ = handler.Close() }()

	cid := initializeChannel(t, handler, collector)

	// Send GetInfo (instant response, no user presence needed)
	handler.HandleMessage(createCBORPacket(cid, []byte{CmdGetInfo}))

	// Small sleep to let any hypothetical keepalives arrive
	time.Sleep(250 * time.Millisecond)

	responses := collector.getResponses()

	for _, resp := range responses {
		if resp[4] == CTAPHIDKeepalive {
			t.Fatal("GetInfo should NOT trigger keepalive messages")
		}
	}

	// Verify we got a proper CBOR response
	found := false
	for _, resp := range responses {
		if resp[4] == CTAPHIDCBOR {
			found = true
			if resp[7] != StatusOK {
				t.Errorf("GetInfo status = 0x%02x, want StatusOK", resp[7])
			}
		}
	}
	if !found {
		t.Fatal("expected GetInfo CBOR response")
	}
}

// TestCTAPHIDHandler_KeepalivePacketFormat verifies the exact format of
// CTAPHID_KEEPALIVE packets per the CTAP HID specification.
func TestCTAPHIDHandler_KeepalivePacketFormat(t *testing.T) {
	handler, collector := createTestHandlerWithDelay(t, 300*time.Millisecond)
	defer func() { _ = handler.Close() }()

	cid := initializeChannel(t, handler, collector)

	// Send MakeCredential to trigger keepalives
	payload := buildMakeCredentialCBOR(t)
	sendMultiPacketCBOR(handler, cid, payload)

	// Wait for response
	time.Sleep(500 * time.Millisecond)

	responses := collector.getResponses()

	// Find the first keepalive
	var keepalive []byte
	for _, resp := range responses {
		if resp[4] == CTAPHIDKeepalive {
			keepalive = resp
			break
		}
	}
	if keepalive == nil {
		t.Fatal("no keepalive packet received")
	}

	// Verify packet format:
	// Bytes 0-3: CID
	// Byte 4: CMD (0xBB = CTAPHID_KEEPALIVE)
	// Bytes 5-6: BCNT (0x0001)
	// Byte 7: Status (0x02 = STATUS_UPNEEDED)
	// Bytes 8-63: padding zeros

	if len(keepalive) != HIDPacketSize {
		t.Fatalf("keepalive packet size = %d, want %d", len(keepalive), HIDPacketSize)
	}

	pktCID := binary.BigEndian.Uint32(keepalive[0:4])
	if pktCID != cid {
		t.Errorf("keepalive CID = 0x%08x, want 0x%08x", pktCID, cid)
	}

	if keepalive[4] != CTAPHIDKeepalive {
		t.Errorf("keepalive CMD = 0x%02x, want 0x%02x", keepalive[4], CTAPHIDKeepalive)
	}

	bcnt := binary.BigEndian.Uint16(keepalive[5:7])
	if bcnt != 1 {
		t.Errorf("keepalive BCNT = %d, want 1", bcnt)
	}

	if keepalive[7] != KeepaliveStatusUpNeeded {
		t.Errorf("keepalive status = 0x%02x, want 0x%02x", keepalive[7], KeepaliveStatusUpNeeded)
	}

	// Remaining bytes should be zero padding
	for i := 8; i < HIDPacketSize; i++ {
		if keepalive[i] != 0 {
			t.Errorf("keepalive byte[%d] = 0x%02x, want 0x00 (padding)", i, keepalive[i])
			break
		}
	}
}

// TestCTAPHIDHandler_KeepaliveProcessingWhenPINRequired verifies that when
// PIN is enabled and set, and the request does NOT carry pinUvAuthParam,
// the keepalive status is KeepaliveStatusProcessing (not UpNeeded).
// This prevents Chrome from showing "Touch your security key" before PIN entry.
func TestCTAPHIDHandler_KeepaliveProcessingWhenPINRequired(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.EnableHMACSecret = false
	config.EnableResidentKey = true
	// Use a delayed approve handler so keepalives have time to be sent.
	config.UserPresenceHandler = &delayedApproveHandler{delay: 500 * time.Millisecond}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer func() { _ = auth.Close() }()

	// Set a PIN so NeedsPINBeforeTouch returns true.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)

	handler := NewCTAPHIDHandler(auth)
	defer func() { _ = handler.Close() }()

	collector := newTestResponseCollector()
	handler.SetResponseHandler(collector.handler)

	cid := initializeChannel(t, handler, collector)

	// Build MakeCredential CBOR WITHOUT pinUvAuthParam — Chrome's first
	// attempt before it knows PIN is needed.
	payload := buildMakeCredentialCBOR(t)
	sendMultiPacketCBOR(handler, cid, payload)

	time.Sleep(800 * time.Millisecond)
	responses := collector.getResponses()

	gotProcessing := false
	gotUpNeeded := false
	for _, resp := range responses {
		if resp[4] == CTAPHIDKeepalive {
			switch resp[7] {
			case KeepaliveStatusProcessing:
				gotProcessing = true
			case KeepaliveStatusUpNeeded:
				gotUpNeeded = true
			}
		}
	}

	if !gotProcessing {
		t.Error("expected KeepaliveStatusProcessing when PIN is required but not yet provided")
	}
	if gotUpNeeded {
		t.Error("should NOT send KeepaliveStatusUpNeeded when PIN is required but not yet provided")
	}
}

// TestCtapCommandName tests the CTAP command name lookup function.
func TestCtapCommandName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		cmd      byte
		expected string
	}{
		{CmdMakeCredential, "MakeCredential"},
		{CmdGetAssertion, "GetAssertion"},
		{CmdGetInfo, "GetInfo"},
		{CmdClientPIN, "ClientPIN"},
		{CmdReset, "Reset"},
		{CmdGetNextAssertion, "GetNextAssertion"},
		{CmdCredentialManagement, "CredentialManagement"},
		{CmdSelection, "Selection"},
		{CmdLargeBlobs, "LargeBlobs"},
		{CmdConfig, "Config"},
		{0xFF, "Unknown(0xFF)"},
		{0x00, "Unknown(0x00)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			result := ctapCommandName(tt.cmd)
			if result != tt.expected {
				t.Errorf("ctapCommandName(0x%02X) = %q, want %q", tt.cmd, result, tt.expected)
			}
		})
	}
}

// TestCTAPHIDHandler_SetLogger tests the SetLogger method.
func TestCTAPHIDHandler_SetLogger(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	handler := NewCTAPHIDHandler(auth)
	defer handler.Close()

	// Set nil logger
	handler.SetLogger(nil)

	// Set actual logger
	logger := auth.Config().Logger
	handler.SetLogger(logger)
}

// =============================================================================
// Tests for processCBORCommandLocked
// =============================================================================

// TestProcessCBORCommandLocked_EmptyPayload tests processCBORCommandLocked
// with an empty payload (zero length).
func TestProcessCBORCommandLocked_EmptyPayload(t *testing.T) {
	t.Parallel()

	handler, collector := createTestHandler(t)
	defer handler.Close()

	cid := initializeChannel(t, handler, collector)

	// Send CBOR packet with empty payload
	emptyPayload := []byte{}
	handler.HandleMessage(createCBORPacket(cid, emptyPayload))

	responses := collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	// Empty payload should result in CTAPHID error (invalid length)
	if responses[0][4] != CTAPHIDError {
		t.Errorf("expected ERROR response (0x%02X), got 0x%02X", CTAPHIDError, responses[0][4])
	}

	errCode := responses[0][7]
	if errCode != CTAPHIDErrInvalidLen {
		t.Errorf("expected invalid length error (0x%02X), got 0x%02X", CTAPHIDErrInvalidLen, errCode)
	}
}

// TestProcessCBORCommandLocked_AllCTAPCommands tests processCBORCommandLocked
// with all defined CTAP command types.
func TestProcessCBORCommandLocked_AllCTAPCommands(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		cmd           byte
		payload       []byte
		expectSuccess bool
	}{
		{
			name:          "GetInfo",
			cmd:           CmdGetInfo,
			payload:       nil,
			expectSuccess: true,
		},
		{
			name:          "Selection",
			cmd:           CmdSelection,
			payload:       nil,
			expectSuccess: true,
		},
		{
			name:          "Reset_returns_response",
			cmd:           CmdReset,
			payload:       nil,
			expectSuccess: false, // May succeed or fail based on user presence
		},
		{
			name:          "ClientPIN_returns_response",
			cmd:           CmdClientPIN,
			payload:       nil,
			expectSuccess: false, // Missing params
		},
		{
			name:          "GetNextAssertion_no_pending",
			cmd:           CmdGetNextAssertion,
			payload:       nil,
			expectSuccess: false,
		},
		{
			name:          "CredentialManagement_returns_response",
			cmd:           CmdCredentialManagement,
			payload:       nil,
			expectSuccess: false, // Missing params
		},
		{
			name:          "Config_returns_response",
			cmd:           CmdConfig,
			payload:       nil,
			expectSuccess: false, // Missing params
		},
		{
			name:          "LargeBlobs_returns_response",
			cmd:           CmdLargeBlobs,
			payload:       nil,
			expectSuccess: false, // Missing params
		},
		{
			name:          "BioEnrollment_not_supported",
			cmd:           CmdBioEnrollment,
			payload:       nil,
			expectSuccess: false,
		},
		{
			name:          "InvalidCommand_0xFE",
			cmd:           0xFE,
			payload:       nil,
			expectSuccess: false,
		},
		{
			name:          "InvalidCommand_0x00",
			cmd:           0x00,
			payload:       nil,
			expectSuccess: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, collector := createTestHandler(t)
			defer handler.Close()

			cid := initializeChannel(t, handler, collector)

			// Build payload with command byte
			payload := []byte{tc.cmd}
			if tc.payload != nil {
				payload = append(payload, tc.payload...)
			}

			handler.HandleMessage(createCBORPacket(cid, payload))

			responses := collector.getResponses()
			if len(responses) < 1 {
				t.Fatal("expected at least 1 response")
			}

			// Find CBOR response (skip keepalives if any)
			var cborResp []byte
			for _, resp := range responses {
				if resp[4] == CTAPHIDCBOR {
					cborResp = resp
					break
				}
			}
			if cborResp == nil {
				t.Fatal("expected CBOR response")
			}

			status := cborResp[7]
			if tc.expectSuccess && status != StatusOK {
				t.Errorf("expected StatusOK, got 0x%02X", status)
			}
			if !tc.expectSuccess && status == StatusOK {
				// This is acceptable - some commands may succeed in certain conditions
				t.Logf("command succeeded unexpectedly with StatusOK")
			}
		})
	}
}

// TestProcessCBORCommandLocked_MakeCredentialInvalidCBOR tests processCBORCommandLocked
// with malformed CBOR data for MakeCredential.
func TestProcessCBORCommandLocked_MakeCredentialInvalidCBOR(t *testing.T) {
	t.Parallel()

	handler, collector := createTestHandler(t)
	defer handler.Close()

	cid := initializeChannel(t, handler, collector)

	// Send MakeCredential with invalid CBOR data
	invalidCBOR := []byte{CmdMakeCredential, 0xFF, 0xFF, 0xFF} // Invalid CBOR
	handler.HandleMessage(createCBORPacket(cid, invalidCBOR))

	// Wait for keepalives to finish
	time.Sleep(200 * time.Millisecond)

	responses := collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected at least 1 response")
	}

	// Find CBOR response
	var cborResp []byte
	for _, resp := range responses {
		if resp[4] == CTAPHIDCBOR {
			cborResp = resp
			break
		}
	}
	if cborResp == nil {
		t.Fatal("expected CBOR response")
	}

	status := cborResp[7]
	// Invalid CBOR should return an error status (not StatusOK)
	if status == StatusOK {
		t.Errorf("expected error status for invalid CBOR, got StatusOK")
	}
}

// TestProcessCBORCommandLocked_GetAssertionInvalidCBOR tests processCBORCommandLocked
// with malformed CBOR data for GetAssertion.
func TestProcessCBORCommandLocked_GetAssertionInvalidCBOR(t *testing.T) {
	t.Parallel()

	handler, collector := createTestHandler(t)
	defer handler.Close()

	cid := initializeChannel(t, handler, collector)

	// Send GetAssertion with invalid CBOR data
	invalidCBOR := []byte{CmdGetAssertion, 0xFF, 0xFF, 0xFF} // Invalid CBOR
	handler.HandleMessage(createCBORPacket(cid, invalidCBOR))

	// Wait for keepalives to finish
	time.Sleep(200 * time.Millisecond)

	responses := collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected at least 1 response")
	}

	// Find CBOR response
	var cborResp []byte
	for _, resp := range responses {
		if resp[4] == CTAPHIDCBOR {
			cborResp = resp
			break
		}
	}
	if cborResp == nil {
		t.Fatal("expected CBOR response")
	}

	status := cborResp[7]
	// Invalid CBOR should return an error status (not StatusOK)
	if status == StatusOK {
		t.Errorf("expected error status for invalid CBOR, got StatusOK")
	}
}

// TestProcessCBORCommandLocked_ClientPINSubcommands tests processCBORCommandLocked
// with various ClientPIN subcommands.
func TestProcessCBORCommandLocked_ClientPINSubcommands(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		subCommand  int
		pinProtocol int
		expectError bool
	}{
		{
			name:        "GetPINRetries",
			subCommand:  0x01, // getPINRetries
			pinProtocol: 1,
			expectError: false,
		},
		{
			name:        "GetKeyAgreement",
			subCommand:  0x02, // getKeyAgreement
			pinProtocol: 1,
			expectError: false,
		},
		{
			name:        "InvalidSubcommand",
			subCommand:  0xFF,
			pinProtocol: 1,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, collector := createTestHandler(t)
			defer handler.Close()

			cid := initializeChannel(t, handler, collector)

			// Build ClientPIN request
			request := map[int]interface{}{
				0x01: tc.pinProtocol, // pinUvAuthProtocol
				0x02: tc.subCommand,  // subCommand
			}
			data, err := cbor.Marshal(request)
			if err != nil {
				t.Fatalf("failed to marshal CBOR: %v", err)
			}

			payload := append([]byte{CmdClientPIN}, data...)
			handler.HandleMessage(createCBORPacket(cid, payload))

			responses := collector.getResponses()
			if len(responses) < 1 {
				t.Fatal("expected at least 1 response")
			}

			// Find CBOR response
			var cborResp []byte
			for _, resp := range responses {
				if resp[4] == CTAPHIDCBOR {
					cborResp = resp
					break
				}
			}
			if cborResp == nil {
				t.Fatal("expected CBOR response")
			}

			status := cborResp[7]
			if tc.expectError && status == StatusOK {
				t.Errorf("expected error status, got StatusOK")
			}
			if !tc.expectError && status != StatusOK {
				t.Errorf("expected StatusOK, got 0x%02X", status)
			}
		})
	}
}

// TestProcessCBORCommandLocked_WithLogger tests processCBORCommandLocked
// with logger enabled to verify logging code paths.
func TestProcessCBORCommandLocked_WithLogger(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	handler := NewCTAPHIDHandler(auth)
	defer handler.Close()

	collector := newTestResponseCollector()
	handler.SetResponseHandler(collector.handler)

	// Set a logger to exercise logging code paths
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler.SetLogger(logger)

	cid := initializeChannel(t, handler, collector)

	// Test successful command with logger
	handler.HandleMessage(createCBORPacket(cid, []byte{CmdGetInfo}))

	responses := collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected at least 1 response")
	}

	// Find CBOR response
	var cborResp []byte
	for _, resp := range responses {
		if resp[4] == CTAPHIDCBOR {
			cborResp = resp
			break
		}
	}
	if cborResp == nil {
		t.Fatal("expected CBOR response")
	}

	if cborResp[7] != StatusOK {
		t.Errorf("expected StatusOK, got 0x%02X", cborResp[7])
	}
}

// TestProcessCBORCommandLocked_WithLoggerErrorPath tests processCBORCommandLocked
// error logging code paths.
func TestProcessCBORCommandLocked_WithLoggerErrorPath(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	handler := NewCTAPHIDHandler(auth)
	defer handler.Close()

	collector := newTestResponseCollector()
	handler.SetResponseHandler(collector.handler)

	// Set a logger to exercise error logging code paths
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler.SetLogger(logger)

	cid := initializeChannel(t, handler, collector)

	// Send an invalid command to trigger error logging
	handler.HandleMessage(createCBORPacket(cid, []byte{0xFE}))

	responses := collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected at least 1 response")
	}

	// Find CBOR response
	var cborResp []byte
	for _, resp := range responses {
		if resp[4] == CTAPHIDCBOR {
			cborResp = resp
			break
		}
	}
	if cborResp == nil {
		t.Fatal("expected CBOR response")
	}

	if cborResp[7] != StatusInvalidCommand {
		t.Errorf("expected StatusInvalidCommand (0x%02X), got 0x%02X", StatusInvalidCommand, cborResp[7])
	}
}

// TestProcessCBORCommandLocked_KeepaliveForGetAssertion tests that keepalives
// are sent during GetAssertion command (like MakeCredential).
func TestProcessCBORCommandLocked_KeepaliveForGetAssertion(t *testing.T) {
	t.Parallel()

	// Create handler with delayed user presence
	handler, collector := createTestHandlerWithDelay(t, 300*time.Millisecond)
	defer handler.Close()

	cid := initializeChannel(t, handler, collector)

	// First, create a discoverable credential to assert. Must use rk:true
	// so that GetAssertion without allowList finds it (and skips the
	// no-credentials deferral path).
	clientDataHash := make([]byte, 32)
	for i := range clientDataHash {
		clientDataHash[i] = byte(i)
	}
	mcRequest := map[int]interface{}{
		0x01: clientDataHash,
		0x02: map[string]interface{}{"id": "test.example.com", "name": "Test RP"},
		0x03: map[string]interface{}{"id": []byte{0x01, 0x02, 0x03}, "name": "testuser"},
		0x04: []map[string]interface{}{{"type": "public-key", "alg": -7}},
		0x07: map[string]bool{"rk": true}, // discoverable credential
	}
	mcData, err := cbor.Marshal(mcRequest)
	require.NoError(t, err)
	mcPayload := append([]byte{CmdMakeCredential}, mcData...)
	sendMultiPacketCBOR(handler, cid, mcPayload)
	time.Sleep(500 * time.Millisecond)
	collector.clear()

	// Build GetAssertion request
	gaClientDataHash := make([]byte, 32)
	for i := range gaClientDataHash {
		gaClientDataHash[i] = byte(i + 32)
	}

	gaRequest := map[int]interface{}{
		0x01: "test.example.com", // rpId
		0x02: gaClientDataHash,   // clientDataHash
	}

	data, err := cbor.Marshal(gaRequest)
	require.NoError(t, err)

	gaPayload := append([]byte{CmdGetAssertion}, data...)
	sendMultiPacketCBOR(handler, cid, gaPayload)

	// Wait for response
	time.Sleep(500 * time.Millisecond)

	responses := collector.getResponses()

	// Count keepalives — should get UpNeeded keepalives during user presence.
	keepaliveCount := 0
	for _, resp := range responses {
		if resp[4] == CTAPHIDKeepalive {
			keepaliveCount++
		}
	}

	require.Greater(t, keepaliveCount, 0, "expected keepalives during GetAssertion with matching credential")
}

// TestProcessCBORCommandLocked_CommandDataExtraction tests that command data
// is correctly extracted from payload (payload[1:] when len > 1).
func TestProcessCBORCommandLocked_CommandDataExtraction(t *testing.T) {
	t.Parallel()

	handler, collector := createTestHandler(t)
	defer handler.Close()

	cid := initializeChannel(t, handler, collector)

	// Send GetInfo with extra data (should be ignored by GetInfo)
	payload := []byte{CmdGetInfo, 0xA0} // 0xA0 is empty CBOR map
	handler.HandleMessage(createCBORPacket(cid, payload))

	responses := collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected at least 1 response")
	}

	// Find CBOR response
	var cborResp []byte
	for _, resp := range responses {
		if resp[4] == CTAPHIDCBOR {
			cborResp = resp
			break
		}
	}
	if cborResp == nil {
		t.Fatal("expected CBOR response")
	}

	// GetInfo should succeed even with extra data
	if cborResp[7] != StatusOK {
		t.Errorf("expected StatusOK, got 0x%02X", cborResp[7])
	}
}

// TestProcessCBORCommandLocked_SingleBytePayload tests processCBORCommandLocked
// with exactly one byte payload (command only, no data).
func TestProcessCBORCommandLocked_SingleBytePayload(t *testing.T) {
	t.Parallel()

	handler, collector := createTestHandler(t)
	defer handler.Close()

	cid := initializeChannel(t, handler, collector)

	// Single byte payload = command byte only
	payload := []byte{CmdGetInfo}
	handler.HandleMessage(createCBORPacket(cid, payload))

	responses := collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected at least 1 response")
	}

	// Find CBOR response
	var cborResp []byte
	for _, resp := range responses {
		if resp[4] == CTAPHIDCBOR {
			cborResp = resp
			break
		}
	}
	if cborResp == nil {
		t.Fatal("expected CBOR response")
	}

	if cborResp[7] != StatusOK {
		t.Errorf("expected StatusOK, got 0x%02X", cborResp[7])
	}
}

// TestProcessCBORCommandLocked_CBORBroadcastChannel tests that CBOR commands
// on broadcast channel are rejected.
func TestProcessCBORCommandLocked_CBORBroadcastChannel(t *testing.T) {
	t.Parallel()

	handler, collector := createTestHandler(t)
	defer handler.Close()

	// Send CBOR directly to broadcast channel (without INIT first)
	payload := []byte{CmdGetInfo}
	handler.HandleMessage(createCBORPacket(CIDBroadcast, payload))

	responses := collector.getResponses()
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	// Should get invalid channel error
	if responses[0][4] != CTAPHIDError {
		t.Errorf("expected ERROR response, got 0x%02X", responses[0][4])
	}

	errCode := responses[0][7]
	if errCode != CTAPHIDErrInvalidChannel {
		t.Errorf("expected invalid channel error (0x%02X), got 0x%02X", CTAPHIDErrInvalidChannel, errCode)
	}
}

// TestProcessCBORCommandLocked_ResponseEncoding tests that CBOR responses
// are properly encoded in HID packets.
func TestProcessCBORCommandLocked_ResponseEncoding(t *testing.T) {
	t.Parallel()

	handler, collector := createTestHandler(t)
	defer handler.Close()

	cid := initializeChannel(t, handler, collector)

	// Send GetInfo command
	handler.HandleMessage(createCBORPacket(cid, []byte{CmdGetInfo}))

	responses := collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected at least 1 response")
	}

	// Verify response structure
	firstPacket := responses[0]

	// Check CID
	respCID := binary.BigEndian.Uint32(firstPacket[0:4])
	if respCID != cid {
		t.Errorf("response CID = 0x%08X, want 0x%08X", respCID, cid)
	}

	// Check command byte
	if firstPacket[4] != CTAPHIDCBOR {
		t.Errorf("response CMD = 0x%02X, want CTAPHIDCBOR (0x%02X)", firstPacket[4], CTAPHIDCBOR)
	}

	// Check payload length
	payloadLen := binary.BigEndian.Uint16(firstPacket[5:7])
	if payloadLen == 0 {
		t.Error("response payload length should not be zero")
	}

	// Check status byte (first byte of payload)
	if firstPacket[7] != StatusOK {
		t.Errorf("response status = 0x%02X, want StatusOK (0x%02X)", firstPacket[7], StatusOK)
	}

	// If multi-packet response, verify continuation packets
	if int(payloadLen) > InitPacketPayloadSize && len(responses) > 1 {
		for i := 1; i < len(responses); i++ {
			contPacket := responses[i]
			contCID := binary.BigEndian.Uint32(contPacket[0:4])
			if contCID != cid {
				t.Errorf("continuation packet %d CID = 0x%08X, want 0x%08X", i, contCID, cid)
			}

			// Continuation packets have sequence number in byte 4
			expectedSeq := byte(i - 1)
			if contPacket[4] != expectedSeq {
				t.Errorf("continuation packet %d seq = %d, want %d", i, contPacket[4], expectedSeq)
			}
		}
	}
}

// TestProcessCBORCommandLocked_LargeResponse tests that large CBOR responses
// are properly fragmented into multiple HID packets.
func TestProcessCBORCommandLocked_LargeResponse(t *testing.T) {
	t.Parallel()

	handler, collector := createTestHandler(t)
	defer handler.Close()

	cid := initializeChannel(t, handler, collector)

	// GetInfo typically returns > 57 bytes, triggering multi-packet response
	handler.HandleMessage(createCBORPacket(cid, []byte{CmdGetInfo}))

	responses := collector.getResponses()
	if len(responses) < 1 {
		t.Fatal("expected at least 1 response")
	}

	// Get total payload length from first packet
	payloadLen := int(binary.BigEndian.Uint16(responses[0][5:7]))

	if payloadLen > InitPacketPayloadSize {
		// Calculate expected number of continuation packets
		remainingBytes := payloadLen - InitPacketPayloadSize
		expectedContPackets := (remainingBytes + ContPacketPayloadSize - 1) / ContPacketPayloadSize
		expectedTotalPackets := 1 + expectedContPackets

		if len(responses) != expectedTotalPackets {
			t.Errorf("expected %d packets for %d byte payload, got %d",
				expectedTotalPackets, payloadLen, len(responses))
		}

		// Reassemble and verify CBOR structure
		var fullPayload []byte
		fullPayload = append(fullPayload, responses[0][7:]...)
		for i := 1; i < len(responses); i++ {
			fullPayload = append(fullPayload, responses[i][5:]...)
		}
		fullPayload = fullPayload[:payloadLen]

		// First byte should be status
		if fullPayload[0] != StatusOK {
			t.Errorf("status = 0x%02X, want StatusOK", fullPayload[0])
		}

		// Remaining bytes should be valid CBOR
		var decoded map[int]interface{}
		if err := cbor.Unmarshal(fullPayload[1:], &decoded); err != nil {
			t.Errorf("failed to decode CBOR response: %v", err)
		}
	}
}

// TestProcessCBORCommandLocked_ConcurrentRequests tests processCBORCommandLocked
// behavior with concurrent requests on different channels.
func TestProcessCBORCommandLocked_ConcurrentRequests(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	handler := NewCTAPHIDHandler(auth)
	defer handler.Close()

	collector := newTestResponseCollector()
	handler.SetResponseHandler(collector.handler)

	// Initialize multiple channels
	var cids []uint32
	for i := 0; i < 3; i++ {
		nonce := []byte{byte(i), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		handler.HandleMessage(createInitPacket(CIDBroadcast, nonce))
	}

	responses := collector.getResponses()
	for _, resp := range responses {
		if resp[4] == CTAPHIDInit {
			_, cid := parseInitResponse(t, resp)
			cids = append(cids, cid)
		}
	}
	collector.clear()

	if len(cids) < 3 {
		t.Fatalf("expected 3 channels, got %d", len(cids))
	}

	// Send concurrent GetInfo requests
	var wg sync.WaitGroup
	for _, cid := range cids {
		wg.Add(1)
		go func(c uint32) {
			defer wg.Done()
			handler.HandleMessage(createCBORPacket(c, []byte{CmdGetInfo}))
		}(cid)
	}
	wg.Wait()

	// All requests should succeed
	time.Sleep(100 * time.Millisecond)
	responses = collector.getResponses()

	successCount := 0
	for _, resp := range responses {
		if resp[4] == CTAPHIDCBOR && resp[7] == StatusOK {
			successCount++
		}
	}

	if successCount < 3 {
		t.Errorf("expected at least 3 successful responses, got %d", successCount)
	}
}

// TestProcessCBORCommandLocked_MakeCredentialMissingParams tests MakeCredential
// with missing required parameters.
func TestProcessCBORCommandLocked_MakeCredentialMissingParams(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		request map[int]interface{}
	}{
		{
			name:    "MissingClientDataHash",
			request: map[int]interface{}{0x02: map[string]interface{}{"id": "test.com"}},
		},
		{
			name:    "MissingRP",
			request: map[int]interface{}{0x01: make([]byte, 32)},
		},
		{
			name:    "EmptyMap",
			request: map[int]interface{}{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, collector := createTestHandler(t)
			defer handler.Close()

			cid := initializeChannel(t, handler, collector)

			data, err := cbor.Marshal(tc.request)
			if err != nil {
				t.Fatalf("failed to marshal CBOR: %v", err)
			}

			payload := append([]byte{CmdMakeCredential}, data...)
			handler.HandleMessage(createCBORPacket(cid, payload))

			// Wait for keepalives to finish
			time.Sleep(200 * time.Millisecond)

			responses := collector.getResponses()

			// Find CBOR response
			var cborResp []byte
			for _, resp := range responses {
				if resp[4] == CTAPHIDCBOR {
					cborResp = resp
					break
				}
			}
			if cborResp == nil {
				t.Fatal("expected CBOR response")
			}

			// Should return an error (MissingParameter or InvalidParameter)
			status := cborResp[7]
			if status == StatusOK {
				t.Error("expected error status for missing parameters")
			}
		})
	}
}

// TestProcessCBORCommandLocked_GetAssertionMissingParams tests GetAssertion
// with missing required parameters.
func TestProcessCBORCommandLocked_GetAssertionMissingParams(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		request map[int]interface{}
	}{
		{
			name:    "MissingRPID",
			request: map[int]interface{}{0x02: make([]byte, 32)},
		},
		{
			name:    "MissingClientDataHash",
			request: map[int]interface{}{0x01: "test.com"},
		},
		{
			name:    "EmptyMap",
			request: map[int]interface{}{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler, collector := createTestHandler(t)
			defer handler.Close()

			cid := initializeChannel(t, handler, collector)

			data, err := cbor.Marshal(tc.request)
			if err != nil {
				t.Fatalf("failed to marshal CBOR: %v", err)
			}

			payload := append([]byte{CmdGetAssertion}, data...)
			handler.HandleMessage(createCBORPacket(cid, payload))

			// Wait for keepalives to finish
			time.Sleep(200 * time.Millisecond)

			responses := collector.getResponses()

			// Find CBOR response
			var cborResp []byte
			for _, resp := range responses {
				if resp[4] == CTAPHIDCBOR {
					cborResp = resp
					break
				}
			}
			if cborResp == nil {
				t.Fatal("expected CBOR response")
			}

			// Should return an error
			status := cborResp[7]
			if status == StatusOK {
				t.Error("expected error status for missing parameters")
			}
		})
	}
}

// TestCTAPHIDCancel_AbortsUserPresence verifies the full CTAPHID_CANCEL flow:
// a GetAssertion CBOR command blocks on user presence (via SocketHandler),
// then a CTAPHID_CANCEL message is sent on the same channel, which cancels
// the context and causes the blocked user presence to return context.Canceled.
// The CBOR response should contain StatusKeepaliveCancel (0x2D).
//
// This tests the complete flow:
//  1. CTAPHID_CBOR (GetAssertion) -> processCBORCommandLocked creates
//     cancellable context and stores cancel func in h.cancelCBOR
//  2. Authenticator.ProcessCBORWithContext -> handleGetAssertion ->
//     requestUserPresence -> SocketHandler blocks on ctx
//  3. CTAPHID_CANCEL -> handleCancel() calls h.cancelCBOR() -> ctx cancelled
//  4. SocketHandler returns ctx.Err() = context.Canceled
//  5. handleGetAssertion returns context.Canceled
//  6. errorToStatus maps context.Canceled to StatusKeepaliveCancel (0x2D)
//  7. CBOR response sent with status 0x2D
func TestCTAPHIDCancel_AbortsUserPresence(t *testing.T) {
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.RequireUserPresence = true

	// Use SocketHandler as UP handler: it blocks until approved, denied,
	// timed out, or context cancelled.
	socketHandler := NewSocketHandler(nil, nil)
	config.UserPresenceHandler = socketHandler

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer func() { _ = auth.Close() }()

	rpID := "example.com"

	// Register a credential directly via storage.
	cred := createAssertionTestCredential(t, auth, rpID, false)

	// Set a PIN so the authenticator is in a realistic state.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)

	// Create the CTAPHID handler and initialize a channel.
	hidHandler := NewCTAPHIDHandler(auth)
	defer func() { _ = hidHandler.Close() }()

	collector := newTestResponseCollector()
	hidHandler.SetResponseHandler(collector.handler)

	cid := initializeChannel(t, hidHandler, collector)

	// Build GetAssertion CBOR payload with uv=false so the regular UP path
	// is taken (not the intent check path which wraps errors to OperationDenied).
	clientDataHash := generateTestClientDataHash()
	gaRequest := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash,
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamOptions: map[string]bool{"up": true, "uv": false},
	}

	gaData, err := cbor.Marshal(gaRequest)
	if err != nil {
		t.Fatalf("failed to marshal GetAssertion CBOR: %v", err)
	}

	gaPayload := append([]byte{CmdGetAssertion}, gaData...)

	// Send the GetAssertion CBOR command in a goroutine because
	// HandleMessage -> processCBORCommandLocked blocks synchronously
	// while waiting for user presence. We need the main goroutine free
	// to send the CANCEL message.
	cborDone := make(chan struct{})
	go func() {
		defer close(cborDone)
		sendMultiPacketCBOR(hidHandler, cid, gaPayload)
	}()

	// Poll until the SocketHandler has a pending UP request, confirming
	// the authenticator is blocked waiting for user presence.
	deadline := time.After(5 * time.Second)
	for !socketHandler.HasPending() {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for user presence to become pending")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Send CTAPHID_CANCEL to abort the blocking user presence request.
	cancelPkt := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(cancelPkt[0:4], cid)
	cancelPkt[4] = CTAPHIDCancel
	binary.BigEndian.PutUint16(cancelPkt[5:7], 0)
	hidHandler.HandleMessage(cancelPkt)

	// Wait for the CBOR goroutine to finish (the cancel should unblock it).
	select {
	case <-cborDone:
		// Good, the CBOR processing completed after cancellation.
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for CBOR command to complete after CANCEL")
	}

	// Give a brief moment for the response handler to collect the response.
	time.Sleep(50 * time.Millisecond)

	// Collect all responses and find the CBOR response.
	responses := collector.getResponses()

	var cborResp []byte
	for _, resp := range responses {
		if resp[4] == CTAPHIDCBOR {
			cborResp = resp
			break
		}
	}
	if cborResp == nil {
		t.Fatal("expected CBOR response after CTAPHID_CANCEL")
	}

	// The CBOR response status byte (first byte of payload) should be
	// StatusKeepaliveCancel (0x2D), indicating the operation was cancelled.
	status := cborResp[7]
	if status != StatusKeepaliveCancel {
		t.Errorf("expected StatusKeepaliveCancel (0x%02X), got 0x%02X",
			StatusKeepaliveCancel, status)
	}
}

// ---------------------------------------------------------------------------
// Multi-authenticator coexistence: no-credentials deferral tests
// ---------------------------------------------------------------------------

// TestNoCredentialsDeferral_SendsProcessingKeepalives verifies that when
// GetAssertion has no matching credentials, the HID adapter sends
// KeepaliveStatusProcessing (not UpNeeded) and waits for CANCEL.
// This keeps Chrome from showing a "touch" prompt for xkey while letting
// the YubiKey's UpNeeded keepalives win.
func TestNoCredentialsDeferral_SendsProcessingKeepalives(t *testing.T) {
	t.Parallel()

	handler, collector := createTestHandler(t)
	defer handler.Close()

	cid := initializeChannel(t, handler, collector)

	// Build a GetAssertion with no matching credentials.
	clientDataHash := sha256.Sum256([]byte("test-deferral"))
	params := map[int]interface{}{
		getAssertionParamRPID:           "no-creds.example.com",
		getAssertionParamClientDataHash: clientDataHash[:],
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)

	// Send in a goroutine because the deferral blocks the calling goroutine.
	payload := append([]byte{CmdGetAssertion}, data...)
	done := make(chan struct{})
	go func() {
		sendMultiPacketCBOR(handler, cid, payload)
		close(done)
	}()

	// Wait for some keepalives to accumulate.
	time.Sleep(500 * time.Millisecond)

	// Verify keepalives are Processing, NOT UpNeeded.
	responses := collector.getResponses()
	require.NotEmpty(t, responses, "expected at least one keepalive response")

	var gotProcessingKeepalive bool
	var gotUpNeededKeepalive bool
	for _, resp := range responses {
		if resp[4] == CTAPHIDKeepalive {
			if resp[7] == KeepaliveStatusProcessing {
				gotProcessingKeepalive = true
			}
			if resp[7] == KeepaliveStatusUpNeeded {
				gotUpNeededKeepalive = true
			}
		}
	}
	require.True(t, gotProcessingKeepalive, "expected KeepaliveStatusProcessing during deferral")
	require.False(t, gotUpNeededKeepalive, "should NOT send KeepaliveStatusUpNeeded for no-credentials case")

	// Send CANCEL to end the deferral (simulates Chrome cancelling after
	// another authenticator succeeds).
	cancelPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(cancelPacket[0:4], cid)
	cancelPacket[4] = CTAPHIDCancel
	binary.BigEndian.PutUint16(cancelPacket[5:7], 0)
	handler.HandleMessage(cancelPacket)

	// Wait for deferral goroutine to complete.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("deferral goroutine did not complete after CANCEL")
	}

	// Verify final response is StatusKeepaliveCancel.
	allResponses := collector.getResponses()
	var cborResp []byte
	for _, resp := range allResponses {
		if resp[4] == CTAPHIDCBOR {
			cborResp = resp
			break
		}
	}
	require.NotNil(t, cborResp, "expected final CBOR response after CANCEL")
	require.Equal(t, byte(StatusKeepaliveCancel), cborResp[7],
		"expected StatusKeepaliveCancel after CANCEL")
}

// TestNoCredentialsDeferral_CancelShortCircuits verifies that sending
// CTAPHID_CANCEL during the no-credentials deferral immediately stops
// the wait and returns StatusKeepaliveCancel. This is the path taken
// when a YubiKey handles the assertion and Chrome cancels xkey.
func TestNoCredentialsDeferral_CancelShortCircuits(t *testing.T) {
	t.Parallel()

	handler, collector := createTestHandler(t)
	defer handler.Close()

	cid := initializeChannel(t, handler, collector)

	// Build a GetAssertion with no matching credentials.
	clientDataHash := sha256.Sum256([]byte("test-cancel-deferral"))
	params := map[int]interface{}{
		getAssertionParamRPID:           "no-creds-cancel.example.com",
		getAssertionParamClientDataHash: clientDataHash[:],
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)

	payload := append([]byte{CmdGetAssertion}, data...)

	// Send GetAssertion in a goroutine because the deferral path blocks
	// the calling goroutine (handleContPacket → processCBORCommandLocked
	// waits for CANCEL or timeout while holding the call stack).
	done := make(chan struct{})
	go func() {
		sendMultiPacketCBOR(handler, cid, payload)
		close(done)
	}()

	// Send CANCEL after 200ms (well before the 1s deferral timeout).
	time.Sleep(200 * time.Millisecond)
	cancelPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(cancelPacket[0:4], cid)
	cancelPacket[4] = CTAPHIDCancel
	binary.BigEndian.PutUint16(cancelPacket[5:7], 0)
	handler.HandleMessage(cancelPacket)

	// Wait for the deferral goroutine to complete.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("deferral goroutine did not complete after CANCEL")
	}

	responses := collector.getResponses()

	// Find the CBOR response.
	var cborResp []byte
	for _, resp := range responses {
		if resp[4] == CTAPHIDCBOR {
			cborResp = resp
			break
		}
	}

	require.NotNil(t, cborResp, "expected CBOR response after CANCEL")
	require.Equal(t, byte(StatusKeepaliveCancel), cborResp[7],
		"expected StatusKeepaliveCancel after CANCEL during deferral")
}

// TestNoCredentialsDeferral_WithCredentials_SkipsDeferral verifies that
// GetAssertion WITH matching credentials does NOT use the deferral path.
// It should go through the normal processing pipeline with UpNeeded keepalives.
func TestNoCredentialsDeferral_WithCredentials_SkipsDeferral(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = false
	config.UserPresenceHandler = NewAutoGrantHandler()

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)

	// Store a credential so HasMatchingCredentials returns true.
	rpID := "has-creds.example.com"
	cred := createAssertionTestCredential(t, auth, rpID, true)

	handler := NewCTAPHIDHandler(auth)
	collector := newTestResponseCollector()
	handler.SetResponseHandler(collector.handler)

	cid := initializeChannel(t, handler, collector)

	// Build a GetAssertion WITH matching credentials.
	clientDataHash := sha256.Sum256([]byte("test-with-creds"))
	params := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash[:],
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)

	payload := append([]byte{CmdGetAssertion}, data...)
	start := time.Now()
	sendMultiPacketCBOR(handler, cid, payload)

	// Wait for the response (should be fast, no deferral).
	time.Sleep(500 * time.Millisecond)
	elapsed := time.Since(start)

	responses := collector.getResponses()

	// Find CBOR response — should be StatusOK.
	var cborResp []byte
	for _, resp := range responses {
		if resp[4] == CTAPHIDCBOR {
			cborResp = resp
			break
		}
	}

	require.NotNil(t, cborResp, "expected CBOR response for assertion with credentials")
	require.Equal(t, byte(StatusOK), cborResp[7], "expected StatusOK for assertion with matching credentials")

	// Should complete well before any deferral — under 5 seconds.
	require.Less(t, elapsed, 5*time.Second,
		"assertion with credentials should not use deferral path")
}

func TestIsU2FAppID(t *testing.T) {
	tests := []struct {
		name string
		rpid string
		want bool
	}{
		{"U2F AWS app-id", "https://u2f.aws.amazon.com/app-id.json", true},
		{"U2F generic HTTPS", "https://example.com/appid", true},
		{"FIDO2 bare domain", "aws.amazon.com", false},
		{"FIDO2 Okta domain", "integrator-4432440.okta.com", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isU2FAppID(tt.rpid)
			if got != tt.want {
				t.Errorf("isU2FAppID(%q) = %v, want %v", tt.rpid, got, tt.want)
			}
		})
	}
}

// TestCTAPHIDHandler_KeepaliveProcessingWhenPINRequired_GetAssertion verifies
// that when PIN is enabled and set, and a GetAssertion request does NOT carry
// pinUvAuthParam, the keepalive status is KeepaliveStatusProcessing (not
// UpNeeded). This prevents Chrome from showing "Touch your security key"
// before PIN entry, matching the MakeCredential behavior.
func TestCTAPHIDHandler_KeepaliveProcessingWhenPINRequired_GetAssertion(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	config.EnablePIN = true
	config.EnableHMACSecret = false
	config.EnableResidentKey = true
	// Use a delayed approve handler so keepalives have time to be sent.
	config.UserPresenceHandler = &delayedApproveHandler{delay: 500 * time.Millisecond}

	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer func() { _ = auth.Close() }()

	rpID := "keepalive-ga.example.com"

	// Register a credential so HasMatchingCredentials returns true.
	cred := createAssertionTestCredential(t, auth, rpID, false)

	// Set a PIN so NeedsPINBeforeTouch returns true.
	rawPIN := "123456"
	fullHash := sha256.Sum256([]byte(rawPIN))
	pinHash := fullHash[:PINHashSize]
	auth.SyncPINHash(pinHash)

	handler := NewCTAPHIDHandler(auth)
	defer func() { _ = handler.Close() }()

	collector := newTestResponseCollector()
	handler.SetResponseHandler(collector.handler)

	cid := initializeChannel(t, handler, collector)

	// Build GetAssertion CBOR WITHOUT pinUvAuthParam -- Chrome's first
	// attempt before it knows PIN is needed.
	clientDataHash := sha256.Sum256([]byte("keepalive-getassertion-test"))
	gaRequest := map[int]interface{}{
		getAssertionParamRPID:           rpID,
		getAssertionParamClientDataHash: clientDataHash[:],
		getAssertionParamAllowList: []interface{}{
			map[string]interface{}{
				"type": "public-key",
				"id":   cred.CredentialID,
			},
		},
		getAssertionParamOptions: map[string]bool{"up": true, "uv": false},
	}

	gaData, err := cbor.Marshal(gaRequest)
	if err != nil {
		t.Fatalf("failed to marshal GetAssertion CBOR: %v", err)
	}

	gaPayload := append([]byte{CmdGetAssertion}, gaData...)
	sendMultiPacketCBOR(handler, cid, gaPayload)

	time.Sleep(800 * time.Millisecond)
	responses := collector.getResponses()

	gotProcessing := false
	gotUpNeeded := false
	for _, resp := range responses {
		if resp[4] == CTAPHIDKeepalive {
			switch resp[7] {
			case KeepaliveStatusProcessing:
				gotProcessing = true
			case KeepaliveStatusUpNeeded:
				gotUpNeeded = true
			}
		}
	}

	if !gotProcessing {
		t.Error("expected KeepaliveStatusProcessing when PIN is required but not yet provided")
	}
	if gotUpNeeded {
		t.Error("should NOT send KeepaliveStatusUpNeeded when PIN is required but not yet provided")
	}
}
