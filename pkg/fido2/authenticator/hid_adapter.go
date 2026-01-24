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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

// CTAP-HID protocol constants as defined in FIDO2 specification.
const (
	// HIDPacketSize is the standard HID report size.
	HIDPacketSize = 64

	// InitPacketPayloadSize is the max payload in an initialization packet (64 - 7).
	InitPacketPayloadSize = 57

	// ContPacketPayloadSize is the max payload in a continuation packet (64 - 5).
	ContPacketPayloadSize = 59

	// InitNonceSize is the size of the nonce in CTAPHID_INIT.
	InitNonceSize = 8

	// CIDBroadcast is the broadcast channel ID used for INIT.
	CIDBroadcast = 0xFFFFFFFF
)

// CTAP-HID command codes.
const (
	CTAPHIDPing      = 0x01 | 0x80
	CTAPHIDU2F       = 0x03 | 0x80 // U2F/CTAP1 message
	CTAPHIDInit      = 0x06 | 0x80
	CTAPHIDWink      = 0x08 | 0x80
	CTAPHIDCBOR      = 0x10 | 0x80 // CTAP2 CBOR command
	CTAPHIDCancel    = 0x11 | 0x80
	CTAPHIDKeepalive = 0x3B | 0x80
	CTAPHIDError     = 0x3F | 0x80
)

// CTAP-HID error codes.
const (
	CTAPHIDErrNone           = 0x00
	CTAPHIDErrInvalidCmd     = 0x01
	CTAPHIDErrInvalidPar     = 0x02
	CTAPHIDErrInvalidLen     = 0x03
	CTAPHIDErrInvalidSeq     = 0x04
	CTAPHIDErrMsgTimeout     = 0x05
	CTAPHIDErrChannelBusy    = 0x06
	CTAPHIDErrLockRequired   = 0x0A
	CTAPHIDErrInvalidChannel = 0x0B
	CTAPHIDErrOther          = 0x7F
)

// CTAPHID protocol version information included in INIT response.
const (
	CTAPHIDProtocolVersion = 2
	CTAPHIDMajorVersion    = 1
	CTAPHIDMinorVersion    = 0
	CTAPHIDBuildVersion    = 0
)

// debugHID enables debug logging for HID adapter.
// Set VFIDO2_DEBUG=1 environment variable to enable.
var debugHID = os.Getenv("VFIDO2_DEBUG") == "1"

// debugHIDLog prints debug messages for HID adapter if debugging is enabled.
func debugHIDLog(format string, args ...interface{}) {
	if debugHID {
		fmt.Printf("[HID DEBUG] "+format+"\n", args...)
	}
}

// CTAPHIDHandler errors.
var (
	// ErrInvalidPacketSize indicates the HID packet is not 64 bytes.
	ErrInvalidPacketSize = errors.New("ctaphid: invalid packet size")

	// ErrInvalidChannelID indicates an unknown or invalid channel ID.
	ErrInvalidChannelID = errors.New("ctaphid: invalid channel ID")

	// ErrInvalidSequence indicates a sequence number mismatch in continuation packet.
	ErrInvalidSequence = errors.New("ctaphid: invalid sequence number")

	// ErrIncompleteMessage indicates the message was not fully received.
	ErrIncompleteMessage = errors.New("ctaphid: incomplete message")

	// ErrNoResponseHandler indicates no response handler has been set.
	ErrNoResponseHandler = errors.New("ctaphid: no response handler set")

	// ErrHandlerClosed indicates the handler has been closed.
	ErrHandlerClosed = errors.New("ctaphid: handler closed")
)

// channelState tracks the state of an active CTAP-HID channel.
type channelState struct {
	cid      uint32
	sequence uint8
	incoming []byte // Buffer for reassembling multi-packet messages
	expected int    // Expected total payload length
	command  byte   // The command being assembled
}

// CTAPHIDHandler handles CTAP-HID protocol framing for the native authenticator.
// It translates HID packets to/from CTAP2 commands and manages channel state.
//
// All methods are safe for concurrent use.
type CTAPHIDHandler struct {
	authenticator   *Authenticator
	channels        map[uint32]*channelState
	nextCID         uint32
	responseHandler func([]byte)
	closed          atomic.Bool
	mu              sync.Mutex
}

// NewCTAPHIDHandler creates a new CTAP-HID handler wrapping an authenticator.
// The authenticator must not be nil.
func NewCTAPHIDHandler(auth *Authenticator) *CTAPHIDHandler {
	return &CTAPHIDHandler{
		authenticator: auth,
		channels:      make(map[uint32]*channelState),
		nextCID:       0x01000000, // Start with a non-trivial CID
	}
}

// SetResponseHandler sets the callback for HID response packets.
// The handler is called with each 64-byte HID packet that should be sent.
// This must be called before processing any messages.
func (h *CTAPHIDHandler) SetResponseHandler(handler func([]byte)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.responseHandler = handler
	debugHIDLog("response handler set: %v", handler != nil)
}

// HandleMessage processes an incoming HID packet.
// The packet must be exactly 64 bytes (HIDPacketSize).
// Responses are delivered via the response handler callback.
func (h *CTAPHIDHandler) HandleMessage(data []byte) {
	if h.closed.Load() {
		debugHIDLog("HandleMessage: handler is closed, ignoring")
		return
	}

	if len(data) < HIDPacketSize {
		debugHIDLog("HandleMessage: invalid packet size %d, expected %d", len(data), HIDPacketSize)
		h.sendError(CIDBroadcast, CTAPHIDErrInvalidLen)
		return
	}

	// Parse channel ID (first 4 bytes)
	cid := binary.BigEndian.Uint32(data[0:4])
	cmdOrSeq := data[4]

	debugHIDLog("HandleMessage: received packet, CID=0x%08x, cmdOrSeq=0x%02x", cid, cmdOrSeq)

	// Check if this is an initialization packet (command byte has high bit set)
	isInitPacket := (cmdOrSeq & 0x80) != 0

	if isInitPacket {
		h.handleInitPacket(cid, cmdOrSeq, data)
	} else {
		h.handleContPacket(cid, cmdOrSeq, data)
	}
}

// Close closes the handler and releases resources.
func (h *CTAPHIDHandler) Close() error {
	if h.closed.Swap(true) {
		return nil // Already closed
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.channels = nil
	h.responseHandler = nil

	return nil
}

// handleInitPacket processes an initialization packet (command with high bit set).
func (h *CTAPHIDHandler) handleInitPacket(cid uint32, cmd byte, data []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Get payload length from bytes 5-6 (big-endian)
	payloadLen := int(binary.BigEndian.Uint16(data[5:7]))

	debugHIDLog("handleInitPacket: CID=0x%08x, cmd=0x%02x, payloadLen=%d", cid, cmd, payloadLen)

	// Extract payload from this packet
	maxPayload := InitPacketPayloadSize
	if payloadLen < maxPayload {
		maxPayload = payloadLen
	}
	payload := make([]byte, maxPayload)
	copy(payload, data[7:7+maxPayload])

	// Handle based on command type
	switch cmd {
	case CTAPHIDInit:
		debugHIDLog("handleInitPacket: CTAPHID_INIT command")
		h.handleInit(cid, payload, payloadLen)

	case CTAPHIDPing:
		debugHIDLog("handleInitPacket: CTAPHID_PING command")
		h.handlePing(cid, payload, payloadLen)

	case CTAPHIDCBOR:
		debugHIDLog("handleInitPacket: CTAPHID_CBOR command")
		h.handleCBOR(cid, payload, payloadLen)

	case CTAPHIDWink:
		debugHIDLog("handleInitPacket: CTAPHID_WINK command")
		h.handleWink(cid)

	case CTAPHIDCancel:
		debugHIDLog("handleInitPacket: CTAPHID_CANCEL command")
		h.handleCancel(cid)

	case CTAPHIDU2F:
		debugHIDLog("handleInitPacket: CTAPHID_U2F command (not supported)")
		// U2F commands are not fully supported in native authenticator
		h.sendErrorLocked(cid, CTAPHIDErrInvalidCmd)

	default:
		debugHIDLog("handleInitPacket: unknown command 0x%02x", cmd)
		h.sendErrorLocked(cid, CTAPHIDErrInvalidCmd)
	}
}

// handleContPacket processes a continuation packet.
func (h *CTAPHIDHandler) handleContPacket(cid uint32, seq byte, data []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()

	debugHIDLog("handleContPacket: CID=0x%08x, seq=%d", cid, seq)

	// Look up channel state
	state, exists := h.channels[cid]
	if !exists {
		debugHIDLog("handleContPacket: channel not found")
		h.sendErrorLocked(cid, CTAPHIDErrInvalidChannel)
		return
	}

	// Verify sequence number
	if seq != state.sequence {
		debugHIDLog("handleContPacket: sequence mismatch, expected %d, got %d", state.sequence, seq)
		delete(h.channels, cid)
		h.sendErrorLocked(cid, CTAPHIDErrInvalidSeq)
		return
	}

	// Calculate how much more data we need
	remaining := state.expected - len(state.incoming)
	if remaining <= 0 {
		// We already have enough data, this is unexpected
		debugHIDLog("handleContPacket: unexpected extra data")
		delete(h.channels, cid)
		h.sendErrorLocked(cid, CTAPHIDErrInvalidLen)
		return
	}

	// Extract payload from continuation packet
	payloadLen := ContPacketPayloadSize
	if remaining < payloadLen {
		payloadLen = remaining
	}
	state.incoming = append(state.incoming, data[5:5+payloadLen]...)
	state.sequence++

	debugHIDLog("handleContPacket: received %d bytes, total %d/%d", payloadLen, len(state.incoming), state.expected)

	// Check if we have the complete message
	if len(state.incoming) >= state.expected {
		debugHIDLog("handleContPacket: message complete, processing")
		// Process the complete message
		cmd := state.command
		payload := state.incoming[:state.expected]
		delete(h.channels, cid)

		// Handle the complete command
		switch cmd {
		case CTAPHIDCBOR:
			h.processCBORCommandLocked(cid, payload)
		case CTAPHIDPing:
			h.sendResponseLocked(cid, CTAPHIDPing, payload)
		default:
			h.sendErrorLocked(cid, CTAPHIDErrInvalidCmd)
		}
	}
}

// handleInit processes CTAPHID_INIT command.
// This allocates a new channel and returns channel info.
func (h *CTAPHIDHandler) handleInit(cid uint32, payload []byte, payloadLen int) {
	// INIT payload must be exactly 8 bytes (nonce)
	if payloadLen != InitNonceSize {
		debugHIDLog("handleInit: invalid payload length %d, expected %d", payloadLen, InitNonceSize)
		h.sendErrorLocked(cid, CTAPHIDErrInvalidLen)
		return
	}

	// Allocate a new channel ID
	newCID := h.nextCID
	h.nextCID++

	// Avoid allocating broadcast CID
	if h.nextCID == CIDBroadcast {
		h.nextCID = 0x01000000
	}

	debugHIDLog("handleInit: allocated new CID=0x%08x", newCID)

	// Create channel state
	h.channels[newCID] = &channelState{
		cid: newCID,
	}

	// Build response: nonce (8) + new CID (4) + protocol version (1) + device version (3) + capabilities (1)
	response := make([]byte, 17)
	copy(response[0:8], payload) // Echo nonce
	binary.BigEndian.PutUint32(response[8:12], newCID)
	response[12] = CTAPHIDProtocolVersion // CTAPHID protocol version
	response[13] = CTAPHIDMajorVersion    // Device major version
	response[14] = CTAPHIDMinorVersion    // Device minor version
	response[15] = CTAPHIDBuildVersion    // Device build version
	response[16] = 0x04                   // Capabilities: CBOR + NMSG (no message)

	h.sendResponseLocked(cid, CTAPHIDInit, response)
}

// handlePing processes CTAPHID_PING command.
// It echoes back the payload.
func (h *CTAPHIDHandler) handlePing(cid uint32, payload []byte, payloadLen int) {
	// Validate channel
	if cid == CIDBroadcast {
		debugHIDLog("handlePing: broadcast CID not allowed")
		h.sendErrorLocked(cid, CTAPHIDErrInvalidChannel)
		return
	}

	// For multi-packet ping, set up reassembly
	if payloadLen > InitPacketPayloadSize {
		debugHIDLog("handlePing: multi-packet ping, setting up reassembly for %d bytes", payloadLen)
		h.channels[cid] = &channelState{
			cid:      cid,
			sequence: 0,
			incoming: payload,
			expected: payloadLen,
			command:  CTAPHIDPing,
		}
		return
	}

	// Single packet ping - echo immediately
	debugHIDLog("handlePing: single packet, echoing %d bytes", payloadLen)
	h.sendResponseLocked(cid, CTAPHIDPing, payload[:payloadLen])
}

// handleCBOR processes CTAPHID_CBOR command start.
func (h *CTAPHIDHandler) handleCBOR(cid uint32, payload []byte, payloadLen int) {
	// Validate channel
	if cid == CIDBroadcast {
		debugHIDLog("handleCBOR: broadcast CID not allowed")
		h.sendErrorLocked(cid, CTAPHIDErrInvalidChannel)
		return
	}

	if _, exists := h.channels[cid]; !exists {
		debugHIDLog("handleCBOR: unknown channel 0x%08x", cid)
		// Unknown channel
		h.sendErrorLocked(cid, CTAPHIDErrInvalidChannel)
		return
	}

	// For multi-packet CBOR, set up reassembly
	if payloadLen > InitPacketPayloadSize {
		debugHIDLog("handleCBOR: multi-packet CBOR, setting up reassembly for %d bytes", payloadLen)
		h.channels[cid] = &channelState{
			cid:      cid,
			sequence: 0,
			incoming: payload,
			expected: payloadLen,
			command:  CTAPHIDCBOR,
		}
		return
	}

	// Single packet CBOR - process immediately
	debugHIDLog("handleCBOR: single packet CBOR, processing %d bytes", payloadLen)
	h.processCBORCommandLocked(cid, payload[:payloadLen])
}

// handleWink processes CTAPHID_WINK command.
func (h *CTAPHIDHandler) handleWink(cid uint32) {
	debugHIDLog("handleWink: acknowledging")
	// Wink is optional; we just acknowledge
	h.sendResponseLocked(cid, CTAPHIDWink, nil)
}

// handleCancel processes CTAPHID_CANCEL command.
func (h *CTAPHIDHandler) handleCancel(cid uint32) {
	debugHIDLog("handleCancel: canceling channel 0x%08x", cid)
	// Cancel any pending operation on this channel
	delete(h.channels, cid)
	// No response is sent for CANCEL
}

// processCBORCommandLocked processes a complete CTAP2 CBOR command.
// Caller must hold h.mu.
func (h *CTAPHIDHandler) processCBORCommandLocked(cid uint32, payload []byte) {
	if len(payload) == 0 {
		debugHIDLog("processCBORCommandLocked: empty payload")
		h.sendErrorLocked(cid, CTAPHIDErrInvalidLen)
		return
	}

	// First byte is the CTAP command
	cmd := payload[0]
	var data []byte
	if len(payload) > 1 {
		data = payload[1:]
	}

	debugHIDLog("processCBORCommandLocked: CTAP command=0x%02x, data length=%d", cmd, len(data))

	// Process through the authenticator (release lock during processing)
	h.mu.Unlock()
	response, err := h.authenticator.ProcessCBOR(cmd, data)
	h.mu.Lock()

	if err != nil {
		debugHIDLog("processCBORCommandLocked: ProcessCBOR error: %v", err)
		debugHIDLog("processCBORCommandLocked: sending error response, length=%d", len(response))
		// The response already contains the status code from ProcessCBOR
		h.sendResponseLocked(cid, CTAPHIDCBOR, response)
		return
	}

	debugHIDLog("processCBORCommandLocked: ProcessCBOR success, response length=%d", len(response))
	if len(response) > 0 {
		debugHIDLog("processCBORCommandLocked: response first byte (status)=0x%02x", response[0])
	}
	h.sendResponseLocked(cid, CTAPHIDCBOR, response)
}

// sendError sends an error response.
func (h *CTAPHIDHandler) sendError(cid uint32, errCode byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sendErrorLocked(cid, errCode)
}

// sendErrorLocked sends an error response (caller must hold h.mu).
func (h *CTAPHIDHandler) sendErrorLocked(cid uint32, errCode byte) {
	debugHIDLog("sendErrorLocked: CID=0x%08x, errCode=0x%02x", cid, errCode)
	h.sendResponseLocked(cid, CTAPHIDError, []byte{errCode})
}

// sendResponseLocked fragments and sends a response (caller must hold h.mu).
func (h *CTAPHIDHandler) sendResponseLocked(cid uint32, cmd byte, data []byte) {
	if h.responseHandler == nil {
		debugHIDLog("sendResponseLocked: no response handler set!")
		return
	}

	debugHIDLog("sendResponseLocked: CID=0x%08x, cmd=0x%02x, data length=%d", cid, cmd, len(data))

	// Critical debug: log the full response data for CBOR commands
	if cmd == CTAPHIDCBOR && len(data) > 0 {
		criticalLog("=== HID RESPONSE DATA (before framing) ===")
		criticalLog("CID: 0x%08x, CMD: 0x%02x, Length: %d", cid, cmd, len(data))
		criticalLog("Full data hex: %x", data)
		criticalLog("=== END HID RESPONSE DATA ===")
	}

	packets := h.createResponsePackets(cid, cmd, data)
	debugHIDLog("sendResponseLocked: created %d packet(s)", len(packets))

	// Critical debug: log each packet being sent and verify reassembly
	if cmd == CTAPHIDCBOR {
		criticalLog("=== HID PACKETS BEING SENT ===")
		for i, packet := range packets {
			criticalLog("Packet %d/%d: %x", i+1, len(packets), packet)
		}

		// Verify by reassembling packets
		reassembled := reassemblePackets(packets)
		if len(reassembled) != len(data) {
			criticalLog("ERROR: Reassembly length mismatch! Original: %d, Reassembled: %d", len(data), len(reassembled))
		} else if hex.EncodeToString(reassembled) != hex.EncodeToString(data) {
			criticalLog("ERROR: Reassembly content mismatch!")
			criticalLog("Original:    %x", data)
			criticalLog("Reassembled: %x", reassembled)
		} else {
			criticalLog("HID packet reassembly verified OK (%d bytes)", len(reassembled))
		}
		criticalLog("=== END HID PACKETS ===")
	}

	for i, packet := range packets {
		debugHIDLog("sendResponseLocked: sending packet %d/%d, first 16 bytes: %s",
			i+1, len(packets), hex.EncodeToString(packet[:16]))
		h.responseHandler(packet)
	}
	debugHIDLog("sendResponseLocked: all packets sent")
}

// createResponsePackets creates HID packets for a response.
func (h *CTAPHIDHandler) createResponsePackets(cid uint32, cmd byte, data []byte) [][]byte {
	var packets [][]byte
	dataLen := len(data)

	// Create initialization packet
	initPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(initPacket[0:4], cid)
	initPacket[4] = cmd
	binary.BigEndian.PutUint16(initPacket[5:7], uint16(dataLen))

	// Copy as much data as fits in init packet
	initPayload := InitPacketPayloadSize
	if dataLen < initPayload {
		initPayload = dataLen
	}
	copy(initPacket[7:], data[:initPayload])
	packets = append(packets, initPacket)

	// If all data fits in init packet, we're done
	if dataLen <= InitPacketPayloadSize {
		return packets
	}

	// Create continuation packets
	remaining := data[InitPacketPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		// Copy as much data as fits
		copyLen := ContPacketPayloadSize
		if len(remaining) < copyLen {
			copyLen = len(remaining)
		}
		copy(contPacket[5:], remaining[:copyLen])

		packets = append(packets, contPacket)
		remaining = remaining[copyLen:]
		seq++

		// Sequence number overflow check (max 0x7F for continuation)
		if seq > 0x7F {
			break
		}
	}

	return packets
}

// Authenticator returns the underlying authenticator.
func (h *CTAPHIDHandler) Authenticator() *Authenticator {
	return h.authenticator
}

// reassemblePackets reassembles HID packets back into original data for verification.
// This is used for debugging to verify the framing is correct.
func reassemblePackets(packets [][]byte) []byte {
	if len(packets) == 0 {
		return nil
	}

	// Parse init packet to get total length
	initPacket := packets[0]
	if len(initPacket) < 7 {
		return nil
	}

	totalLen := int(binary.BigEndian.Uint16(initPacket[5:7]))
	result := make([]byte, 0, totalLen)

	// Extract payload from init packet
	initPayload := InitPacketPayloadSize
	if totalLen < initPayload {
		initPayload = totalLen
	}
	result = append(result, initPacket[7:7+initPayload]...)

	// Extract payload from continuation packets
	for i := 1; i < len(packets); i++ {
		remaining := totalLen - len(result)
		if remaining <= 0 {
			break
		}

		contPayload := ContPacketPayloadSize
		if remaining < contPayload {
			contPayload = remaining
		}
		result = append(result, packets[i][5:5+contPayload]...)
	}

	return result
}
