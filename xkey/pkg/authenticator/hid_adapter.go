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
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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

// CTAPHID keepalive status codes sent in CTAPHID_KEEPALIVE messages.
const (
	// KeepaliveStatusProcessing indicates the authenticator is still processing.
	KeepaliveStatusProcessing = 0x01

	// KeepaliveStatusUpNeeded indicates the authenticator is waiting for user presence.
	KeepaliveStatusUpNeeded = 0x02

	// KeepaliveInterval is the interval between CTAPHID_KEEPALIVE messages.
	KeepaliveInterval = 100 * time.Millisecond
)

// CTAPHID protocol version information included in INIT response.
const (
	CTAPHIDProtocolVersion = 2
	CTAPHIDMajorVersion    = 1
	CTAPHIDMinorVersion    = 0
	CTAPHIDBuildVersion    = 0
)

// noCredentialsSafetyTimeout is the maximum time xkey waits for
// CTAPHID_CANCEL when it has no matching credentials for a GetAssertion
// and the request does NOT contain pinUvAuthParam (i.e., Chrome is still
// in the multi-authenticator selection phase). 5 seconds covers a typical
// user touch on another authenticator while keeping xkey responsive.
//
// When pinUvAuthParam IS present, Chrome has already committed to this
// authenticator (PIN exchange completed), so deferral is skipped entirely.
const noCredentialsSafetyTimeout = 5 * time.Second

// debugHID enables debug logging for HID adapter.
// Set VFIDO2_DEBUG=1 environment variable to enable.
var debugHID = os.Getenv("VFIDO2_DEBUG") == "1"

// debugHIDLog prints debug messages for HID adapter if debugging is enabled.
func debugHIDLog(format string, args ...interface{}) {
	if debugHID {
		fmt.Printf("[HID DEBUG] "+format+"\n", args...)
	}
}

// isU2FAppID returns true when the RP ID looks like a U2F App ID (an HTTPS
// URL) rather than a FIDO2 RP ID (a bare domain). U2F App IDs always contain
// "://" while FIDO2 RP IDs never do. When Chrome sends a GetAssertion with a
// U2F App ID that does not match any stored credentials, responding immediately
// with StatusNoCredentials is correct — Chrome will retry with the real RP ID.
// Deferring with noCredentialsSafetyTimeout is counterproductive here because
// Chrome blocks waiting for the response and never sends CTAPHID_CANCEL.
func isU2FAppID(rpid string) bool {
	return strings.Contains(rpid, "://")
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
	logger          *slog.Logger
	closed          atomic.Bool

	// cancelCBOR cancels the context of the currently-executing CBOR command.
	// Set by processCBORCommandLocked before dispatching, called by handleCancel
	// to abort blocking operations (e.g., user presence prompts) when the host
	// sends CTAPHID_CANCEL.
	cancelCBOR context.CancelFunc

	mu sync.Mutex
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

// SetLogger sets the structured logger for operational logging (keepalives, etc.).
func (h *CTAPHIDHandler) SetLogger(logger *slog.Logger) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logger = logger
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
		if h.logger != nil {
			h.logger.Info("CTAPHID_MSG (U2F): rejected, CTAP2-only device",
				slog.String("cid", fmt.Sprintf("0x%08X", cid)),
				slog.Int("payload_len", payloadLen),
			)
		}
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
		h.channels[cid] = &channelState{cid: cid}
		h.sendErrorLocked(cid, CTAPHIDErrInvalidSeq)
		return
	}

	// Calculate how much more data we need
	remaining := state.expected - len(state.incoming)
	if remaining <= 0 {
		// We already have enough data, this is unexpected
		debugHIDLog("handleContPacket: unexpected extra data")
		h.channels[cid] = &channelState{cid: cid}
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
		h.channels[cid] = &channelState{cid: cid}

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

	if h.logger != nil {
		h.logger.Info("CTAPHID_INIT: channel allocated",
			slog.String("src_cid", fmt.Sprintf("0x%08X", cid)),
			slog.String("new_cid", fmt.Sprintf("0x%08X", newCID)),
		)
	}

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
	response[16] = 0x01 | 0x04 | 0x08     // Capabilities: WINK (0x01) + CBOR (0x04) + NMSG (0x08)

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
// It cancels any in-flight CBOR command (e.g., blocking user presence prompt)
// and resets the channel state. Per the CTAP HID specification, no response
// is sent for CANCEL.
func (h *CTAPHIDHandler) handleCancel(cid uint32) {
	debugHIDLog("handleCancel: canceling channel 0x%08x", cid)

	// Cancel the in-flight CBOR command context. This unblocks any pending
	// user presence request, causing it to return context.Canceled.
	if h.cancelCBOR != nil {
		h.cancelCBOR()
		h.cancelCBOR = nil
	}

	// Reset channel state.
	h.channels[cid] = &channelState{cid: cid}
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

	cmdName := ctapCommandName(cmd)
	debugHIDLog("processCBORCommandLocked: CTAP command=0x%02x (%s), data length=%d", cmd, cmdName, len(data))

	if h.logger != nil {
		h.logger.Info("processing CTAP2 command",
			slog.String("cmd", cmdName),
			slog.String("cmd_hex", fmt.Sprintf("0x%02X", cmd)),
			slog.Int("data_len", len(data)),
		)
	}

	// Create a cancellable context for this CBOR command. CTAPHID_CANCEL
	// calls h.cancelCBOR() to abort blocking operations like user presence.
	ctx, cancel := context.WithCancel(context.Background())
	h.cancelCBOR = cancel

	// Multi-authenticator coexistence: when this authenticator has no
	// matching credentials for a GetAssertion request AND the request
	// does not contain pinUvAuthParam, Chrome may still be in the
	// multi-authenticator selection phase. We must NOT return
	// StatusNoCredentials immediately — Chrome processes the first error
	// it receives and may treat it as terminal for the entire ceremony
	// before other authenticators (e.g., YubiKey) have started their
	// keepalives. Instead, we send KeepaliveStatusProcessing ("I'm working
	// on it" — NOT "touch me") and wait for either:
	//   a) CTAPHID_CANCEL from Chrome (another device handled it), or
	//   b) noCredentialsSafetyTimeout expiry (failsafe).
	//
	// When pinUvAuthParam IS present, Chrome already completed PIN exchange
	// with this authenticator — it's committed to us and won't fall through
	// to another device. Skip deferral and let normal processing return
	// StatusNoCredentials immediately.
	hasMatch, parseable, hasPINAuth, assertionRPID := h.authenticator.HasMatchingCredentials(data)

	// U2F appid probes: Chrome sends GetAssertion with rpid="https://..."
	// (a U2F App ID URL) before retrying with the real RP ID (bare domain).
	// Respond immediately — deferring just adds 5s dead time since Chrome
	// blocks waiting and never sends CTAPHID_CANCEL for these probes.
	if cmd == CmdGetAssertion && parseable && !hasMatch && !hasPINAuth && isU2FAppID(assertionRPID) {
		if h.logger != nil {
			h.logger.Info("GetAssertion: U2F appid probe, responding immediately",
				slog.String("cid", fmt.Sprintf("0x%08X", cid)),
				slog.String("rpid", assertionRPID),
			)
		}
	}

	if cmd == CmdGetAssertion && parseable && !hasMatch && !hasPINAuth && !isU2FAppID(assertionRPID) {
		debugHIDLog("processCBORCommandLocked: GetAssertion no matching credentials, deferring until CANCEL")
		if h.logger != nil {
			h.logger.Info("GetAssertion: no matching credentials, waiting for CTAPHID_CANCEL",
				slog.String("cid", fmt.Sprintf("0x%08X", cid)),
				slog.String("rpid", assertionRPID),
				slog.Bool("has_pinUvAuthParam", hasPINAuth),
			)
		}

		// Send KeepaliveStatusProcessing to keep the HID channel alive
		// without triggering Chrome's "touch your security key" prompt.
		keepaliveDone := make(chan struct{})
		var keepaliveWG sync.WaitGroup
		keepaliveWG.Add(1)
		go func() {
			defer keepaliveWG.Done()
			h.sendKeepalives(cid, KeepaliveStatusProcessing, keepaliveDone)
		}()

		// Release lock and wait for CANCEL (or safety timeout).
		h.mu.Unlock()
		safetyTimer := time.NewTimer(noCredentialsSafetyTimeout)
		var cancelled bool
		select {
		case <-ctx.Done():
			safetyTimer.Stop()
			cancelled = true
			debugHIDLog("processCBORCommandLocked: host cancelled during no-credentials deferral")
		case <-safetyTimer.C:
			debugHIDLog("processCBORCommandLocked: safety timeout expired (browser may have crashed)")
		}

		// Stop keepalives and re-acquire lock.
		close(keepaliveDone)
		keepaliveWG.Wait()
		h.mu.Lock()

		cancel()
		h.cancelCBOR = nil

		if h.logger != nil {
			h.logger.Info("GetAssertion no-credentials deferral ended",
				slog.String("cid", fmt.Sprintf("0x%08X", cid)),
				slog.Bool("cancelled_by_host", cancelled),
			)
		}

		// When cancelled by the host (normal path): respond with
		// StatusKeepaliveCancel per CTAP2 spec.
		// When safety timeout expires (abnormal): also respond with
		// StatusKeepaliveCancel to avoid Chrome treating StatusNoCredentials
		// as a terminal ceremony failure.
		h.sendResponseLocked(cid, CTAPHIDCBOR, []byte{StatusKeepaliveCancel})
		return
	}

	// Start keepalive goroutine for commands that require user presence.
	// Per CTAP HID spec, the authenticator must send CTAPHID_KEEPALIVE
	// messages while processing long-running commands to prevent host timeout.
	// GetAssertion only reaches here if matching credentials exist (the
	// no-credentials case is handled by the deferral above).
	//
	// Keepalive status selection:
	//   - KeepaliveStatusProcessing (0x01): the authenticator will return
	//     ErrPINRequired because PIN is set but pinUvAuthParam is absent.
	//     Chrome should show the PIN dialog, NOT "touch your security key".
	//   - KeepaliveStatusUpNeeded (0x02): PIN was already verified (or not
	//     required) and the authenticator is waiting for a physical touch.
	keepaliveDone := make(chan struct{})
	var keepaliveWG sync.WaitGroup
	if cmd == CmdMakeCredential || cmd == CmdGetAssertion {
		keepaliveStatus := byte(KeepaliveStatusUpNeeded)
		if h.authenticator.NeedsPINBeforeTouch(cmd, data) {
			keepaliveStatus = KeepaliveStatusProcessing
		}
		if h.logger != nil {
			h.logger.Info("starting keepalive sender",
				slog.String("cid", fmt.Sprintf("0x%08X", cid)),
				slog.String("cmd", cmdName),
				slog.String("status", fmt.Sprintf("0x%02X", keepaliveStatus)),
			)
		}
		keepaliveWG.Add(1)
		go func() {
			defer keepaliveWG.Done()
			h.sendKeepalives(cid, keepaliveStatus, keepaliveDone)
		}()
	}

	// Process through the authenticator (release lock during processing).
	// The cancellable context allows CTAPHID_CANCEL to abort the command.
	h.mu.Unlock()
	response, err := h.authenticator.ProcessCBORWithContext(ctx, cmd, data)

	// Stop keepalive goroutine and wait for it to finish before re-acquiring lock
	close(keepaliveDone)
	keepaliveWG.Wait()

	h.mu.Lock()

	// Clear the cancel function now that the command has completed.
	cancel()
	h.cancelCBOR = nil

	if err != nil {
		debugHIDLog("processCBORCommandLocked: ProcessCBOR error: %v", err)
		if h.logger != nil {
			statusCode := byte(0xFF)
			if len(response) > 0 {
				statusCode = response[0]
			}
			h.logger.Warn("CTAP2 command failed",
				slog.String("cmd", cmdName),
				slog.String("error", err.Error()),
				slog.String("status", fmt.Sprintf("0x%02X", statusCode)),
			)
		}
		h.sendResponseLocked(cid, CTAPHIDCBOR, response)
		return
	}

	if h.logger != nil {
		h.logger.Info("CTAP2 command succeeded",
			slog.String("cmd", cmdName),
			slog.Int("response_len", len(response)),
		)
	}
	h.sendResponseLocked(cid, CTAPHIDCBOR, response)
}

// ctapCommandName returns a human-readable name for a CTAP2 command byte.
var ctapCommandNames = map[byte]string{
	CmdMakeCredential:       "MakeCredential",
	CmdGetAssertion:         "GetAssertion",
	CmdGetInfo:              "GetInfo",
	CmdClientPIN:            "ClientPIN",
	CmdReset:                "Reset",
	CmdGetNextAssertion:     "GetNextAssertion",
	CmdBioEnrollment:        "BioEnrollment",
	CmdCredentialManagement: "CredentialManagement",
	CmdSelection:            "Selection",
	CmdLargeBlobs:           "LargeBlobs",
	CmdConfig:               "Config",
}

func ctapCommandName(cmd byte) string {
	if name, ok := ctapCommandNames[cmd]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02X)", cmd)
}

// sendKeepalives sends periodic CTAPHID_KEEPALIVE messages until done is closed.
// This prevents the host from timing out during long-running operations like
// user presence verification.
//
// Per the CTAP HID specification, keepalives must be sent at regular intervals
// (100ms). Chrome is particularly strict about timing and will abort the
// transaction if the first keepalive is not received promptly. To satisfy this
// requirement, an initial keepalive is sent immediately before entering the
// periodic ticker loop.
func (h *CTAPHIDHandler) sendKeepalives(cid uint32, status byte, done <-chan struct{}) {
	// Send an initial keepalive immediately. Chrome requires the first
	// keepalive within ~100ms of the command starting, but time.NewTicker
	// does not fire until after the first interval elapses.
	h.mu.Lock()
	debugHIDLog("sendKeepalives: sending initial keepalive CID=0x%08x, status=0x%02x", cid, status)
	h.sendResponseLocked(cid, CTAPHIDKeepalive, []byte{status})
	h.mu.Unlock()

	ticker := time.NewTicker(KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			h.mu.Lock()
			debugHIDLog("sendKeepalives: sending keepalive CID=0x%08x, status=0x%02x", cid, status)
			h.sendResponseLocked(cid, CTAPHIDKeepalive, []byte{status})
			h.mu.Unlock()
		}
	}
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

	packets := h.createResponsePackets(cid, cmd, data)
	debugHIDLog("sendResponseLocked: created %d packet(s)", len(packets))

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
