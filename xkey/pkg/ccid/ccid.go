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

package ccid

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gadget"
)

// CCID message types (PC to Reader direction).
const (
	// PC_to_RDR_IccPowerOn powers on the ICC and retrieves the ATR.
	PC_to_RDR_IccPowerOn byte = 0x62

	// PC_to_RDR_IccPowerOff powers off the ICC.
	PC_to_RDR_IccPowerOff byte = 0x63

	// PC_to_RDR_GetSlotStatus requests the current slot status.
	PC_to_RDR_GetSlotStatus byte = 0x65

	// PC_to_RDR_XfrBlock transfers an APDU command to the ICC.
	PC_to_RDR_XfrBlock byte = 0x6F

	// PC_to_RDR_GetParameters requests the current protocol parameters.
	PC_to_RDR_GetParameters byte = 0x6C

	// PC_to_RDR_ResetParameters resets the protocol parameters.
	PC_to_RDR_ResetParameters byte = 0x6D

	// PC_to_RDR_SetParameters sets the protocol parameters.
	PC_to_RDR_SetParameters byte = 0x61

	// PC_to_RDR_Escape sends a vendor-specific escape command.
	PC_to_RDR_Escape byte = 0x6B

	// PC_to_RDR_IccClock manages the ICC clock.
	PC_to_RDR_IccClock byte = 0x6E

	// PC_to_RDR_Abort aborts the current operation.
	PC_to_RDR_Abort byte = 0x72
)

// CCID message types (Reader to PC direction).
const (
	// RDR_to_PC_DataBlock is a data block response.
	RDR_to_PC_DataBlock byte = 0x80

	// RDR_to_PC_SlotStatus is a slot status response.
	RDR_to_PC_SlotStatus byte = 0x81

	// RDR_to_PC_Parameters is a parameters response.
	RDR_to_PC_Parameters byte = 0x82

	// RDR_to_PC_Escape is a vendor escape response.
	RDR_to_PC_Escape byte = 0x83
)

// ICC status values.
const (
	// ICCStatusActive indicates the ICC is present and active.
	ICCStatusActive byte = 0x00

	// ICCStatusInactive indicates the ICC is present but inactive.
	ICCStatusInactive byte = 0x01

	// ICCStatusNotPresent indicates no ICC is present.
	ICCStatusNotPresent byte = 0x02
)

// Command status values.
const (
	// CmdStatusSuccess indicates the command completed successfully.
	CmdStatusSuccess byte = 0x00

	// CmdStatusFailed indicates the command failed.
	CmdStatusFailed byte = 0x01

	// CmdStatusTimeExtension indicates a time extension request.
	CmdStatusTimeExtension byte = 0x02
)

// APDUHandler processes ISO 7816 APDU commands and returns responses.
type APDUHandler interface {
	// HandleAPDU processes a command APDU and returns a response APDU.
	HandleAPDU(cmd *CommandAPDU) *ResponseAPDU

	// GetATR returns the Answer to Reset bytes for the virtual smartcard.
	GetATR() []byte
}

// CCIDDevice represents a virtual CCID smartcard device over a pluggable transport.
//
// It creates a virtual USB device with CCID class descriptors that
// appears to the operating system as a smartcard reader with an
// inserted card. CCID messages are received via the transport,
// APDU payloads are extracted and passed to the APDUHandler, and
// responses are sent back via the transport.
//
// All public methods are safe for concurrent use.
type CCIDDevice struct {
	transport gadget.Transport
	handler   APDUHandler
	logger    *slog.Logger
	running   atomic.Bool
	iccPower  atomic.Bool
	done      chan struct{}
	seqNum    atomic.Uint32
}

// NewCCIDDevice creates a new virtual CCID device backed by the given
// APDU handler and transport. The handler processes all ISO 7816
// commands received through the CCID transport.
//
// The device is not started until Start() is called.
func NewCCIDDevice(handler APDUHandler, transport gadget.Transport, logger *slog.Logger) (*CCIDDevice, error) {
	if handler == nil {
		return nil, ErrNilHandler
	}
	if transport == nil {
		return nil, gadget.ErrNilTransport
	}
	if logger == nil {
		return nil, ErrNilLogger
	}

	return &CCIDDevice{
		transport: transport,
		handler:   handler,
		logger:    logger,
		done:      make(chan struct{}),
	}, nil
}

// Start begins processing CCID messages over the transport. It blocks
// until the context is cancelled or Stop() is called.
func (d *CCIDDevice) Start(ctx context.Context) error {
	if d.running.Swap(true) {
		return ErrDeviceAlreadyRunning
	}

	d.logger.Info("CCID device starting")

	// Start the event loop
	return d.eventLoop(ctx)
}

// Stop signals the CCID device to shut down. The blocking Start()
// call will return after cleanup completes.
func (d *CCIDDevice) Stop() error {
	if !d.running.Load() {
		return ErrDeviceNotRunning
	}

	// Signal event loop to stop
	select {
	case d.done <- struct{}{}:
	default:
	}

	return nil
}

// IsRunning returns true if the device is currently active.
func (d *CCIDDevice) IsRunning() bool {
	return d.running.Load()
}

// eventLoop reads messages from the transport, dispatches CCID messages,
// and sends responses back. It exits when the context is cancelled or
// Stop() is called.
func (d *CCIDDevice) eventLoop(ctx context.Context) error {
	defer func() {
		d.running.Store(false)
		d.logger.Info("CCID event loop stopped")
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-d.done:
			return nil
		default:
		}

		// Read the next message from the transport
		data, err := d.transport.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			d.logger.Error("transport read error",
				slog.Any("error", err),
			)
			continue
		}

		if len(data) < CCIDHeaderLength {
			d.logger.Warn("CCID message too short",
				slog.Int("length", len(data)),
			)
			continue
		}

		// Dispatch the CCID message
		response := d.handleCCIDMessage(data)
		if response == nil {
			continue
		}

		// Send the response via the transport
		if writeErr := d.transport.Write(response); writeErr != nil {
			d.logger.Error("transport write error",
				slog.Any("error", writeErr),
			)
		}
	}
}

// handleCCIDMessage parses a raw CCID message, dispatches it to the
// appropriate handler, and returns the response bytes.
//
// CCID message header (10 bytes):
//
//	[0]     bMessageType
//	[1:5]   dwLength (data length, little-endian)
//	[5]     bSlot
//	[6]     bSeq
//	[7:10]  Message-specific bytes
func (d *CCIDDevice) handleCCIDMessage(msg []byte) []byte {
	msgType := msg[0]
	dataLen := binary.LittleEndian.Uint32(msg[1:5])
	slot := msg[5]
	seq := msg[6]

	d.logger.Debug("CCID message received",
		slog.String("type", ccidMessageTypeName(msgType)),
		slog.Uint64("data_len", uint64(dataLen)),
		slog.Uint64("slot", uint64(slot)),
		slog.Uint64("seq", uint64(seq)),
	)

	// Map-based dispatch for O(1) constant-time lookup.
	handler, ok := d.ccidHandlers()[msgType]
	if !ok {
		d.logger.Warn("unsupported CCID message type",
			slog.String("type", ccidMessageTypeName(msgType)),
			slog.Uint64("type_byte", uint64(msgType)),
		)
		return d.buildSlotStatus(seq, slot, ICCStatusNotPresent, CmdStatusFailed, 0)
	}

	return handler(msg, seq, slot, dataLen)
}

// ccidHandlerFunc is the function signature for CCID message handlers.
type ccidHandlerFunc func(msg []byte, seq, slot byte, dataLen uint32) []byte

// ccidHandlers returns the dispatch map for CCID message types.
func (d *CCIDDevice) ccidHandlers() map[byte]ccidHandlerFunc {
	return map[byte]ccidHandlerFunc{
		PC_to_RDR_IccPowerOn:    d.handleIccPowerOn,
		PC_to_RDR_IccPowerOff:   d.handleIccPowerOff,
		PC_to_RDR_GetSlotStatus: d.handleGetSlotStatus,
		PC_to_RDR_XfrBlock:      d.handleXfrBlock,
		PC_to_RDR_GetParameters: d.handleGetParameters,
		PC_to_RDR_Escape:        d.handleEscape,
		PC_to_RDR_Abort:         d.handleAbort,
	}
}

// handleIccPowerOn powers on the ICC and returns the ATR.
func (d *CCIDDevice) handleIccPowerOn(_ []byte, seq, slot byte, _ uint32) []byte {
	d.iccPower.Store(true)
	atr := d.handler.GetATR()

	d.logger.Info("ICC powered on",
		slog.Int("atr_length", len(atr)),
	)

	return d.buildDataBlock(seq, slot, atr)
}

// handleIccPowerOff powers off the ICC.
func (d *CCIDDevice) handleIccPowerOff(_ []byte, seq, slot byte, _ uint32) []byte {
	d.iccPower.Store(false)
	d.logger.Info("ICC powered off")
	return d.buildSlotStatus(seq, slot, ICCStatusInactive, CmdStatusSuccess, 0)
}

// handleGetSlotStatus returns the current slot status.
func (d *CCIDDevice) handleGetSlotStatus(_ []byte, seq, slot byte, _ uint32) []byte {
	status := ICCStatusActive
	if !d.iccPower.Load() {
		status = ICCStatusInactive
	}
	return d.buildSlotStatus(seq, slot, status, CmdStatusSuccess, 0)
}

// handleXfrBlock receives an APDU command, processes it through the
// handler, and returns the response.
func (d *CCIDDevice) handleXfrBlock(msg []byte, seq, slot byte, dataLen uint32) []byte {
	if !d.iccPower.Load() {
		d.logger.Warn("XfrBlock received but ICC not powered on")
		return d.buildSlotStatus(seq, slot, ICCStatusInactive, CmdStatusFailed, 0)
	}

	// Extract the APDU data from the CCID message.
	apduStart := CCIDHeaderLength
	apduEnd := apduStart + int(dataLen)
	if apduEnd > len(msg) {
		apduEnd = len(msg)
	}

	if apduStart >= apduEnd {
		d.logger.Warn("XfrBlock with empty APDU data")
		errResp := NewErrorResponse(SW_WRONG_LENGTH)
		return d.buildDataBlock(seq, slot, errResp.Serialize())
	}

	apduBytes := msg[apduStart:apduEnd]

	// Parse the command APDU.
	cmdAPDU, err := ParseCommandAPDU(apduBytes)
	if err != nil {
		d.logger.Error("failed to parse command APDU",
			slog.Any("error", err),
			slog.Int("length", len(apduBytes)),
		)
		errResp := NewErrorResponse(SW_WRONG_LENGTH)
		return d.buildDataBlock(seq, slot, errResp.Serialize())
	}

	d.logger.Debug("processing APDU",
		slog.String("CLA", fmt.Sprintf("0x%02X", cmdAPDU.CLA)),
		slog.String("INS", fmt.Sprintf("0x%02X", cmdAPDU.INS)),
		slog.String("P1", fmt.Sprintf("0x%02X", cmdAPDU.P1)),
		slog.String("P2", fmt.Sprintf("0x%02X", cmdAPDU.P2)),
		slog.Int("data_len", len(cmdAPDU.Data)),
	)

	// Pass the APDU to the handler.
	respAPDU := d.handler.HandleAPDU(cmdAPDU)

	// Serialize the response and wrap in a CCID DataBlock.
	return d.buildDataBlock(seq, slot, respAPDU.Serialize())
}

// handleGetParameters returns the current ICC protocol parameters.
func (d *CCIDDevice) handleGetParameters(_ []byte, seq, slot byte, _ uint32) []byte {
	// Return T=1 protocol parameters.
	params := []byte{
		0x01, // Protocol T=1
		0x11, // bmFindexDindex: Fi=372, Di=1
		0x00, // bmTCCKST1: No CRC
		0x00, // bGuardTimeT1
		0xFE, // bmWaitingIntegersT1: BWI=15, CWI=14
		0x00, // bClockStop: Not supported
		0xFE, // bIFSC: 254 bytes
		0x00, // bNadValue: 0
	}
	return d.buildParameters(seq, slot, params)
}

// handleEscape handles vendor-specific escape commands.
func (d *CCIDDevice) handleEscape(_ []byte, seq, slot byte, _ uint32) []byte {
	return d.buildSlotStatus(seq, slot, ICCStatusActive, CmdStatusFailed, 0)
}

// handleAbort handles abort requests.
func (d *CCIDDevice) handleAbort(_ []byte, seq, slot byte, _ uint32) []byte {
	return d.buildSlotStatus(seq, slot, ICCStatusActive, CmdStatusSuccess, 0)
}

// buildDataBlock constructs a RDR_to_PC_DataBlock CCID response.
func (d *CCIDDevice) buildDataBlock(seq, slot byte, data []byte) []byte {
	msg := make([]byte, CCIDHeaderLength+len(data))
	msg[0] = RDR_to_PC_DataBlock
	binary.LittleEndian.PutUint32(msg[1:5], uint32(len(data)))
	msg[5] = slot
	msg[6] = seq
	msg[7] = ICCStatusActive // bStatus: ICC present and active
	msg[8] = 0x00            // bError: No error
	msg[9] = 0x00            // bChainParameter: not used
	copy(msg[CCIDHeaderLength:], data)
	return msg
}

// buildSlotStatus constructs a RDR_to_PC_SlotStatus CCID response.
func (d *CCIDDevice) buildSlotStatus(seq, slot, iccStatus, cmdStatus, clockStatus byte) []byte {
	msg := make([]byte, CCIDHeaderLength)
	msg[0] = RDR_to_PC_SlotStatus
	binary.LittleEndian.PutUint32(msg[1:5], 0) // No data
	msg[5] = slot
	msg[6] = seq
	msg[7] = iccStatus | (cmdStatus << 6) // bStatus
	msg[8] = 0x00                         // bError
	msg[9] = clockStatus                  // bClockStatus
	return msg
}

// buildParameters constructs a RDR_to_PC_Parameters CCID response.
func (d *CCIDDevice) buildParameters(seq, slot byte, params []byte) []byte {
	msg := make([]byte, CCIDHeaderLength+len(params))
	msg[0] = RDR_to_PC_Parameters
	binary.LittleEndian.PutUint32(msg[1:5], uint32(len(params)))
	msg[5] = slot
	msg[6] = seq
	msg[7] = ICCStatusActive // bStatus
	msg[8] = 0x00            // bError
	msg[9] = 0x01            // bProtocolNum: T=1
	copy(msg[CCIDHeaderLength:], params)
	return msg
}

// ccidMessageTypeName returns a human-readable name for a CCID message type.
var ccidMessageTypeNames = map[byte]string{
	PC_to_RDR_IccPowerOn:      "PC_to_RDR_IccPowerOn",
	PC_to_RDR_IccPowerOff:     "PC_to_RDR_IccPowerOff",
	PC_to_RDR_GetSlotStatus:   "PC_to_RDR_GetSlotStatus",
	PC_to_RDR_XfrBlock:        "PC_to_RDR_XfrBlock",
	PC_to_RDR_GetParameters:   "PC_to_RDR_GetParameters",
	PC_to_RDR_ResetParameters: "PC_to_RDR_ResetParameters",
	PC_to_RDR_SetParameters:   "PC_to_RDR_SetParameters",
	PC_to_RDR_Escape:          "PC_to_RDR_Escape",
	PC_to_RDR_IccClock:        "PC_to_RDR_IccClock",
	PC_to_RDR_Abort:           "PC_to_RDR_Abort",
}

func ccidMessageTypeName(msgType byte) string {
	if name, ok := ccidMessageTypeNames[msgType]; ok {
		return name
	}
	return "unknown"
}
