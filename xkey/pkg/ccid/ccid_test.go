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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gadget"
)

// mockGadgetTransport implements gadget.Transport for unit testing.
// Tests that exercise handleCCIDMessage directly never call Read/Write
// on the transport, so this is a minimal stub.
type mockGadgetTransport struct{}

func (m *mockGadgetTransport) Read(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (m *mockGadgetTransport) Write(data []byte) error {
	return nil
}

func (m *mockGadgetTransport) Close() error {
	return nil
}

// stubHandler implements APDUHandler for testing the CCID device logic
// without requiring UHID or a real PKCS#11 transport.
type stubHandler struct {
	atr      []byte
	handleFn func(cmd *CommandAPDU) *ResponseAPDU
}

func (h *stubHandler) GetATR() []byte {
	return h.atr
}

func (h *stubHandler) HandleAPDU(cmd *CommandAPDU) *ResponseAPDU {
	if h.handleFn != nil {
		return h.handleFn(cmd)
	}
	return NewSuccessResponse(nil)
}

func TestNewCCIDDevice(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatalf("NewCCIDDevice failed: %v", err)
	}
	if device == nil {
		t.Fatal("NewCCIDDevice returned nil")
	}
}

func TestNewCCIDDevice_NilHandler(t *testing.T) {
	_, err := NewCCIDDevice(nil, &mockGadgetTransport{}, newTestLogger())
	if !errors.Is(err, ErrNilHandler) {
		t.Errorf("error = %v, want ErrNilHandler", err)
	}
}

func TestNewCCIDDevice_NilTransport(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	_, err := NewCCIDDevice(handler, nil, newTestLogger())
	if !errors.Is(err, gadget.ErrNilTransport) {
		t.Errorf("error = %v, want ErrNilTransport", err)
	}
}

func TestNewCCIDDevice_NilLogger(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	_, err := NewCCIDDevice(handler, &mockGadgetTransport{}, nil)
	if !errors.Is(err, ErrNilLogger) {
		t.Errorf("error = %v, want ErrNilLogger", err)
	}
}

func TestCCIDDevice_IsRunning_InitiallyFalse(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	if device.IsRunning() {
		t.Error("Expected IsRunning to be false initially")
	}
}

func TestCCIDDevice_Stop_NotRunning(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	err = device.Stop()
	if !errors.Is(err, ErrDeviceNotRunning) {
		t.Errorf("Stop error = %v, want ErrDeviceNotRunning", err)
	}
}

func TestCCIDDevice_HandleCCIDMessage_PowerOn(t *testing.T) {
	atr := []byte{0x3B, 0x80, 0x01}
	handler := &stubHandler{atr: atr}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Build a PC_to_RDR_IccPowerOn message
	msg := make([]byte, CCIDHeaderLength)
	msg[0] = PC_to_RDR_IccPowerOn
	binary.LittleEndian.PutUint32(msg[1:5], 0)
	msg[5] = 0x00 // slot
	msg[6] = 0x01 // seq

	resp := device.handleCCIDMessage(msg)
	if resp == nil {
		t.Fatal("handleCCIDMessage returned nil")
	}

	// Verify response type
	if resp[0] != RDR_to_PC_DataBlock {
		t.Errorf("Response type = 0x%02X, want RDR_to_PC_DataBlock (0x%02X)", resp[0], RDR_to_PC_DataBlock)
	}

	// Verify ATR is in the response
	dataLen := binary.LittleEndian.Uint32(resp[1:5])
	if int(dataLen) != len(atr) {
		t.Errorf("Data length = %d, want %d", dataLen, len(atr))
	}

	// Verify sequence number is echoed
	if resp[6] != 0x01 {
		t.Errorf("Seq = %d, want 1", resp[6])
	}

	// Verify ICC power state
	if !device.iccPower.Load() {
		t.Error("Expected ICC to be powered on")
	}
}

func TestCCIDDevice_HandleCCIDMessage_PowerOff(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Power on first
	device.iccPower.Store(true)

	msg := make([]byte, CCIDHeaderLength)
	msg[0] = PC_to_RDR_IccPowerOff
	msg[5] = 0x00
	msg[6] = 0x02

	resp := device.handleCCIDMessage(msg)
	if resp[0] != RDR_to_PC_SlotStatus {
		t.Errorf("Response type = 0x%02X, want RDR_to_PC_SlotStatus", resp[0])
	}

	if device.iccPower.Load() {
		t.Error("Expected ICC to be powered off")
	}
}

func TestCCIDDevice_HandleCCIDMessage_GetSlotStatus_Active(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	device.iccPower.Store(true)

	msg := make([]byte, CCIDHeaderLength)
	msg[0] = PC_to_RDR_GetSlotStatus
	msg[5] = 0x00
	msg[6] = 0x03

	resp := device.handleCCIDMessage(msg)
	if resp[0] != RDR_to_PC_SlotStatus {
		t.Errorf("Response type = 0x%02X, want RDR_to_PC_SlotStatus", resp[0])
	}

	// bStatus should indicate active (bit 0-1 = 0x00)
	status := resp[7] & 0x03
	if status != ICCStatusActive {
		t.Errorf("ICC status = %d, want ICCStatusActive", status)
	}
}

func TestCCIDDevice_HandleCCIDMessage_GetSlotStatus_Inactive(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, CCIDHeaderLength)
	msg[0] = PC_to_RDR_GetSlotStatus
	msg[6] = 0x04

	resp := device.handleCCIDMessage(msg)
	status := resp[7] & 0x03
	if status != ICCStatusInactive {
		t.Errorf("ICC status = %d, want ICCStatusInactive", status)
	}
}

func TestCCIDDevice_HandleCCIDMessage_XfrBlock(t *testing.T) {
	handler := &stubHandler{
		atr: DefaultATR(),
		handleFn: func(cmd *CommandAPDU) *ResponseAPDU {
			return NewSuccessResponse([]byte{0xDE, 0xAD})
		},
	}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	device.iccPower.Store(true)

	// Build a CCID XfrBlock with a SELECT APDU
	apdu := []byte{0x00, 0xA4, 0x04, 0x00}
	msg := make([]byte, CCIDHeaderLength+len(apdu))
	msg[0] = PC_to_RDR_XfrBlock
	binary.LittleEndian.PutUint32(msg[1:5], uint32(len(apdu)))
	msg[5] = 0x00
	msg[6] = 0x05
	copy(msg[CCIDHeaderLength:], apdu)

	resp := device.handleCCIDMessage(msg)
	if resp[0] != RDR_to_PC_DataBlock {
		t.Errorf("Response type = 0x%02X, want RDR_to_PC_DataBlock", resp[0])
	}

	// The data should be the APDU response: [0xDE, 0xAD, 0x90, 0x00]
	dataLen := binary.LittleEndian.Uint32(resp[1:5])
	if dataLen != 4 {
		t.Errorf("Data length = %d, want 4", dataLen)
	}
}

func TestCCIDDevice_HandleCCIDMessage_XfrBlock_NotPowered(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	// Do NOT power on

	apdu := []byte{0x00, 0xA4, 0x04, 0x00}
	msg := make([]byte, CCIDHeaderLength+len(apdu))
	msg[0] = PC_to_RDR_XfrBlock
	binary.LittleEndian.PutUint32(msg[1:5], uint32(len(apdu)))
	msg[6] = 0x06

	resp := device.handleCCIDMessage(msg)
	if resp[0] != RDR_to_PC_SlotStatus {
		t.Errorf("Response type = 0x%02X, want RDR_to_PC_SlotStatus", resp[0])
	}
}

func TestCCIDDevice_HandleCCIDMessage_XfrBlock_EmptyAPDU(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	device.iccPower.Store(true)

	msg := make([]byte, CCIDHeaderLength)
	msg[0] = PC_to_RDR_XfrBlock
	binary.LittleEndian.PutUint32(msg[1:5], 0) // No data
	msg[6] = 0x07

	resp := device.handleCCIDMessage(msg)
	if resp[0] != RDR_to_PC_DataBlock {
		t.Errorf("Response type = 0x%02X, want RDR_to_PC_DataBlock", resp[0])
	}

	// Should contain SW_WRONG_LENGTH response
	dataLen := binary.LittleEndian.Uint32(resp[1:5])
	if dataLen != 2 {
		t.Errorf("Data length = %d, want 2 (status word only)", dataLen)
	}
}

func TestCCIDDevice_HandleCCIDMessage_GetParameters(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, CCIDHeaderLength)
	msg[0] = PC_to_RDR_GetParameters
	msg[6] = 0x08

	resp := device.handleCCIDMessage(msg)
	if resp[0] != RDR_to_PC_Parameters {
		t.Errorf("Response type = 0x%02X, want RDR_to_PC_Parameters", resp[0])
	}

	// bProtocolNum should be T=1
	if resp[9] != 0x01 {
		t.Errorf("Protocol = %d, want 1 (T=1)", resp[9])
	}
}

func TestCCIDDevice_HandleCCIDMessage_Escape(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, CCIDHeaderLength)
	msg[0] = PC_to_RDR_Escape
	msg[6] = 0x09

	resp := device.handleCCIDMessage(msg)
	if resp[0] != RDR_to_PC_SlotStatus {
		t.Errorf("Response type = 0x%02X, want RDR_to_PC_SlotStatus", resp[0])
	}
}

func TestCCIDDevice_HandleCCIDMessage_Abort(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, CCIDHeaderLength)
	msg[0] = PC_to_RDR_Abort
	msg[6] = 0x0A

	resp := device.handleCCIDMessage(msg)
	if resp[0] != RDR_to_PC_SlotStatus {
		t.Errorf("Response type = 0x%02X, want RDR_to_PC_SlotStatus", resp[0])
	}
}

func TestCCIDDevice_HandleCCIDMessage_UnknownType(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	msg := make([]byte, CCIDHeaderLength)
	msg[0] = 0xFF // Unknown type
	msg[6] = 0x0B

	resp := device.handleCCIDMessage(msg)
	if resp[0] != RDR_to_PC_SlotStatus {
		t.Errorf("Response type = 0x%02X, want RDR_to_PC_SlotStatus (error response)", resp[0])
	}
}

func TestCCIDMessageTypeNames(t *testing.T) {
	tests := []struct {
		msgType byte
		name    string
	}{
		{PC_to_RDR_IccPowerOn, "PC_to_RDR_IccPowerOn"},
		{PC_to_RDR_IccPowerOff, "PC_to_RDR_IccPowerOff"},
		{PC_to_RDR_GetSlotStatus, "PC_to_RDR_GetSlotStatus"},
		{PC_to_RDR_XfrBlock, "PC_to_RDR_XfrBlock"},
		{PC_to_RDR_GetParameters, "PC_to_RDR_GetParameters"},
		{PC_to_RDR_Escape, "PC_to_RDR_Escape"},
		{PC_to_RDR_Abort, "PC_to_RDR_Abort"},
		{0xFF, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ccidMessageTypeName(tt.msgType)
			if got != tt.name {
				t.Errorf("ccidMessageTypeName(0x%02X) = %q, want %q", tt.msgType, got, tt.name)
			}
		})
	}
}

func TestCCIDMessageTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant byte
		expected byte
	}{
		{"PC_to_RDR_IccPowerOn", PC_to_RDR_IccPowerOn, 0x62},
		{"PC_to_RDR_IccPowerOff", PC_to_RDR_IccPowerOff, 0x63},
		{"PC_to_RDR_GetSlotStatus", PC_to_RDR_GetSlotStatus, 0x65},
		{"PC_to_RDR_XfrBlock", PC_to_RDR_XfrBlock, 0x6F},
		{"PC_to_RDR_GetParameters", PC_to_RDR_GetParameters, 0x6C},
		{"PC_to_RDR_Escape", PC_to_RDR_Escape, 0x6B},
		{"PC_to_RDR_Abort", PC_to_RDR_Abort, 0x72},
		{"RDR_to_PC_DataBlock", RDR_to_PC_DataBlock, 0x80},
		{"RDR_to_PC_SlotStatus", RDR_to_PC_SlotStatus, 0x81},
		{"RDR_to_PC_Parameters", RDR_to_PC_Parameters, 0x82},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = 0x%02X, want 0x%02X", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

func TestBuildDataBlock(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	data := []byte{0x90, 0x00}
	msg := device.buildDataBlock(0x05, 0x00, data)

	if msg[0] != RDR_to_PC_DataBlock {
		t.Errorf("Message type = 0x%02X, want 0x%02X", msg[0], RDR_to_PC_DataBlock)
	}

	dataLen := binary.LittleEndian.Uint32(msg[1:5])
	if dataLen != 2 {
		t.Errorf("Data length = %d, want 2", dataLen)
	}

	if msg[5] != 0x00 {
		t.Errorf("Slot = %d, want 0", msg[5])
	}

	if msg[6] != 0x05 {
		t.Errorf("Seq = %d, want 5", msg[6])
	}

	if msg[CCIDHeaderLength] != 0x90 || msg[CCIDHeaderLength+1] != 0x00 {
		t.Errorf("Data = %x, want 9000", msg[CCIDHeaderLength:CCIDHeaderLength+2])
	}
}

func TestBuildSlotStatus(t *testing.T) {
	handler := &stubHandler{atr: DefaultATR()}
	device, err := NewCCIDDevice(handler, &mockGadgetTransport{}, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}

	msg := device.buildSlotStatus(0x03, 0x00, ICCStatusActive, CmdStatusSuccess, 0x00)

	if msg[0] != RDR_to_PC_SlotStatus {
		t.Errorf("Message type = 0x%02X, want 0x%02X", msg[0], RDR_to_PC_SlotStatus)
	}

	if len(msg) != CCIDHeaderLength {
		t.Errorf("Message length = %d, want %d", len(msg), CCIDHeaderLength)
	}
}
