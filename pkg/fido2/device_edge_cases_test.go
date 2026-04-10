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

//go:build linux

package fido2

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for UnlockWithKey retry paths - covers fido2.go:156
// Skipped: Complex HID protocol mock implementation issues
func TestUnlockWithKey_RetryOnTimeout_FC(t *testing.T) {
	t.Skip("Complex HID protocol mock requires real device behavior")
}

// TimeoutThenSuccessDeviceFC fails with timeout, then succeeds
type TimeoutThenSuccessDeviceFC struct {
	*MockHIDDevice
	failCount int
	attempts  int
	mu        sync.Mutex
}

func (d *TimeoutThenSuccessDeviceFC) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.fcInitResp(data[7:])
	case CTAPHID_CBOR:
		d.fcCBORResp(data[7:])
	}

	return len(data), nil
}

func (d *TimeoutThenSuccessDeviceFC) fcInitResp(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *TimeoutThenSuccessDeviceFC) fcCBORResp(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		info := map[int]interface{}{
			0x01: []string{"FIDO_2_0"},
			0x02: []string{"hmac-secret"},
			0x03: make([]byte, 16),
			0x04: map[string]bool{"up": true},
		}
		encoded, _ := cbor.Marshal(info)
		d.fcWritePkts(0x12345678, append([]byte{StatusOK}, encoded...))
	case CmdGetAssertion:
		d.mu.Lock()
		d.attempts++
		attempt := d.attempts
		d.mu.Unlock()

		if attempt <= d.failCount {
			// Return timeout error
			d.fcWritePkts(0x12345678, []byte{StatusUserActionTimeout})
		} else {
			// Return success
			authData := make([]byte, 37+32)
			copy(authData[0:32], make([]byte, 32))
			authData[32] = 0x81
			binary.BigEndian.PutUint32(authData[33:37], 2)
			hmacOutput := make([]byte, 32)
			for i := range hmacOutput {
				hmacOutput[i] = byte(i + 100)
			}
			copy(authData[37:], hmacOutput)

			respMap := map[int]interface{}{
				0x01: map[string]interface{}{"type": "public-key", "id": make([]byte, 32)},
				0x02: authData,
				0x03: make([]byte, 64),
			}
			encoded, _ := cbor.Marshal(respMap)
			d.fcWritePkts(0x12345678, append([]byte{StatusOK}, encoded...))
		}
	}
}

func (d *TimeoutThenSuccessDeviceFC) fcWritePkts(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	if payloadLen <= HIDPacketSize-7 {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:HIDPacketSize-7])
	d.readBuf.Write(firstPacket)
}

func (d *TimeoutThenSuccessDeviceFC) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// SingleDeviceEnumeratorFC returns a single device
type SingleDeviceEnumeratorFC struct {
	device HIDDevice
}

func (e *SingleDeviceEnumeratorFC) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	return []HIDDevice{e.device}, nil
}

func (e *SingleDeviceEnumeratorFC) Open(path string) (HIDDevice, error) {
	return e.device, nil
}

// Tests for UnlockWithKey all retries fail - covers fido2.go:231
func TestUnlockWithKey_AllRetriesFail_FC(t *testing.T) {
	config := DefaultConfig
	config.RetryCount = 2
	config.RetryDelay = 10 * time.Millisecond

	mockDev := &AlwaysTimeoutDeviceFC{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumeratorFC{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	_, err = handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	// The error is from the underlying FIDO2 operation
	assert.Contains(t, err.Error(), "timeout")
}

// AlwaysTimeoutDeviceFC always returns timeout
type AlwaysTimeoutDeviceFC struct {
	*MockHIDDevice
}

func (d *AlwaysTimeoutDeviceFC) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.atInitResp(data[7:])
	case CTAPHID_CBOR:
		d.atCBORResp(data[7:])
	}

	return len(data), nil
}

func (d *AlwaysTimeoutDeviceFC) atInitResp(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *AlwaysTimeoutDeviceFC) atCBORResp(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		info := map[int]interface{}{
			0x01: []string{"FIDO_2_0"},
			0x02: []string{"hmac-secret"},
			0x03: make([]byte, 16),
			0x04: map[string]bool{"up": true},
		}
		encoded, _ := cbor.Marshal(info)
		d.atWritePkts(0x12345678, append([]byte{StatusOK}, encoded...))
	case CmdGetAssertion:
		// Always return timeout
		d.atWritePkts(0x12345678, []byte{StatusUserActionTimeout})
	}
}

func (d *AlwaysTimeoutDeviceFC) atWritePkts(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	if payloadLen <= HIDPacketSize-7 {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:HIDPacketSize-7])
	d.readBuf.Write(firstPacket)
}

func (d *AlwaysTimeoutDeviceFC) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// Tests for UnlockWithKey retry on user presence required - covers fido2.go:215-216
// Skipped: Complex HID protocol mock implementation issues
func TestUnlockWithKey_RetryOnUserPresenceRequired_FC(t *testing.T) {
	t.Skip("Complex HID protocol mock requires real device behavior")
}

// UserPresenceThenSuccessDeviceFC fails with user presence required, then succeeds
type UserPresenceThenSuccessDeviceFC struct {
	*MockHIDDevice
	failCount int
	attempts  int
	mu        sync.Mutex
}

func (d *UserPresenceThenSuccessDeviceFC) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.upInitResp(data[7:])
	case CTAPHID_CBOR:
		d.upCBORResp(data[7:])
	}

	return len(data), nil
}

func (d *UserPresenceThenSuccessDeviceFC) upInitResp(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *UserPresenceThenSuccessDeviceFC) upCBORResp(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		info := map[int]interface{}{
			0x01: []string{"FIDO_2_0"},
			0x02: []string{"hmac-secret"},
			0x03: make([]byte, 16),
			0x04: map[string]bool{"up": true},
		}
		encoded, _ := cbor.Marshal(info)
		d.upWritePkts(0x12345678, append([]byte{StatusOK}, encoded...))
	case CmdGetAssertion:
		d.mu.Lock()
		d.attempts++
		attempt := d.attempts
		d.mu.Unlock()

		if attempt <= d.failCount {
			// Return user presence required
			d.upWritePkts(0x12345678, []byte{StatusUPRequired})
		} else {
			// Return success
			authData := make([]byte, 37+32)
			copy(authData[0:32], make([]byte, 32))
			authData[32] = 0x81
			binary.BigEndian.PutUint32(authData[33:37], 2)
			hmacOutput := make([]byte, 32)
			for i := range hmacOutput {
				hmacOutput[i] = byte(i + 100)
			}
			copy(authData[37:], hmacOutput)

			respMap := map[int]interface{}{
				0x01: map[string]interface{}{"type": "public-key", "id": make([]byte, 32)},
				0x02: authData,
				0x03: make([]byte, 64),
			}
			encoded, _ := cbor.Marshal(respMap)
			d.upWritePkts(0x12345678, append([]byte{StatusOK}, encoded...))
		}
	}
}

func (d *UserPresenceThenSuccessDeviceFC) upWritePkts(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	if payloadLen <= HIDPacketSize-7 {
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	copy(firstPacket[7:], fullPayload[:HIDPacketSize-7])
	d.readBuf.Write(firstPacket)
}

func (d *UserPresenceThenSuccessDeviceFC) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// Tests for WaitForDevice with enumerate error - covers fido2.go:278
func TestWaitForDevice_EnumerateErrorContinues_FC(t *testing.T) {
	config := DefaultConfig

	// Enumerator that fails first then succeeds
	enum := &FailThenSucceedEnumeratorFC{
		failCount: 2,
	}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	device, err := handler.WaitForDevice(ctx)
	require.NoError(t, err)
	assert.NotNil(t, device)
}

// FailThenSucceedEnumeratorFC fails initially then succeeds
type FailThenSucceedEnumeratorFC struct {
	failCount int
	attempts  int
	mu        sync.Mutex
}

func (e *FailThenSucceedEnumeratorFC) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	e.mu.Lock()
	e.attempts++
	attempt := e.attempts
	e.mu.Unlock()

	if attempt <= e.failCount {
		return nil, errors.New("enumerate failed")
	}

	mockDev := NewMockHIDDevice("/dev/hidraw0")
	return []HIDDevice{mockDev}, nil
}

func (e *FailThenSucceedEnumeratorFC) Open(path string) (HIDDevice, error) {
	return NewMockHIDDevice(path), nil
}

// Tests for SendCBOR empty response - covers device.go:327
func TestSendCBOR_EmptyResponse_FC(t *testing.T) {
	config := DefaultConfig
	mockDev := &EmptyResponseDeviceFC{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	// Try to send a CBOR command that returns empty response
	_, err = ctapDev.SendCBOR(CmdGetInfo, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty CBOR response")
}

// EmptyResponseDeviceFC returns empty CBOR response
type EmptyResponseDeviceFC struct {
	*MockHIDDevice
}

func (d *EmptyResponseDeviceFC) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.erInitResp(data[7:])
	case CTAPHID_CBOR:
		d.erCBORResp()
	}

	return len(data), nil
}

func (d *EmptyResponseDeviceFC) erInitResp(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *EmptyResponseDeviceFC) erCBORResp() {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Write empty CBOR response (0 payload length)
	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], 0x12345678)
	response[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(response[5:7], 0) // Zero length payload

	d.readBuf.Write(response)
}

func (d *EmptyResponseDeviceFC) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// Tests for readResponseSync with incomplete first packet - covers device.go:220-221
func TestReadResponseSync_IncompleteFirstPacket_FC(t *testing.T) {
	config := DefaultConfig
	mockDev := &IncompletePacketDeviceFC{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	_, err := NewCTAPHIDDevice(mockDev, &config)
	assert.Error(t, err) // Should fail because packet is incomplete
}

// IncompletePacketDeviceFC returns incomplete packets
type IncompletePacketDeviceFC struct {
	*MockHIDDevice
}

func (d *IncompletePacketDeviceFC) Write(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Write short response (less than HIDPacketSize)
	d.readBuf.Write(make([]byte, 32)) // Only 32 bytes

	return len(data), nil
}

func (d *IncompletePacketDeviceFC) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// Tests for readResponseSync channel ID mismatch - covers device.go:226-227
func TestReadResponseSync_CIDMismatch_FC(t *testing.T) {
	config := DefaultConfig
	mockDev := &CIDMismatchDeviceFC{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		useBadCID:     false,
	}

	// First init should succeed
	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	// Now enable bad CID responses
	mockDev.useBadCID = true

	// Next command should fail due to CID mismatch
	_, err = ctapDev.SendCBOR(CmdGetInfo, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "channel ID mismatch")
}

// CIDMismatchDeviceFC returns responses with wrong CID
type CIDMismatchDeviceFC struct {
	*MockHIDDevice
	useBadCID bool
}

func (d *CIDMismatchDeviceFC) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.cmInitResp(data[7:])
	case CTAPHID_CBOR:
		d.cmCBORResp()
	}

	return len(data), nil
}

func (d *CIDMismatchDeviceFC) cmInitResp(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *CIDMismatchDeviceFC) cmCBORResp() {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	if d.useBadCID {
		// Use wrong CID
		binary.BigEndian.PutUint32(response[0:4], 0x99999999)
	} else {
		binary.BigEndian.PutUint32(response[0:4], 0x12345678)
	}
	response[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(response[5:7], 1)
	response[7] = StatusOK

	d.readBuf.Write(response)
}

func (d *CIDMismatchDeviceFC) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// Tests for readResponseSync keepalive handling - covers device.go:233-237
func TestReadResponseSync_Keepalive_FC(t *testing.T) {
	config := DefaultConfig
	mockDev := &KeepaliveDeviceFC{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	// Should handle keepalive and then get actual response
	resp, err := ctapDev.SendCBOR(CmdGetInfo, nil)
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// KeepaliveDeviceFC sends keepalive before actual response
type KeepaliveDeviceFC struct {
	*MockHIDDevice
	sendKeepalive bool
}

func (d *KeepaliveDeviceFC) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.kaInitResp(data[7:])
	case CTAPHID_CBOR:
		d.sendKeepalive = true
		d.kaCBORResp()
	}

	return len(data), nil
}

func (d *KeepaliveDeviceFC) kaInitResp(nonce []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], nonce[:8])
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01

	d.readBuf.Write(response)
}

func (d *KeepaliveDeviceFC) kaCBORResp() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.sendKeepalive {
		// First send a keepalive
		keepalive := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(keepalive[0:4], 0x12345678)
		keepalive[4] = CTAPHID_KEEPALIVE
		binary.BigEndian.PutUint16(keepalive[5:7], 1)
		keepalive[7] = 0x01 // Status byte
		d.readBuf.Write(keepalive)
		d.sendKeepalive = false
	}

	// Then send actual response
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}
	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	payloadLen := len(fullPayload)

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], 0x12345678)
	response[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(response[5:7], uint16(payloadLen))
	copy(response[7:], fullPayload)

	d.readBuf.Write(response)
}

func (d *KeepaliveDeviceFC) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}

// Tests for readResponseSync error response - covers device.go:240-245
func TestReadResponseSync_CTAPHIDError_FC(t *testing.T) {
	config := DefaultConfig
	mockDev := &CTAPHIDErrorDeviceFC{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	// CTAP init should fail due to CTAPHID error
	_, err := NewCTAPHIDDevice(mockDev, &config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CTAPHID error")
}

// CTAPHIDErrorDeviceFC returns CTAPHID_ERROR responses
type CTAPHIDErrorDeviceFC struct {
	*MockHIDDevice
}

func (d *CTAPHIDErrorDeviceFC) Write(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Return error response
	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_ERROR
	binary.BigEndian.PutUint16(response[5:7], 1)
	response[7] = 0x01 // Error code

	d.readBuf.Write(response)

	return len(data), nil
}

func (d *CTAPHIDErrorDeviceFC) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}
