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

package fido2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Additional coverage tests for pkg/fido2
// These tests cover edge cases and error paths not covered in other test files

// TestReadResponseSync_ErrorResponseZeroCode tests CTAPHID error with code 0x00
func TestReadResponseSync_ErrorResponseZeroCode(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig
	config.Timeout = 500 * time.Millisecond

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	// Create error response with code 0x00
	errorPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(errorPacket[0:4], ctapDev.cid)
	errorPacket[4] = CTAPHID_ERROR
	binary.BigEndian.PutUint16(errorPacket[5:7], 1) // 1 byte payload
	errorPacket[7] = 0x00                           // Error code 0x00

	mockDev.Reset()
	mockDev.SetResponse(errorPacket)

	_, err = ctapDev.SendCBOR(CmdGetInfo, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CTAPHID error")
}

// TestSendCommand_WriteError tests write failure handling
func TestSendCommand_WriteError(t *testing.T) {
	mockDev := &ErrorMockHIDDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		writeErr:      errors.New("write failed"),
	}
	config := DefaultConfig
	config.Timeout = 500 * time.Millisecond

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	_, err := ctapDev.sendCommand(ctapDev.cid, CTAPHID_PING, []byte("test"), config.Timeout)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write HID packet")
}

// TestEnrollKey_CTAPDeviceInitError tests CTAP device initialization failure
func TestEnrollKey_CTAPDeviceInitError(t *testing.T) {
	config := DefaultConfig
	config.Timeout = 100 * time.Millisecond

	mockDev := &FailingInitMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	result, err := handler.EnrollKey(enrollConfig)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to initialize CTAP")
}

// TestUnlockWithKey_CTAPDeviceInitError tests CTAP device initialization failure
func TestUnlockWithKey_CTAPDeviceInitError(t *testing.T) {
	config := DefaultConfig
	config.Timeout = 100 * time.Millisecond

	mockDev := &FailingInitMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	result, err := handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to initialize CTAP")
}

// TestParseAuthDataExtensions_NoExtensionDataAtEnd tests when auth data is exactly at offset
func TestParseAuthDataExtensions_NoExtensionDataAtEnd(t *testing.T) {
	authData := make([]byte, 37)
	authData[32] = 0x80 // ED flag only

	extensions, err := ParseAuthDataExtensions(authData)
	assert.NoError(t, err)
	assert.Nil(t, extensions)
}

// TestConfig_AllFieldsValidation tests validation of all config fields
func TestConfig_AllFieldsValidation(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{name: "negative timeout", config: Config{Timeout: -1}},
		{name: "negative user presence timeout", config: Config{UserPresenceTimeout: -1}},
		{name: "negative retry delay", config: Config{RetryDelay: -1}},
		{name: "empty relying party name", config: Config{RelyingPartyName: ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			assert.NoError(t, err)
		})
	}
}

// TestHMACSecretInput_Coverage tests HMAC secret input structure
func TestHMACSecretInput_Coverage(t *testing.T) {
	input := HMACSecretInput{
		KeyAgreement:      map[string]interface{}{"1": 2, "-1": 1},
		SaltEnc:           make([]byte, 32),
		SaltAuth:          make([]byte, 16),
		PinUVAuthProtocol: 1,
	}

	assert.NotNil(t, input.KeyAgreement)
	assert.Equal(t, 32, len(input.SaltEnc))
	assert.Equal(t, 16, len(input.SaltAuth))
	assert.Equal(t, uint64(1), input.PinUVAuthProtocol)
}

// TestEnrollmentResult_Coverage tests enrollment result structure
func TestEnrollmentResult_Coverage(t *testing.T) {
	result := EnrollmentResult{
		CredentialID: make([]byte, 32),
		PublicKey:    make([]byte, 65),
		AAGUID:       make([]byte, 16),
		SignCount:    1,
		RelyingParty: RelyingParty{ID: "test.com", Name: "Test"},
		User:         User{Name: "test", DisplayName: "Test"},
		Salt:         make([]byte, 32),
		Created:      time.Now(),
	}

	assert.Equal(t, 32, len(result.CredentialID))
	assert.Equal(t, 65, len(result.PublicKey))
	assert.Equal(t, 16, len(result.AAGUID))
	assert.Equal(t, uint32(1), result.SignCount)
	assert.False(t, result.Created.IsZero())
}

// Helper types for testing

// ErrorMockHIDDevice is a mock that can fail on write/read
type ErrorMockHIDDevice struct {
	*MockHIDDevice
	writeErr error
	readErr  error
}

func (d *ErrorMockHIDDevice) Write(data []byte) (int, error) {
	if d.writeErr != nil {
		return 0, d.writeErr
	}
	return d.MockHIDDevice.Write(data)
}

func (d *ErrorMockHIDDevice) Read(data []byte) (int, error) {
	if d.readErr != nil {
		return 0, d.readErr
	}
	return d.MockHIDDevice.Read(data)
}

// FailingInitMockDevice fails during CTAP initialization
type FailingInitMockDevice struct {
	*MockHIDDevice
	callCount int
}

func (d *FailingInitMockDevice) Write(data []byte) (int, error) {
	d.callCount++
	return d.MockHIDDevice.Write(data)
}

func (d *FailingInitMockDevice) Read(data []byte) (int, error) {
	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 5) // Too short
	copy(data, response)
	return HIDPacketSize, nil
}

func (d *FailingInitMockDevice) Close() error {
	return d.MockHIDDevice.Close()
}

// SingleDeviceEnumerator returns a single device
type SingleDeviceEnumerator struct {
	device HIDDevice
}

func (e *SingleDeviceEnumerator) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	return []HIDDevice{e.device}, nil
}

func (e *SingleDeviceEnumerator) Open(path string) (HIDDevice, error) {
	return e.device, nil
}

// TestCTAPHIDConstants_Coverage verifies all CTAP HID constants
func TestCTAPHIDConstants_Coverage(t *testing.T) {
	assert.Equal(t, 0x81, CTAPHID_PING)
	assert.Equal(t, 0x83, CTAPHID_MSG)
	assert.Equal(t, 0x84, CTAPHID_LOCK)
	assert.Equal(t, 0x86, CTAPHID_INIT)
	assert.Equal(t, 0x88, CTAPHID_WINK)
	assert.Equal(t, 0x90, CTAPHID_CBOR)
	assert.Equal(t, 0x91, CTAPHID_CANCEL)
	assert.Equal(t, 0xBB, CTAPHID_KEEPALIVE)
	assert.Equal(t, 0xBF, CTAPHID_ERROR)
	assert.Equal(t, 64, HIDPacketSize)
	assert.Equal(t, 8, InitNonceSize)
	assert.Equal(t, 4, CIDSize)
	assert.Equal(t, uint32(0xFFFFFFFF), uint32(CIDBroadcast))
	assert.Equal(t, 0xF1D0, FIDOAllianceVID)
	assert.Equal(t, 0xF1D0, HIDUsagePage)
	assert.Equal(t, 0x01, HIDUsage)
}

// TestAllStatusCodes_Coverage tests all CTAP status code constants
func TestAllStatusCodes_Coverage(t *testing.T) {
	assert.Equal(t, 0x00, StatusOK)
	assert.Equal(t, 0x7F, StatusOtherError)
	assert.NotEqual(t, StatusOK, StatusInvalidCommand)
	assert.NotEqual(t, StatusOK, StatusInvalidParameter)
}

// TestAllCTAPCommands_Coverage tests all CTAP command constants
func TestAllCTAPCommands_Coverage(t *testing.T) {
	assert.Equal(t, 0x01, CmdMakeCredential)
	assert.Equal(t, 0x02, CmdGetAssertion)
	assert.Equal(t, 0x04, CmdGetInfo)
	assert.Equal(t, 0x06, CmdClientPIN)
	assert.Equal(t, 0x07, CmdReset)
}

// TestDefaultTimeoutConstants_Coverage tests default timeout values
func TestDefaultTimeoutConstants_Coverage(t *testing.T) {
	assert.Equal(t, 30*time.Second, DefaultTimeout)
	assert.Equal(t, 30*time.Second, DefaultUserPresenceTimeout)
	assert.Equal(t, 3, DefaultRetryCount)
	assert.Equal(t, 100*time.Millisecond, DefaultRetryDelay)
}

// TestMockHIDDevice_Reset_Coverage tests the Reset method
func TestMockHIDDevice_Reset_Coverage(t *testing.T) {
	dev := NewMockHIDDevice("/dev/hidraw0")
	_, err := dev.Write([]byte("test data"))
	require.NoError(t, err)
	dev.SetResponse(make([]byte, 64))
	assert.Equal(t, 1, dev.writeCount)
	assert.NotEmpty(t, dev.responses)
	dev.Reset()
	assert.Equal(t, 0, dev.writeCount)
	assert.Empty(t, dev.responses)
	assert.False(t, dev.closed)
}

// TestCreatePackets_LargePayload_Coverage tests packet creation with large payloads
func TestCreatePackets_LargePayload_Coverage(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	largePayload := make([]byte, 500)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	packets := ctapDev.createPackets(ctapDev.cid, CTAPHID_CBOR, largePayload)

	expectedPackets := 1 + (500-57+58)/59
	assert.Equal(t, expectedPackets, len(packets))

	for _, packet := range packets {
		assert.Equal(t, HIDPacketSize, len(packet))
	}

	assert.Equal(t, ctapDev.cid, binary.BigEndian.Uint32(packets[0][0:4]))
	assert.Equal(t, byte(CTAPHID_CBOR), packets[0][4])
	assert.Equal(t, uint16(500), binary.BigEndian.Uint16(packets[0][5:7]))
}

// TestReadResponse_IncompleteFirstPacket_Coverage tests handling incomplete first packet
func TestReadResponse_IncompleteFirstPacket_Coverage(t *testing.T) {
	config := DefaultConfig
	config.Timeout = 500 * time.Millisecond

	mockDev := &IncompleteReadMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		shortRead:     true,
	}

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	_, err := ctapDev.readResponseSync(ctapDev.cid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete first packet")
}

// IncompleteReadMockDevice returns incomplete reads
type IncompleteReadMockDevice struct {
	*MockHIDDevice
	shortRead bool
}

func (d *IncompleteReadMockDevice) Read(data []byte) (int, error) {
	if d.shortRead {
		return 30, nil
	}
	return d.MockHIDDevice.Read(data)
}

// TestDeviceInfo_AllFields_Coverage tests DeviceInfo with all optional fields
func TestDeviceInfo_AllFields_Coverage(t *testing.T) {
	info := &DeviceInfo{
		Versions:                         []string{"FIDO_2_0", "FIDO_2_1"},
		Extensions:                       []string{"hmac-secret", "credProtect"},
		AAGUID:                           make([]byte, 16),
		Options:                          map[string]bool{"rk": true, "up": true},
		MaxMsgSize:                       2048,
		PINProtocols:                     []uint64{1, 2},
		MaxCredentialCount:               25,
		MaxCredentialIDLen:               128,
		Transports:                       []string{"usb", "nfc"},
		Algorithms:                       []PublicKeyCredentialParameter{{Type: "public-key", Alg: -7}},
		MaxSerializedLargeBlobArray:      4096,
		ForcePINChange:                   false,
		MinPINLength:                     4,
		FirmwareVersion:                  0x00010002,
		MaxCredBlobLen:                   32,
		MaxRPIDsForSetMinPIN:             3,
		PreferredPlatformUvAttempts:      3,
		UVModality:                       2,
		Certifications:                   map[string]interface{}{"FIDO": []interface{}{1}},
		RemainingDiscoverableCredentials: 100,
		VendorPrototypeConfigCommands:    []uint64{0x01},
	}

	assert.Equal(t, 2, len(info.Versions))
	assert.Equal(t, 2, len(info.Extensions))
	assert.Equal(t, uint64(2048), info.MaxMsgSize)
	assert.Equal(t, 2, len(info.PINProtocols))
}

// TestHandleCTAPError_UnknownError_Coverage tests unknown error code handling
func TestHandleCTAPError_UnknownError_Coverage(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
	}

	err := ctapDev.handleCTAPError(0xF5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CTAP error: 0xF5")

	err = ctapDev.handleCTAPError(0xE5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CTAP error: 0xE5")
}

// TestSendCBOR_ErrorStatus_Coverage tests CBOR response with error status
func TestSendCBOR_ErrorStatus_Coverage(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	errorResp := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(errorResp[0:4], ctapDev.cid)
	errorResp[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(errorResp[5:7], 1)
	errorResp[7] = StatusPINRequired

	mockDev.Reset()
	mockDev.SetResponse(errorResp)

	_, err = ctapDev.SendCBOR(CmdMakeCredential, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPINRequired)
}

// TestReadResponseSync_EmptyPayload_Coverage tests handling of empty payload
func TestReadResponseSync_EmptyPayload_Coverage(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	emptyResp := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(emptyResp[0:4], ctapDev.cid)
	emptyResp[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(emptyResp[5:7], 1)
	emptyResp[7] = StatusOK

	mockDev.Reset()
	mockDev.SetResponse(emptyResp)

	resp, err := ctapDev.SendCBOR(CmdGetInfo, nil)
	require.NoError(t, err)
	assert.Empty(t, resp)
}

// TestCTAPHIDDevice_Close_Coverage tests device close
func TestCTAPHIDDevice_Close_Coverage(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)

	err = ctapDev.Close()
	assert.NoError(t, err)
	assert.True(t, mockDev.closed)
}

// TestReadResponse_FirstPacketReadError_Coverage tests first packet read error
func TestReadResponse_FirstPacketReadError_Coverage(t *testing.T) {
	config := DefaultConfig
	config.Timeout = 500 * time.Millisecond

	mockDev := &ReadErrorMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		err:           errors.New("read failed"),
	}

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	_, err := ctapDev.readResponseSync(ctapDev.cid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read first packet")
}

// ReadErrorMockDevice always fails on read
type ReadErrorMockDevice struct {
	*MockHIDDevice
	err error
}

func (d *ReadErrorMockDevice) Read(data []byte) (int, error) {
	return 0, d.err
}

// TestMockHIDDevice_ReadAfterClose_Coverage tests read after close
func TestMockHIDDevice_ReadAfterClose_Coverage(t *testing.T) {
	dev := NewMockHIDDevice("/dev/hidraw0")
	err := dev.Close()
	require.NoError(t, err)

	buf := make([]byte, 64)
	_, err = dev.Read(buf)
	assert.Error(t, err)
}

// TestReadBuffer_Coverage tests read buffer operations
func TestReadBuffer_Coverage(t *testing.T) {
	dev := NewMockHIDDevice("/dev/hidraw0")
	testData := make([]byte, 64)
	for i := range testData {
		testData[i] = byte(i)
	}
	dev.readBuf = bytes.NewBuffer(testData)

	buf := make([]byte, 64)
	n, err := dev.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 64, n)
	assert.Equal(t, testData, buf)
}

// TestWaitForDevice_NoDev_Coverage tests waiting for device when none exist
func TestWaitForDevice_NoDev_Coverage(t *testing.T) {
	config := DefaultConfig
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = handler.WaitForDevice(ctx)
	assert.Error(t, err)
}

// TestSendCBOR_EmptyResponse_Coverage tests empty CBOR response handling
func TestSendCBOR_EmptyResponse_Coverage(t *testing.T) {
	config := DefaultConfig
	config.Timeout = 500 * time.Millisecond

	mockDev := &EmptyResponseMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	emptyResp := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(emptyResp[0:4], ctapDev.cid)
	emptyResp[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(emptyResp[5:7], 0)

	mockDev.SetResponse(emptyResp)

	_, err := ctapDev.SendCBOR(CmdGetInfo, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty CBOR response")
}

// EmptyResponseMockDevice returns empty responses
type EmptyResponseMockDevice struct {
	*MockHIDDevice
}

// TestReadResponse_Timeout_Coverage tests timeout handling in readResponse
func TestReadResponse_Timeout_Coverage(t *testing.T) {
	config := DefaultConfig
	config.Timeout = 100 * time.Millisecond

	mockDev := &SlowReadMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		delay:         200 * time.Millisecond,
	}

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	_, err := ctapDev.readResponse(ctx, ctapDev.cid)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationTimeout)
}

// SlowReadMockDevice delays reads
type SlowReadMockDevice struct {
	*MockHIDDevice
	delay time.Duration
}

func (d *SlowReadMockDevice) Read(data []byte) (int, error) {
	time.Sleep(d.delay)
	return d.MockHIDDevice.Read(data)
}

// TestReadResponse_ChannelIDMismatch_Coverage tests channel ID mismatch handling
func TestReadResponse_ChannelIDMismatch_Coverage(t *testing.T) {
	config := DefaultConfig
	config.Timeout = 500 * time.Millisecond

	mockDev := NewMockHIDDevice("/dev/hidraw0")

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	// Write directly to readBuf instead of using SetResponse
	// (SetResponse is consumed during Write, but we're calling readResponseSync directly)
	wrongCIDResp := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(wrongCIDResp[0:4], 0x87654321) // Wrong CID
	wrongCIDResp[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(wrongCIDResp[5:7], 1)
	wrongCIDResp[7] = StatusOK

	mockDev.mu.Lock()
	mockDev.readBuf.Write(wrongCIDResp)
	mockDev.mu.Unlock()

	_, err := ctapDev.readResponseSync(ctapDev.cid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "channel ID mismatch")
}

// MismatchedCIDMockDevice returns responses with wrong CID
type MismatchedCIDMockDevice struct {
	*MockHIDDevice
}

// TestReadResponse_KeepaliveHandling_Coverage tests keepalive message handling
func TestReadResponse_KeepaliveHandling_Coverage(t *testing.T) {
	config := DefaultConfig
	config.Timeout = 2 * time.Second

	mockDev := &KeepaliveMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		cid:           0x12345678,
	}

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	resp, err := ctapDev.readResponseSync(ctapDev.cid)
	require.NoError(t, err)
	assert.NotEmpty(t, resp)
}

// KeepaliveMockDevice sends keepalive then real response
type KeepaliveMockDevice struct {
	*MockHIDDevice
	readCount int
	cid       uint32
}

func (d *KeepaliveMockDevice) Read(data []byte) (int, error) {
	d.readCount++

	if d.readCount == 1 {
		keepalive := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(keepalive[0:4], d.cid)
		keepalive[4] = CTAPHID_KEEPALIVE
		binary.BigEndian.PutUint16(keepalive[5:7], 1)
		keepalive[7] = 0x01
		copy(data, keepalive)
		return HIDPacketSize, nil
	}

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], d.cid)
	response[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(response[5:7], 2)
	response[7] = StatusOK
	response[8] = 0xA0
	copy(data, response)
	return HIDPacketSize, nil
}

// TestInit_NonceMismatch_Coverage tests nonce mismatch during initialization
func TestInit_NonceMismatch_Coverage(t *testing.T) {
	mockDev := &NonceMismatchMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}
	config := DefaultConfig
	config.Timeout = 500 * time.Millisecond

	_, err := NewCTAPHIDDevice(mockDev, &config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce mismatch")
}

// NonceMismatchMockDevice returns init response with wrong nonce
type NonceMismatchMockDevice struct {
	*MockHIDDevice
}

func (d *NonceMismatchMockDevice) Write(data []byte) (int, error) {
	return d.MockHIDDevice.Write(data)
}

func (d *NonceMismatchMockDevice) Read(data []byte) (int, error) {
	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	binary.BigEndian.PutUint16(response[5:7], 17)
	copy(response[7:15], make([]byte, 8))
	binary.BigEndian.PutUint32(response[15:19], 0x12345678)
	response[19] = 2
	response[20] = 1
	response[21] = 0
	response[22] = 0
	response[23] = 0x01
	copy(data, response)
	return HIDPacketSize, nil
}

// TestContinuationPacket_SequenceMismatch_Coverage tests sequence mismatch in continuation
func TestContinuationPacket_SequenceMismatch_Coverage(t *testing.T) {
	config := DefaultConfig
	config.Timeout = 500 * time.Millisecond

	mockDev := &SequenceMismatchMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		cid:           0x12345678,
	}

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	_, err := ctapDev.readResponseSync(ctapDev.cid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sequence mismatch")
}

// SequenceMismatchMockDevice returns continuation with wrong sequence
type SequenceMismatchMockDevice struct {
	*MockHIDDevice
	readCount int
	cid       uint32
}

func (d *SequenceMismatchMockDevice) Read(data []byte) (int, error) {
	d.readCount++

	if d.readCount == 1 {
		response := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(response[0:4], d.cid)
		response[4] = CTAPHID_CBOR
		binary.BigEndian.PutUint16(response[5:7], 100)
		copy(data, response)
		return HIDPacketSize, nil
	}

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], d.cid)
	response[4] = 0xFF
	copy(data, response)
	return HIDPacketSize, nil
}

// TestContinuationPacket_CIDMismatch_Coverage tests CID mismatch in continuation
func TestContinuationPacket_CIDMismatch_Coverage(t *testing.T) {
	config := DefaultConfig
	config.Timeout = 500 * time.Millisecond

	mockDev := &CIDMismatchContinuationMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		cid:           0x12345678,
	}

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	_, err := ctapDev.readResponseSync(ctapDev.cid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "channel ID mismatch")
}

// CIDMismatchContinuationMockDevice returns continuation with wrong CID
type CIDMismatchContinuationMockDevice struct {
	*MockHIDDevice
	readCount int
	cid       uint32
}

func (d *CIDMismatchContinuationMockDevice) Read(data []byte) (int, error) {
	d.readCount++

	if d.readCount == 1 {
		response := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(response[0:4], d.cid)
		response[4] = CTAPHID_CBOR
		binary.BigEndian.PutUint16(response[5:7], 100)
		copy(data, response)
		return HIDPacketSize, nil
	}

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], 0x87654321)
	response[4] = 0
	copy(data, response)
	return HIDPacketSize, nil
}

// TestContinuationPacket_IncompleteRead_Coverage tests incomplete continuation packet read
func TestContinuationPacket_IncompleteRead_Coverage(t *testing.T) {
	config := DefaultConfig
	config.Timeout = 500 * time.Millisecond

	mockDev := &IncompleteContinuationMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		cid:           0x12345678,
	}

	ctapDev := &CTAPHIDDevice{
		device: mockDev,
		config: &config,
		cid:    0x12345678,
	}

	_, err := ctapDev.readResponseSync(ctapDev.cid)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete continuation packet")
}

// IncompleteContinuationMockDevice returns incomplete continuation packet
type IncompleteContinuationMockDevice struct {
	*MockHIDDevice
	readCount int
	cid       uint32
}

func (d *IncompleteContinuationMockDevice) Read(data []byte) (int, error) {
	d.readCount++

	if d.readCount == 1 {
		response := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(response[0:4], d.cid)
		response[4] = CTAPHID_CBOR
		binary.BigEndian.PutUint16(response[5:7], 100)
		copy(data, response)
		return HIDPacketSize, nil
	}

	return 30, nil
}

// TestEnrollCredential_NoAttestedCredData_Coverage tests enrollment without attested credential data
func TestEnrollCredential_NoAttestedCredData_Coverage(t *testing.T) {
	config := DefaultConfig
	mockDev := &NoAttestedCredDataMockDevice{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{ID: "test.com", Name: "Test"},
		User:         User{Name: "test", DisplayName: "Test"},
	}

	_, err = hmacExt.EnrollCredential(enrollConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "attested credential data not included")
}

// NoAttestedCredDataMockDevice returns MakeCredential without AT flag
type NoAttestedCredDataMockDevice struct {
	*MockHIDDevice
	initDone bool
}

func (d *NoAttestedCredDataMockDevice) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, fmt.Errorf("packet too short")
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitResponseNoAT(data[7:])
	case CTAPHID_CBOR:
		d.generateNoAttestedCredResponse(data[7:])
	}

	return len(data), nil
}

func (d *NoAttestedCredDataMockDevice) generateInitResponseNoAT(nonce []byte) {
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
	d.initDone = true
}

func (d *NoAttestedCredDataMockDevice) generateNoAttestedCredResponse(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoResponseNoAT()
	case CmdMakeCredential:
		d.generateMakeCredNoAttestedResponse()
	}
}

func (d *NoAttestedCredDataMockDevice) generateGetInfoResponseNoAT() {
	// Use a minimal GetInfo response that fits in a single HID packet (57 bytes max payload)
	// The full response is: StatusOK (1 byte) + CBOR encoded info
	// We need to keep the CBOR data small enough to fit in one packet
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},        // versions - required
		0x02: []string{"hmac-secret"},     // extensions
		0x03: make([]byte, 16),            // aaguid
		0x04: map[string]bool{"up": true}, // minimal options
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)

	// Use writeHIDPackets helper to properly handle multi-packet responses
	d.writeHIDPacketsNoAT(0x12345678, fullPayload)
}

// writeHIDPacketsNoAT writes CBOR payload as HID packets (handles continuation packets)
func (d *NoAttestedCredDataMockDevice) writeHIDPacketsNoAT(cid uint32, fullPayload []byte) {
	payloadLen := len(fullPayload)

	// First packet
	firstPacket := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(firstPacket[0:4], cid)
	firstPacket[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(firstPacket[5:7], uint16(payloadLen))

	firstPayloadSize := HIDPacketSize - 7 // 57 bytes
	if payloadLen <= firstPayloadSize {
		// Single packet response
		copy(firstPacket[7:], fullPayload)
		d.readBuf.Write(firstPacket)
		return
	}

	// Multi-packet response
	copy(firstPacket[7:], fullPayload[:firstPayloadSize])
	d.readBuf.Write(firstPacket)

	remaining := fullPayload[firstPayloadSize:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		contPayloadSize := HIDPacketSize - 5 // 59 bytes
		n := contPayloadSize
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *NoAttestedCredDataMockDevice) generateMakeCredNoAttestedResponse() {
	authData := make([]byte, 37)
	authData[32] = 0x01 // UP flag only, no AT flag

	respMap := map[int]interface{}{
		0x01: "none",
		0x02: authData,
		0x03: map[string]interface{}{},
	}

	encoded, _ := cbor.Marshal(respMap)
	fullPayload := append([]byte{StatusOK}, encoded...)

	// Use the helper to properly handle multi-packet responses
	d.writeHIDPacketsNoAT(0x12345678, fullPayload)
}

func (d *NoAttestedCredDataMockDevice) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, fmt.Errorf("no data")
}
