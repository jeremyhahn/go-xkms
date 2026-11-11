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
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListDevices_CloseError tests error handling when closing devices during list.
func TestListDevices_CloseError(t *testing.T) {
	config := DefaultConfig

	mockDev := &CloseErrorDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleCloseErrorEnumeratorCB{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	// Should still return devices even if close fails
	devices, err := handler.ListDevices()
	require.NoError(t, err)
	assert.NotEmpty(t, devices)
}

// CloseErrorDeviceCB returns an error on Close.
type CloseErrorDeviceCB struct {
	*MockHIDDevice
}

func (d *CloseErrorDeviceCB) Close() error {
	return errors.New("close failed")
}

// SingleCloseErrorEnumeratorCB returns a device that fails on close.
type SingleCloseErrorEnumeratorCB struct {
	device *CloseErrorDeviceCB
}

func (e *SingleCloseErrorEnumeratorCB) Enumerate(vendorID, productID uint16) ([]HIDDevice, error) {
	return []HIDDevice{e.device}, nil
}

func (e *SingleCloseErrorEnumeratorCB) Open(path string) (HIDDevice, error) {
	return e.device, nil
}

// TestWaitForDevice_ContextCanceled tests context cancellation.
func TestWaitForDevice_ContextCanceled(t *testing.T) {
	config := DefaultConfig

	// Empty enumerator - no devices
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	device, err := handler.WaitForDevice(ctx)
	assert.Error(t, err)
	assert.Nil(t, device)
	assert.Equal(t, context.DeadlineExceeded, err)
}

// TestMakeCredential_SendCBORError tests error handling when SendCBOR fails.
func TestMakeCredential_SendCBORError(t *testing.T) {
	config := DefaultConfig
	mockDev := &SendCBORErrorDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		failOnCmd:     CmdMakeCredential,
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	req := &MakeCredentialRequest{
		ClientDataHash: make([]byte, 32),
		RP:             RelyingParty{ID: "test.com", Name: "Test"},
		User:           User{ID: make([]byte, 32), Name: "test", DisplayName: "Test"},
		PubKeyCredParams: []PublicKeyCredentialParameter{
			{Type: "public-key", Alg: COSEAlgES256},
		},
	}

	_, err = auth.MakeCredential(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "MakeCredential command failed")
}

// SendCBORErrorDeviceCB fails on specific CBOR commands.
type SendCBORErrorDeviceCB struct {
	*MockHIDDevice
	failOnCmd byte
	initDone  bool
}

func (d *SendCBORErrorDeviceCB) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, &errs.Message{Msg: "packet too short"}
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.generateInitRespCB(data[7:])
	case CTAPHID_CBOR:
		if len(data) > 7 && data[7] == d.failOnCmd {
			d.generateErrorRespCB()
		} else {
			d.generateCBORRespCB(data[7:])
		}
	}

	return len(data), nil
}

func (d *SendCBORErrorDeviceCB) generateInitRespCB(nonce []byte) {
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

func (d *SendCBORErrorDeviceCB) generateErrorRespCB() {
	d.mu.Lock()
	defer d.mu.Unlock()

	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], 0x12345678)
	response[4] = CTAPHID_CBOR
	binary.BigEndian.PutUint16(response[5:7], 1)
	response[7] = StatusInvalidParameter

	d.readBuf.Write(response)
}

func (d *SendCBORErrorDeviceCB) generateCBORRespCB(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		d.generateGetInfoRspCB()
	}
}

func (d *SendCBORErrorDeviceCB) generateGetInfoRspCB() {
	info := map[int]interface{}{
		0x01: []string{"FIDO_2_0"},
		0x02: []string{"hmac-secret"},
		0x03: make([]byte, 16),
		0x04: map[string]bool{"up": true},
	}

	encoded, _ := cbor.Marshal(info)
	fullPayload := append([]byte{StatusOK}, encoded...)
	d.writeHIDPktsCB(0x12345678, fullPayload)
}

func (d *SendCBORErrorDeviceCB) writeHIDPktsCB(cid uint32, fullPayload []byte) {
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

	remaining := fullPayload[HIDPacketSize-7:]
	seq := byte(0)

	for len(remaining) > 0 {
		contPacket := make([]byte, HIDPacketSize)
		binary.BigEndian.PutUint32(contPacket[0:4], cid)
		contPacket[4] = seq

		n := HIDPacketSize - 5
		if len(remaining) < n {
			n = len(remaining)
		}

		copy(contPacket[5:], remaining[:n])
		d.readBuf.Write(contPacket)

		remaining = remaining[n:]
		seq++
	}
}

func (d *SendCBORErrorDeviceCB) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, &errs.Message{Msg: "no data"}
}

// TestEnrollKey_NoHMACSecretSupport tests EnrollKey when device doesn't support hmac-secret.
func TestEnrollKey_NoHMACSecretSupport(t *testing.T) {
	config := DefaultConfig
	mockDev := &NoExtensionDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	_, err = handler.EnrollKey(enrollConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hmac-secret")
}

// NoExtensionDeviceCB returns GetInfo without hmac-secret support.
type NoExtensionDeviceCB struct {
	*MockHIDDevice
}

func (d *NoExtensionDeviceCB) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, &errs.Message{Msg: "packet too short"}
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.genInitRespCB(data[7:])
	case CTAPHID_CBOR:
		d.genCBORRespCB(data[7:])
	}

	return len(data), nil
}

func (d *NoExtensionDeviceCB) genInitRespCB(nonce []byte) {
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

func (d *NoExtensionDeviceCB) genCBORRespCB(payload []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	ctapCmd := payload[0]

	switch ctapCmd {
	case CmdGetInfo:
		// Return GetInfo WITHOUT hmac-secret extension
		info := map[int]interface{}{
			0x01: []string{"FIDO_2_0"},
			0x02: []string{}, // Empty extensions - no hmac-secret
			0x03: make([]byte, 16),
			0x04: map[string]bool{"up": true},
		}

		encoded, _ := cbor.Marshal(info)
		fullPayload := append([]byte{StatusOK}, encoded...)
		d.writePktsCB(0x12345678, fullPayload)
	}
}

func (d *NoExtensionDeviceCB) writePktsCB(cid uint32, fullPayload []byte) {
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

func (d *NoExtensionDeviceCB) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, &errs.Message{Msg: "no data"}
}

// TestHandler_EnrollKey_CloseDeviceError tests close error handling in EnrollKey.
func TestHandler_EnrollKey_CloseDeviceError(t *testing.T) {
	config := DefaultConfig
	mockDev := &CloseErrorMockDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	// Should still succeed even if close fails
	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// CloseErrorMockDeviceCB is a mock device that returns an error on Close.
type CloseErrorMockDeviceCB struct {
	*MockHIDDevice
	closeCount int
	muCB       sync.Mutex
}

func (d *CloseErrorMockDeviceCB) Close() error {
	d.muCB.Lock()
	defer d.muCB.Unlock()
	d.closeCount++
	return errors.New("close error")
}

// TestHandler_UnlockWithKey_CloseDeviceError tests close error handling in UnlockWithKey.
func TestHandler_UnlockWithKey_CloseDeviceError(t *testing.T) {
	config := DefaultConfig
	mockDev := &CloseErrorMockDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	// Should still succeed even if close fails
	derivedKey, err := handler.UnlockWithKey(authConfig)
	require.NoError(t, err)
	assert.NotNil(t, derivedKey)
}

// TestReadResponseSync_ContinuationReadError tests error when reading continuation packet fails.
func TestReadResponseSync_ContinuationReadError(t *testing.T) {
	config := DefaultConfig
	mockDev := &ContinuationReadErrorDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	_, err := NewCTAPHIDDevice(mockDev, &config)
	// The init should fail because it requires multiple packets
	assert.Error(t, err)
}

// ContinuationReadErrorDeviceCB fails on continuation packet reads.
type ContinuationReadErrorDeviceCB struct {
	*MockHIDDevice
	readCount int
}

func (d *ContinuationReadErrorDeviceCB) Write(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Generate an init response that requires continuation packets
	response := make([]byte, HIDPacketSize)
	binary.BigEndian.PutUint32(response[0:4], CIDBroadcast)
	response[4] = CTAPHID_INIT
	// Indicate large payload that would need continuation
	binary.BigEndian.PutUint16(response[5:7], 100)
	d.readBuf.Write(response)

	return len(data), nil
}

func (d *ContinuationReadErrorDeviceCB) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.readCount++
	if d.readCount > 1 {
		// Fail on continuation packet read
		return 0, errors.New("read error")
	}

	return d.readBuf.Read(data)
}

// TestNewHandlerWithLogger_EmptyConfigDefaults tests handler creation with empty config using defaults.
func TestNewHandlerWithLogger_EmptyConfigDefaults(t *testing.T) {
	config := Config{} // Empty config should get defaults
	enum := NewMockHIDDeviceEnumerator()

	handler, err := NewHandlerWithLogger(&config, enum, nil)
	require.NoError(t, err)
	assert.NotNil(t, handler)
	// Verify defaults were applied
	assert.Equal(t, DefaultTimeout, config.Timeout)
}

// TestEnrollKey_HMACExtensionWithSalt tests EnrollKey with provided salt.
func TestEnrollKey_HMACExtensionWithSalt(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")
	enrollConfig.Salt = make([]byte, 32) // Provide salt

	result, err := handler.EnrollKey(enrollConfig)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.Salt)
}

// TestNewHMACSecretExtension_NoSupport tests creating extension on device without hmac-secret.
func TestNewHMACSecretExtension_NoSupport(t *testing.T) {
	config := DefaultConfig
	mockDev := &NoExtensionDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	_, err = NewHMACSecretExtension(auth)
	assert.Error(t, err)
	assert.Equal(t, ErrUnsupportedExtension, err)
}

// TestEnrollCredential_MakeCredentialError tests EnrollCredential when MakeCredential fails.
func TestEnrollCredential_MakeCredentialError(t *testing.T) {
	config := DefaultConfig
	mockDev := &SendCBORErrorDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
		failOnCmd:     CmdMakeCredential,
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
	assert.Contains(t, err.Error(), "failed to create credential")
}

// TestDeriveSecret_GetAssertionError tests DeriveSecret when GetAssertion fails.
func TestDeriveSecret_GetAssertionError(t *testing.T) {
	config := DefaultConfig
	mockDev := &GetAssertionErrorDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	authConfig := &AuthenticationConfig{
		RelyingPartyID: "test.com",
		CredentialID:   make([]byte, 32),
		Salt:           make([]byte, 32),
	}

	_, err = hmacExt.DeriveSecret(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get assertion")
}

// GetAssertionErrorDeviceCB fails on GetAssertion.
type GetAssertionErrorDeviceCB struct {
	*MockHIDDevice
}

func (d *GetAssertionErrorDeviceCB) Write(data []byte) (int, error) {
	if len(data) < HIDPacketSize {
		return 0, &errs.Message{Msg: "packet too short"}
	}

	cmd := data[4]

	switch cmd {
	case CTAPHID_INIT:
		d.gaeInitResp(data[7:])
	case CTAPHID_CBOR:
		d.gaeCBORResp(data[7:])
	}

	return len(data), nil
}

func (d *GetAssertionErrorDeviceCB) gaeInitResp(nonce []byte) {
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

func (d *GetAssertionErrorDeviceCB) gaeCBORResp(payload []byte) {
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
		d.gaeWritePkts(0x12345678, append([]byte{StatusOK}, encoded...))
	case CmdClientPIN:
		writeCTAPHIDResponse(d.readBuf, 0x12345678, d.sim.respond(payload))
	case CmdGetAssertion:
		// Return error status
		d.gaeWritePkts(0x12345678, []byte{StatusNoCredentials})
	}
}

func (d *GetAssertionErrorDeviceCB) gaeWritePkts(cid uint32, fullPayload []byte) {
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

func (d *GetAssertionErrorDeviceCB) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, &errs.Message{Msg: "no data"}
}

// TestUnlockWithKey_CTAPInitError tests error when CTAP init fails.
func TestUnlockWithKey_CTAPInitError(t *testing.T) {
	config := DefaultConfig

	mockDev := &CTAPInitFailDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	_, err = handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize CTAP device")
}

// CTAPInitFailDeviceCB fails during CTAP initialization.
type CTAPInitFailDeviceCB struct {
	*MockHIDDevice
}

func (d *CTAPInitFailDeviceCB) Write(data []byte) (int, error) {
	// Return an invalid response that will cause CTAP init to fail
	d.mu.Lock()
	defer d.mu.Unlock()

	// Write garbage response
	d.readBuf.Write(make([]byte, HIDPacketSize))
	return len(data), nil
}

func (d *CTAPInitFailDeviceCB) Read(data []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.readBuf.Len() > 0 {
		return d.readBuf.Read(data)
	}

	return 0, &errs.Message{Msg: "no data"}
}

// TestUnlockWithKey_HMACSecretNotSupported tests error when device doesn't support hmac-secret.
func TestUnlockWithKey_HMACSecretNotSupported(t *testing.T) {
	config := DefaultConfig
	mockDev := &NoExtensionDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	authConfig := DefaultAuthenticationConfig(make([]byte, 32), make([]byte, 32))

	_, err = handler.UnlockWithKey(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hmac-secret")
}

// TestWaitForDevice_DeviceFoundImmediately tests WaitForDevice when device exists.
func TestWaitForDevice_DeviceFoundImmediately(t *testing.T) {
	config := DefaultConfig
	mockDev := NewMockHIDDevice("/dev/hidraw0")

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	device, err := handler.WaitForDevice(ctx)
	require.NoError(t, err)
	assert.NotNil(t, device)
}

// TestSelectDevice_MultipleDevicesFirstMatch tests selecting a matching device
// when multiple devices are available.
func TestSelectDevice_MultipleDevicesFirstMatch(t *testing.T) {
	config := DefaultConfig
	config.AllowedVendors = []uint16{0x1234}

	mockDev1 := NewMockHIDDevice("/dev/hidraw0")
	mockDev1.vendorID = 0x9999 // No match

	mockDev2 := NewMockHIDDevice("/dev/hidraw1")
	mockDev2.vendorID = 0x1234 // Match

	mockDev3 := NewMockHIDDevice("/dev/hidraw2")
	mockDev3.vendorID = 0x1234 // Also match

	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev1)
	enum.AddDevice(mockDev2)
	enum.AddDevice(mockDev3)

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	device, err := handler.selectDevice()
	require.NoError(t, err)
	// Should select a matching device (either hidraw1 or hidraw2)
	// Note: map iteration order is non-deterministic, so we can't
	// guarantee which matching device is selected first
	validPaths := []string{"/dev/hidraw1", "/dev/hidraw2"}
	assert.Contains(t, validPaths, device.Path())
}

// TestEnrollKey_CTAPInitError tests error when CTAP init fails during enrollment.
func TestEnrollKey_CTAPInitError(t *testing.T) {
	config := DefaultConfig

	mockDev := &CTAPInitFailDeviceCB{
		MockHIDDevice: NewMockHIDDevice("/dev/hidraw0"),
	}

	enum := &SingleDeviceEnumerator{device: mockDev}

	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)

	enrollConfig := DefaultEnrollmentConfig("testuser")

	_, err = handler.EnrollKey(enrollConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize CTAP device")
}
